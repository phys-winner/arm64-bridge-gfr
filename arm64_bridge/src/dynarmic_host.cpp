#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "guest_cp15.h"
#include "jni_fake_env.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <stdexcept>
#include <fstream>
#include <iterator>
#include <android/log.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "Arm32Bridge_Host"
#include "bridge_log.h"

namespace {
constexpr uint32_t kExitArm = 4;
constexpr uint32_t kExitThumb = 8;
constexpr uint32_t kBlockMagic = 0x41524D31;
constexpr uint32_t kFreedMagic = 0x41524D46;
constexpr uint32_t kHeaderSize = 16;
bool PowerOfTwo(size_t value) { return value && !(value & (value - 1)); }


}

void GuestSyncForget(uint32_t addr, uint32_t size);
void GuestLibcThreadExit(DynarmicHost& host);

struct DynarmicHost::ThreadState {
    DynarmicHost* owner = nullptr;
    uint32_t slot = kMaxThreads;
    uint32_t stack_bottom = 0;
    uint32_t stack_top = 0;
    uint32_t errno_addr = 0;
    uint32_t tls_allocation = 0;
    uint32_t tls_address = 0;
    uint32_t tls_writable = 0;
    uint32_t fpscr = 0;
    std::array<uint32_t, 4> result_words{};
    size_t depth = 0;
    Dynarmic::A32::Jit* active = nullptr;
    bool exiting = false;
    uint32_t exit_value = 0;
    std::array<std::unique_ptr<Dynarmic::A32::Jit>, kMaxDepth> jits;
    ~ThreadState() { if (owner) owner->RetireThread(*this); }
};
thread_local std::unique_ptr<DynarmicHost::ThreadState> DynarmicHost::t_thread;

DynarmicHost::DynarmicHost() = default;
DynarmicHost::~DynarmicHost() {
    FakeJniEnv::Instance().Shutdown(*this);
    ReleaseCurrentThread();
    {
        std::lock_guard<std::mutex> lock(m_jits_mutex);
        if (m_stack_slots.any()) {
            LOGE("Host destroyed while guest threads remain");
            std::abort();
        }
    }
    if (m_memory) munmap(m_memory, m_memory_size);
}

bool DynarmicHost::Initialize() {
    if (m_memory) return false;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || !PowerOfTwo(page_size) || size_t(page_size) >= kStackSize) return false;
    m_page_size = size_t(page_size);
    m_memory_size = GUEST_ADDRESS_SPACE;
    void* memory = mmap(nullptr, m_memory_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (memory == MAP_FAILED) { m_memory_size = 0; LOGE("Cannot reserve guest 4-GiB address space"); return false; }
    m_memory = static_cast<uint8_t*>(memory);
    m_monitor = std::make_unique<Dynarmic::ExclusiveMonitor>(kMaxJits);
    m_config.callbacks = this;
    m_config.global_monitor = m_monitor.get();
    m_config.arch_version = Dynarmic::A32::ArchVersion::v7;
    m_config.enable_cycle_counting = false;
    m_config.always_little_endian = true;
    m_config.define_unpredictable_behaviour = true;
    m_config.fastmem_pointer = reinterpret_cast<uintptr_t>(m_memory);
    m_config.code_cache_size = 16 * 1024 * 1024;
    m_config.coprocessors[15] = std::make_shared<GuestCp15>(*this);
    MemoryWrite32(kExitArm, 0xEF000000);
    MemoryWrite16(kExitThumb, 0xDF00);
    AddExecutableRange(kExitArm, 4);
    AddExecutableRange(kExitThumb, 2);
    m_thunk_manager = std::make_unique<ThunkManager>(*this);
    m_thunk_manager->RegisterAllThunks();
    LOGI("Dynarmic Host initialized: AArch64 host, A32 guest, %zu bytes, page=%zu, per-thread JIT", m_memory_size, m_page_size);
    return true;
}

namespace {
std::vector<uint8_t> ReadImage(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
}

bool DynarmicHost::LoadGame(const std::string& path) {
    const auto image = ReadImage(path);
    return LoadGameFromMemory(image.data(), image.size());
}

bool DynarmicHost::LoadGameFromMemory(const uint8_t* data, size_t size) {
    return LoadModulesFromMemory({{"game", data, size, 0x40000000, 0x50000000}});
}

bool DynarmicHost::LoadLibraries(const std::string& fmodex, const std::string& fmodevent, const std::string& game) {
    const auto a = ReadImage(fmodex), b = ReadImage(fmodevent), c = ReadImage(game);
    return LoadLibrariesFromMemory(a.data(), a.size(), b.data(), b.size(), c.data(), c.size());
}

bool DynarmicHost::LoadLibrariesFromMemory(const uint8_t* fmodex, size_t fmodex_size,
                                         const uint8_t* fmodevent, size_t fmodevent_size,
                                         const uint8_t* game, size_t game_size) {
    // Compatibility layout. Larger games should supply explicit disjoint reservations.
    return LoadModulesFromMemory({
        {"libfmodex.so", fmodex, fmodex_size, 0x40400000, 0x40600000},
        {"libfmodevent.so", fmodevent, fmodevent_size, 0x40600000, 0x50000000},
        {"game", game, game_size, 0x40000000, 0x40400000},
    });
}

bool DynarmicHost::LoadModulesFromMemory(const std::vector<GuestModuleImage>& inputs) {
    if (!m_memory || !m_libraries.empty() || inputs.empty() || HasFailed()) return false;
    for (size_t i = 0; i < inputs.size(); ++i) {
        const auto& in = inputs[i];
        if (in.name.empty() || !in.data || !in.size || in.base < 0x00100000 ||
            in.base >= in.limit || in.limit > kHeapBase) return false;
        for (size_t j = 0; j < i; ++j)
            if (in.name == inputs[j].name || (in.base < inputs[j].limit && inputs[j].base < in.limit)) return false;
    }
    for (const auto& in : inputs) {
        auto elf = std::make_unique<ElfLoader>(m_memory, m_memory_size, in.base, in.limit);
        if (!elf->LoadFromMemory(in.data, in.size)) { Fail("Guest ELF load failed"); return false; }
        m_libraries.push_back({in.name, std::move(elf), false});
    }
    auto resolver = [this](const std::string& name, uint8_t type) {
        for (auto it = m_libraries.rbegin(); it != m_libraries.rend(); ++it)
            if (uint32_t address = it->elf->GetSymbolAddress(name, type)) return address;
        return m_thunk_manager->ResolveSymbol(name, type);
    };
    for (const auto& library : m_libraries)
        if (!library.elf->Relocate(resolver)) { Fail("Guest ELF relocation failed"); return false; }
    m_libraries_ready.store(true, std::memory_order_release);
    for (const auto& library : m_libraries)
        if (!RunLibraryConstructors(library.name)) return false;
    return !HasFailed();
}

bool DynarmicHost::RunLibraryConstructors(const std::string& name) {
    for (auto& library : m_libraries) {
        if (library.name != name) continue;
        if (library.constructors_ran) return !HasFailed();
        library.constructors_ran = true;
        for (uint32_t function : library.elf->GetInitArray()) {
            RunFunction(function);
            if (HasFailed()) return false;
        }
        return true;
    }
    return false;
}

ElfLoader* DynarmicHost::FindModule(const std::string& name) {
    for (const auto& library : m_libraries) if (library.name == name) return library.elf.get();
    return nullptr;
}
ElfLoader& DynarmicHost::GetElfLoader() {
    if (auto* game = FindModule("game")) return *game;
    if (m_libraries.empty()) throw std::logic_error("Guest ELF is not loaded");
    return *m_libraries.back().elf;
}
ElfLoader* DynarmicHost::GetFmodExLoader() { return FindModule("libfmodex.so"); }
ElfLoader* DynarmicHost::GetFmodEventLoader() { return FindModule("libfmodevent.so"); }
uint32_t DynarmicHost::FindLibrarySymbol(const std::string& library, const std::string& symbol) const {
    if (!m_libraries_ready.load(std::memory_order_acquire)) return 0;
    for (const auto& item : m_libraries) if (item.name == library) return item.elf->GetSymbolAddress(symbol);
    return 0;
}
uint32_t DynarmicHost::FindSymbol(const std::string& name) {
    if (m_libraries_ready.load(std::memory_order_acquire))
        for (auto it = m_libraries.rbegin(); it != m_libraries.rend(); ++it)
            if (uint32_t address = it->elf->GetSymbolAddress(name)) return address;
    return m_thunk_manager ? m_thunk_manager->FindRegisteredSymbol(name) : 0;
}

DynarmicHost::ThreadState& DynarmicHost::EnsureThread() {
    if (t_thread) {
        if (t_thread->owner != this) { LOGE("Multiple guest hosts on one thread"); std::abort(); }
        return *t_thread;
    }
    auto thread = std::make_unique<ThreadState>();
    thread->owner = this;
    {
        std::lock_guard<std::mutex> lock(m_jits_mutex);
        for (size_t slot = 0; slot < kMaxThreads; ++slot) {
            if (!m_stack_slots[slot]) { m_stack_slots.set(slot); thread->slot = slot; break; }
        }
    }
    if (thread->slot == kMaxThreads) { LOGE("Guest thread pool exhausted"); std::abort(); }
    const uint32_t bottom = kStackBase + thread->slot * kStackStride;
    thread->stack_bottom = bottom + m_page_size;
    thread->stack_top = bottom + kStackSize;
    if (mprotect(m_memory + bottom, m_page_size, PROT_NONE) != 0 ||
        mprotect(m_memory + thread->stack_top, m_page_size, PROT_NONE) != 0) {
        LOGE("Could not protect guest stack guards"); std::abort();
    }
    thread->tls_allocation = GuestAlloc(256);
    thread->tls_address = thread->tls_allocation;
    thread->errno_addr = thread->tls_allocation ? thread->tls_allocation + 8 : 0;
    if (!thread->errno_addr) { LOGE("Could not allocate thread errno"); std::abort(); }
    MemoryWrite32(thread->tls_address, thread->tls_address);
    MemoryWrite32(thread->tls_address + 4, thread->slot + 1);
    t_thread = std::move(thread);
    return *t_thread;
}

Dynarmic::A32::Jit& DynarmicHost::EnsureJit(ThreadState& thread, size_t depth) {
    if (depth >= kMaxDepth) { LOGE("Guest nested JIT depth exhausted"); std::abort(); }
    if (!thread.jits[depth]) {
        auto config = m_config;
        const size_t id = thread.slot * kMaxDepth + depth;
        config.processor_id = id;
        auto jit = std::make_unique<Dynarmic::A32::Jit>(config);
        {
            std::lock_guard<std::mutex> lock(m_jits_mutex);
            m_monitor->ClearProcessor(id);
            m_live_jits[id] = jit.get();
            thread.jits[depth] = std::move(jit);
        }
    }
    return *thread.jits[depth];
}

Dynarmic::A32::Jit& DynarmicHost::CurrentJit() {
    auto& thread = EnsureThread();
    return thread.active ? *thread.active : EnsureJit(thread, 0);
}

uint32_t DynarmicHost::ReadStackWord(Dynarmic::A32::Jit& jit, uint32_t spilled_word_index) {
    if (!t_thread || t_thread->owner != this || t_thread->active != &jit || !t_thread->depth)
        throw std::out_of_range("Stack read requires this thread's active guest JIT");
    const uint64_t sp = jit.Regs()[13];
    const uint64_t address = sp + uint64_t(spilled_word_index) * sizeof(uint32_t);
    if ((sp & 3) || sp < t_thread->stack_bottom || sp > t_thread->stack_top ||
        address < t_thread->stack_bottom || address + sizeof(uint32_t) > t_thread->stack_top ||
        address + sizeof(uint32_t) > m_memory_size)
        throw std::out_of_range("Guest argument lies outside the active thread's usable stack");
    uint32_t value;
    memcpy(&value, m_memory + address, sizeof(value));
    return value;
}

bool DynarmicHost::IsJitRunning() const {
    return t_thread && t_thread->owner == this && t_thread->depth != 0;
}

uint32_t DynarmicHost::GuestErrnoAddress() { return EnsureThread().errno_addr; }
uint32_t DynarmicHost::GuestTlsAddress() { return EnsureThread().tls_address; }
uint32_t DynarmicHost::GuestTlsWritable() { return EnsureThread().tls_writable; }
void DynarmicHost::SetGuestTlsWritable(uint32_t value) { EnsureThread().tls_writable=value; }
void DynarmicHost::SetGuestTlsAddress(uint32_t address) {
    if (!address || uint64_t(address)+256>m_memory_size) { Fail("Invalid guest TLS address");return; }
    auto& thread=EnsureThread();thread.tls_address=address;thread.errno_addr=address+8;
}

void DynarmicHost::RetireThread(ThreadState& thread) {
    if (thread.depth) { LOGE("Attempted to free executing guest thread"); std::abort(); }
    if (thread.slot == kMaxThreads) return;
    {
        std::lock_guard<std::mutex> lock(m_jits_mutex);
        for (size_t depth = 0; depth < kMaxDepth; ++depth) {
            const size_t id = thread.slot * kMaxDepth + depth;
            m_live_jits[id] = nullptr;
            m_monitor->ClearProcessor(id);
        }
    }
    for (auto& jit : thread.jits) jit.reset();
    GuestFree(thread.tls_allocation);
    const uint32_t bottom = kStackBase + thread.slot * kStackStride;
    if (madvise(m_memory + bottom, kStackStride, MADV_DONTNEED) != 0) Fail("Guest stack discard failed");
    std::lock_guard<std::mutex> lock(m_jits_mutex);
    m_stack_slots.reset(thread.slot);
}

void DynarmicHost::ReleaseCurrentThread() {
    if (!t_thread || t_thread->owner != this) return;
    if (t_thread->depth) { Fail("Guest thread release while executing"); return; }
    BeginThreadCleanup();
    GuestLibcThreadExit(*this);
    t_thread.reset();
}

bool DynarmicHost::IsCurrentGuestThreadExiting() const {
    return t_thread && t_thread->owner == this && t_thread->exiting;
}

void DynarmicHost::BeginThreadCleanup() {
    if (!t_thread || t_thread->owner != this) return;
    if (t_thread->depth) { Fail("Thread cleanup attempted inside guest execution"); return; }
    t_thread->exiting = false;
    for (auto& jit : t_thread->jits)
        if (jit) jit->ClearHalt(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::ExitCurrentGuestThread(uint32_t result) {
    auto& thread = EnsureThread();
    thread.exiting = true;
    thread.exit_value = result;
    for (auto& jit : thread.jits)
        if (jit) jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
}

void DynarmicHost::Fail(const char* reason) {
    bool first = false;
    {
        std::lock_guard lock(m_failure_mutex);
        if (!m_failed.load()) {
            size_t size = strnlen(reason, sizeof(m_failure_reason) - 1);
            memcpy(m_failure_reason, reason, size);
            m_failed.store(true);
            first = true;
        }
    }
    if (first) LOGE("Bridge FAILED: %s", reason);
    std::lock_guard<std::mutex> lock(m_jits_mutex);
    for (auto* jit : m_live_jits)
        if (jit) jit->HaltExecution(Dynarmic::HaltReason::UserDefined2);
}

uint32_t DynarmicHost::RunFunction(uint32_t target, const std::vector<uint32_t>& args) {
    if (HasFailed() || !m_memory) return 0;
    if (!IsExecutableAddress(target)) { Fail("Guest entry is not executable"); return 0; }
    auto& thread = EnsureThread();
    if (thread.exiting) return thread.exit_value;
    const size_t depth = thread.depth;
    auto& jit = EnsureJit(thread, depth);
    auto* outer = thread.active;
    const uint32_t old_sp = outer ? outer->Regs()[13] : thread.stack_top;
    if (old_sp < thread.stack_bottom || old_sp > thread.stack_top || (depth && old_sp - thread.stack_bottom < 256)) {
        Fail("Invalid guest stack at call boundary"); return 0;
    }
    const uint32_t top = depth ? old_sp - 256 : thread.stack_top;
    const uint64_t extra = args.size() > 4 ? uint64_t(args.size() - 4) * 4 : 0;
    if (extra > uint64_t(top) - thread.stack_bottom) { Fail("Guest arguments exceed stack"); return 0; }
    const uint32_t sp = (top - uint32_t(extra)) & ~7u;
    if (sp < thread.stack_bottom) { Fail("Guest argument alignment crosses stack guard"); return 0; }
    jit.Regs().fill(0);
    jit.ExtRegs().fill(0);
    jit.SetCpsr(0x10 | ((target & 1) ? 0x20 : 0));
    jit.SetFpscr(outer ? outer->Fpscr() : thread.fpscr);
    jit.ClearExclusiveState();
    m_monitor->ClearProcessor(thread.slot * kMaxDepth + depth);
    for (size_t i = 0; i < std::min(args.size(), size_t(4)); ++i) jit.Regs()[i] = args[i];
    for (size_t i = 4; i < args.size(); ++i) MemoryWrite32(sp + uint32_t(i - 4) * 4, args[i]);
    jit.Regs()[13] = sp;
    jit.Regs()[14] = (target & 1) ? (kExitThumb | 1) : kExitArm;
    jit.Regs()[15] = target & ~1u;
    thread.active = &jit;
    ++thread.depth;
    // No host registry/allocator/JIT lock is held over Run or a blocking/reentrant thunk.
    for (;;) {
        const auto reason = jit.Run();
        if (thread.exiting || HasFailed()) break;
        const uint32_t bits = static_cast<uint32_t>(reason);
        const uint32_t cache = static_cast<uint32_t>(Dynarmic::HaltReason::CacheInvalidation);
        if (bits && !(bits & ~cache)) continue;
        const uint32_t pc = jit.Regs()[15];
        const uint32_t returned = static_cast<uint32_t>(Dynarmic::HaltReason::UserDefined1);
        if ((bits & returned) && !(bits & ~(cache | returned)) &&
            (pc == kExitArm || pc == kExitArm + 4 || pc == kExitThumb || pc == kExitThumb + 2)) break;
        LOGE("Unexpected guest halt: entry=0x%08x PC=0x%08x LR=0x%08x reason=0x%x", target, pc, jit.Regs()[14], bits);
        Fail("Unexpected guest halt"); break;
    }
    thread.fpscr = jit.Fpscr();
    if (outer) outer->SetFpscr(thread.fpscr);
    std::copy_n(jit.Regs().begin(), thread.result_words.size(), thread.result_words.begin());
    const uint32_t result = thread.exiting ? thread.exit_value : jit.Regs()[0];
    --thread.depth;
    thread.active = outer;
    return result;
}

uint32_t DynarmicHost::CallGuestNested(uint32_t target, const std::vector<uint32_t>& args) {
    return RunFunction(target, args);
}

void DynarmicHost::InvalidateGuestCode(uint32_t address, size_t size) {
    std::lock_guard<std::mutex> lock(m_jits_mutex);
    for (auto* jit : m_live_jits)
        if (jit) jit->InvalidateCacheRange(address, size);
}

uint32_t DynarmicHost::GuestAlloc(size_t size, size_t alignment) {
    if (!PowerOfTwo(alignment) || size > kHeapLimit - kHeapBase || alignment > kHeapLimit - kHeapBase) return 0;
    if (!size) size = 1;
    alignment = std::max(alignment, size_t(8));
    const uint64_t need = uint64_t(size) + alignment + kHeaderSize;
    if (need > kHeapLimit - kHeapBase) return 0;
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    uint32_t base = 0, capacity = 0;
    if (need <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < need) ++cls;
        capacity = 1u << (cls + kMinClassShift);
        auto& list = m_free_small[cls];
        if (!list.empty()) { base = list.back(); list.pop_back(); }
    } else {
        capacity = uint32_t((need + 15) & ~15ull);
        auto found = m_free_huge.find(capacity);
        if (found != m_free_huge.end() && !found->second.empty()) {
            base = found->second.back(); found->second.pop_back();
        }
    }
    const bool reused = base != 0;
    if (!base) {
        if (uint64_t(m_heap_current) + capacity > kHeapLimit) { LOGE("Guest heap exhausted"); return 0; }
        base = m_heap_current;
        m_heap_current += capacity;
    }
    const uint32_t payload = uint32_t((uint64_t(base) + kHeaderSize + alignment - 1) & ~(uint64_t(alignment) - 1));
    if (reused) memset(m_memory + payload, 0, size);
    MemoryWrite32(payload - 16, kBlockMagic);
    MemoryWrite32(payload - 12, base);
    MemoryWrite32(payload - 8, capacity);
    MemoryWrite32(payload - 4, uint32_t(size));
    return payload;
}

bool DynarmicHost::ValidAllocation(uint32_t address) const {
    if (address < kHeapBase + kHeaderSize || address >= m_heap_current) return false;
    uint32_t header[4]; memcpy(header, m_memory + address - kHeaderSize, sizeof(header));
    const uint32_t base = header[1], capacity = header[2], size = header[3];
    return header[0] == kBlockMagic && base >= kHeapBase && (base & 15) == 0 &&
           capacity >= (1u << kMinClassShift) && !(capacity & 15) &&
           (capacity > kMaxClassSize || PowerOfTwo(capacity)) &&
           uint64_t(base) + capacity <= m_heap_current && address >= base + kHeaderSize &&
           size && uint64_t(address) + size <= uint64_t(base) + capacity;
}

void DynarmicHost::GuestFree(uint32_t address) {
    uint32_t base, capacity, size;
    {
        std::lock_guard<std::mutex> lock(m_heap_mutex);
        if (!ValidAllocation(address)) return;
        base = MemoryRead32(address - 12); capacity = MemoryRead32(address - 8); size = MemoryRead32(address - 4);
        MemoryWrite32(address - 16, kFreedMagic);
    }
    // Retire address-keyed synchronization before another allocator can recycle this block.
    GuestSyncForget(address, size);
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    if (capacity <= kMaxClassSize) {
        int cls = 0;
        while ((1u << (cls + kMinClassShift)) < capacity) ++cls;
        m_free_small[cls].push_back(base);
    } else m_free_huge[capacity].push_back(base);
}

uint32_t DynarmicHost::GuestAllocSize(uint32_t address) {
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    return ValidAllocation(address) ? MemoryRead32(address - 4) : 0;
}

uint32_t DynarmicHost::GuestAllocMapping(size_t size, size_t alignment) {
    if (!size || !PowerOfTwo(alignment)) return 0;
    std::lock_guard<std::mutex> lock(m_heap_mutex);
    const uint64_t aligned = (uint64_t(m_map_current) + alignment - 1) & ~(uint64_t(alignment) - 1);
    if (aligned >= kMapLimit || size > kMapLimit - aligned) return 0;
    m_map_current = uint32_t(aligned + size);
    return uint32_t(aligned);
}

bool DynarmicHost::HeapSelfCheck() {
    bool ok = true;
#define CHECK_HEAP(test) do { if (!(test)) { LOGE("HeapSelfCheck FAILED: %s", #test); ok = false; } } while (0)
    const uint32_t a = GuestAlloc(100), b = GuestAlloc(100), aligned = GuestAlloc(64, 0x1000);
    CHECK_HEAP(a && b && a != b && !(a & 7) && !(b & 7));
    CHECK_HEAP(a + 100 <= b - kHeaderSize || b + 100 <= a - kHeaderSize);
    CHECK_HEAP(aligned && !(aligned & 0xFFF));
    CHECK_HEAP(GuestAllocSize(a) == 100);
    MemoryWrite32(a, 0xDEADBEEF); GuestFree(a); GuestFree(a);
    CHECK_HEAP(GuestAllocSize(a) == 0);
    const uint32_t reused = GuestAlloc(100);
    CHECK_HEAP(reused == a && MemoryRead32(reused) == 0);
    GuestFree(0x40000000); GuestFree(kHeapBase + 4); GuestFree(b + 8);
    CHECK_HEAP(GuestAllocSize(b) == 100);
    const uint32_t big = GuestAlloc(8 * 1024 * 1024, 0x10000);
    CHECK_HEAP(big && !(big & 0xFFFF));
    GuestFree(big);
    const uint32_t big2 = GuestAlloc(8 * 1024 * 1024, 0x10000);
    CHECK_HEAP(big2 == big);
    CHECK_HEAP(GuestAlloc(SIZE_MAX) == 0 && GuestAlloc(8, 3) == 0);
    GuestFree(big2); GuestFree(b); GuestFree(reused); GuestFree(aligned);
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, LOG_TAG,
                        "HeapSelfCheck %s", ok ? "OK" : "FAILED");
#undef CHECK_HEAP
    return ok;
}

bool DynarmicHost::RuntimeSelfCheck() {
    const uint32_t sum = 0x2000, align = 0x2100, thumb = 0x2200;
    std::vector<uint32_t> code = {0xE0800001, 0xE0800002, 0xE0800003};
    for (uint32_t offset = 0; offset < 20; offset += 4) { code.push_back(0xE59D1000 | offset); code.push_back(0xE0800001); }
    code.push_back(0xE12FFF1E);
    for (size_t i = 0; i < code.size(); ++i) MemoryWrite32(sum + i * 4, code[i]);
    MemoryWrite32(align, 0xE1A0000D); MemoryWrite32(align + 4, 0xE2000007); MemoryWrite32(align + 8, 0xE12FFF1E);
    MemoryWrite32(thumb, 0x4770202A);
    AddExecutableRange(sum, code.size() * 4); AddExecutableRange(align, 12); AddExecutableRange(thumb, 4);
    const std::vector<uint32_t> arguments{1, 2, 3, 4, 5, 6, 7, 8, 9};
    bool ok = RunFunction(sum, arguments) == 45 && RunFunction(align, arguments) == 0 && RunFunction(thumb | 1) == 42;
    const uint32_t nested = m_thunk_manager->RegisterThunk("__bridge_selfcheck_nested", [sum, arguments](auto& jit, auto& host) {
        const uint32_t sp = jit.Regs()[13], lr = jit.Regs()[14];
        const uint32_t result = host.CallGuestNested(sum, arguments);
        if (&host.CurrentJit() != &jit || jit.Regs()[13] != sp || jit.Regs()[14] != lr) host.Fail("Nested JIT corrupted caller");
        jit.Regs()[0] = result;
    });
    ok &= RunFunction(nested) == 45;
    const uint32_t checked_stack = m_thunk_manager->RegisterThunk("__bridge_selfcheck_stack", [](auto& jit, auto& host) {
        uint32_t total = 0;
        for (uint32_t word = 0; word < 5; ++word) total += host.ReadStackWord(jit, word);
        bool overflow_rejected = false;
        try { host.ReadStackWord(jit, UINT32_MAX); }
        catch (const std::out_of_range&) { overflow_rejected = true; }
        const uint32_t saved_sp = jit.Regs()[13];
        const auto& thread = host.EnsureThread();
        bool guards_rejected = true;
        for (uint32_t bad_sp : {thread.stack_bottom - 4, thread.stack_top, UINT32_MAX - 3}) {
            jit.Regs()[13] = bad_sp;
            bool rejected = false;
            try { host.ReadStackWord(jit, 0); }
            catch (const std::out_of_range&) { rejected = true; }
            guards_rejected &= rejected;
        }
        jit.Regs()[13] = saved_sp;
        if (!overflow_rejected || !guards_rejected) host.Fail("Guest stack reader failed bounds self-check");
        jit.Regs()[0] = total;
    });
    ok &= RunFunction(checked_stack, arguments) == 35;
    const uint32_t parent_errno = GuestErrnoAddress();
    MemoryWrite32(parent_errno, 0x1234);
    const uint32_t concurrent = m_thunk_manager->RegisterThunk("__bridge_selfcheck_thread", [sum, arguments, parent_errno](auto& jit, auto& host) {
        uint32_t result = 0;
        std::thread worker([&] {
            const uint32_t child_errno = host.GuestErrnoAddress();
            if (child_errno == parent_errno) host.Fail("Thread errno alias");
            host.MemoryWrite32(child_errno, 0x5678);
            result = host.RunFunction(sum, arguments);
            host.ReleaseCurrentThread();
        });
        worker.join();
        jit.Regs()[0] = result;
    });
    // Join while the caller is inside a thunk proves no common JIT/registry lock spans execution.
    ok &= RunFunction(concurrent) == 45 && RunFunction(concurrent) == 45 && MemoryRead32(parent_errno) == 0x1234;
    MemoryWrite32(parent_errno, 0);
    ok &= !HasFailed();
    LOGI("BridgeAbiThreadSelfCheck %s (ARM/Thumb, 9-word spill, nested calls, thread/errno recycling)", ok ? "OK" : "FAILED");
    return ok;
}

void DynarmicHost::AddExecutableRange(uint32_t base, uint32_t size) {
    if (!size || uint64_t(base) + size > m_memory_size || uint64_t(base) + size > UINT32_MAX) {
        Fail("Invalid executable range"); return;
    }
    std::lock_guard<std::mutex> lock(m_code_mutex);
    m_code_ranges.emplace_back(base, base + size);
}

bool DynarmicHost::IsExecutableAddress(uint32_t address) const {
    const uint32_t pc = address & ~1u;
    if (m_libraries_ready.load())
        for (const auto& library : m_libraries)
            if (library.elf->IsExecutable(address)) return true;
    std::lock_guard<std::mutex> lock(m_code_mutex);
    for (const auto& [begin, end] : m_code_ranges)
        if (pc >= begin && uint64_t(pc) + 2 <= end) return true;
    return false;
}

std::optional<std::uint32_t> DynarmicHost::MemoryReadCode(std::uint32_t address) {
    if (!IsExecutableAddress(address)) {
        LOGE("[RUNAWAY] code fetch 0x%08x", address);
        if (!HasFailed() && t_thread && t_thread->owner == this && t_thread->active) {
            const auto& r = t_thread->active->Regs();
            LOGE("Guest fetch context: depth=%zu PC=%08x LR=%08x SP=%08x CPSR=%08x r0-r12=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",
                 t_thread->depth, r[15], r[14], r[13], t_thread->active->Cpsr(),
                 r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12]);
            if (r[13] >= t_thread->stack_bottom && uint64_t(r[13]) + 64 <= t_thread->stack_top)
                for (unsigned i = 0; i < 16; i += 4)
                    LOGE("Guest fetch stack: %08x=%08x,%08x,%08x,%08x", r[13] + i * 4,
                         MemoryRead32(r[13] + i * 4), MemoryRead32(r[13] + (i + 1) * 4),
                         MemoryRead32(r[13] + (i + 2) * 4), MemoryRead32(r[13] + (i + 3) * 4));
        }
        Fail("Invalid guest code fetch");
        return 0xE7FEDEFFu;
    }
    if (uint64_t(address) + 4 > m_memory_size) return std::nullopt;
    return MemoryRead32(address);
}

#define MEMORY_READ(bits, type) type DynarmicHost::MemoryRead##bits(uint32_t address) { \
    type value = 0; \
    if (uint64_t(address) + sizeof(value) <= m_memory_size) memcpy(&value, m_memory + address, sizeof(value)); \
    else Fail("Guest memory read out of bounds"); \
    return value; \
}
MEMORY_READ(8, uint8_t)
MEMORY_READ(16, uint16_t)
MEMORY_READ(32, uint32_t)
MEMORY_READ(64, uint64_t)
#undef MEMORY_READ

bool DynarmicHost::IsReadOnlyMemory(uint32_t address) {
    if (!m_read_only_memory_finalized.load(std::memory_order_acquire)) return false;

    // PT_LOAD segments without PF_W had immutable mappings in the original
    // process.  Keeping the largest folded read wholly inside such a segment
    // lets Dynarmic safely constant-fold ARM literal and rodata loads.
    constexpr uint64_t kMaximumFoldedRead = sizeof(uint64_t);
    for (const auto& library : m_libraries) {
        const uint64_t image_base = library.elf->GetBaseAddress();
        for (const auto& segment : library.elf->GetSegments()) {
            if (!(segment.flags & PF_R) || (segment.flags & PF_W)) continue;
            const uint64_t begin = image_base + segment.vaddr;
            const uint64_t end = begin + segment.memsz;
            if (address >= begin && uint64_t(address) + kMaximumFoldedRead <= end)
                return true;
        }
    }
    return false;
}

bool DynarmicHost::FinalizeReadOnlyMemory() {
    if (!m_libraries_ready.load(std::memory_order_acquire) || HasFailed() ||
        m_read_only_memory_finalized.exchange(true, std::memory_order_acq_rel)) {
        Fail("Invalid guest read-only memory finalization");
        return false;
    }

    uint64_t immutable_bytes = 0;
    for (const auto& library : m_libraries)
        for (const auto& segment : library.elf->GetSegments())
            if ((segment.flags & PF_R) && !(segment.flags & PF_W))
                immutable_bytes += segment.memsz;
    LOGI("Guest read-only memory finalized: %" PRIu64 " bytes available to JIT constant folding",
         immutable_bytes);
    return true;
}

#define MEMORY_WRITE(bits, type) void DynarmicHost::MemoryWrite##bits(uint32_t address, type value) { \
    if (uint64_t(address) + sizeof(value) <= m_memory_size) memcpy(m_memory + address, &value, sizeof(value)); \
    else Fail("Guest memory write out of bounds"); \
}
MEMORY_WRITE(8, uint8_t)
MEMORY_WRITE(16, uint16_t)
MEMORY_WRITE(32, uint32_t)
MEMORY_WRITE(64, uint64_t)
#undef MEMORY_WRITE

void DynarmicHost::InterpreterFallback(uint32_t pc, size_t) {
    LOGE("Interpreter fallback at 0x%08x", pc); Fail("Unsupported guest instruction");
}
void DynarmicHost::CallSVC(uint32_t swi) {
    auto& jit = CurrentJit();
    if (!swi) {
        const uint32_t pc = jit.Regs()[15];
        if (pc == kExitArm || pc == kExitArm + 4 || pc == kExitThumb || pc == kExitThumb + 2)
            jit.HaltExecution(Dynarmic::HaltReason::UserDefined1);
        else {
            // EABI Linux syscall: r7 is the number, r0-r5 carry six words.
            // The libc adapter takes number in r0, then applies ARM argument ABI.
            const auto registers = jit.Regs();
            const uint32_t entry = m_thunk_manager->FindRegisteredSymbol("syscall");
            uint32_t result = RunFunction(entry,{registers[7],registers[0],registers[1],
                registers[2],registers[3],registers[4],registers[5]});
            if(result==UINT32_MAX)result=0u-MemoryRead32(GuestErrnoAddress());
            jit.Regs()[0]=result;
        }
        return;
    }
    m_thunk_manager->DispatchThunk(swi, jit);
}
void DynarmicHost::ExceptionRaised(uint32_t pc, Dynarmic::A32::Exception exception) {
    LOGE("Guest exception PC=0x%08x type=%d", pc, int(exception)); Fail("Guest instruction exception");
}

template<class T> static bool CompareAndSwap(uint8_t* memory, size_t size, uint32_t address, T value, T expected) {
    if (uint64_t(address) + sizeof(T) > size || address % alignof(T)) return false;
    return __atomic_compare_exchange_n(reinterpret_cast<T*>(memory + address), &expected, value, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}
#define EXCLUSIVE(bits, type) bool DynarmicHost::MemoryWriteExclusive##bits(uint32_t address, type value, type expected) { \
    return CompareAndSwap(m_memory, m_memory_size, address, value, expected); \
}
EXCLUSIVE(8, uint8_t)
EXCLUSIVE(16, uint16_t)
EXCLUSIVE(32, uint32_t)
EXCLUSIVE(64, uint64_t)
#undef EXCLUSIVE

uint32_t DynarmicHost::GetResultHigh() const {
    return GetResultWord(1);
}

std::string DynarmicHost::FailureReason() const {
    std::lock_guard lock(m_failure_mutex);
    return m_failure_reason;
}

uint32_t DynarmicHost::GetResultWord(unsigned index) const {
    if (index >= 4) throw std::out_of_range("Guest result word index");
    return t_thread && t_thread->owner == this ? t_thread->result_words[index] : 0;
}

bool DynarmicHost::RunSelfChecks() {
    return HeapSelfCheck() && ElfLoader::SelfCheck(m_memory, m_memory_size) && RuntimeSelfCheck();
}
