#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "elf_loader.h"
#include <elf.h>
#include <pthread.h>
#include <atomic>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <unistd.h>
#include <sys/syscall.h>

extern "C" pthread_mutex_t* TimerTestMutex(DynarmicHost&, uint32_t);

namespace {
using Host = DynarmicHost;
using Jit = Dynarmic::A32::Jit;
Host* engine;
ElfLoader* image;
uint32_t base = 0x40000000;
std::unordered_map<std::string, uint32_t> originals;
std::atomic<unsigned> checks{0};
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expr); std::abort(); } } while (0)
void* span(uint32_t address, size_t size) {
    CHECK(address && uint64_t(address) + size <= engine->GetGuestMemorySize());
    return engine->GetGuestMemoryBase() + address;
}
uint32_t word(uint32_t p) { return engine->MemoryRead32(p); }
void put(uint32_t p, uint32_t v) { engine->MemoryWrite32(p, v); }
bool native_span(uint32_t va, size_t size) {
    for (const auto& s : image->GetSegments())
        if (va >= s.vaddr && uint64_t(va) + size <= uint64_t(s.vaddr) + s.memsz) return true;
    return false;
}
bool preimage(uint32_t va, const void* bytes, size_t size, const char* label, std::string& error) {
    if (native_span(va, size) && !memcmp(span(base + va, size), bytes, size)) return true;
    error = label; return false;
}
bool binding(const char* name, uint32_t va, std::string& error) {
    const uint32_t p = image->GetSymbolAddress(name);
    if (p == base + va) { originals[name] = p; return true; }
    error = name; return false;
}
uint32_t call(uint32_t p, const std::vector<uint32_t>& a = {}) { return engine->CallGuestNested(p, a); }
uint32_t call(const char* name, const std::vector<uint32_t>& a = {}) { return call(originals.at(name), a); }
struct ErrorState {
    int native = errno;
    uint32_t guest = word(engine->GuestErrnoAddress());
    void restore() const { errno = native; put(engine->GuestErrnoAddress(), guest); }
};
#include "../src/grim_reference/timer_retirement.inc"

// This probe wraps the real host pthread lock, below SDL and the bridge thunk.
// The regression establishes an attempted acquisition while the callback owns
// the existing recursive mutex; it does not depend on scheduler sleeps.
std::atomic<long> observe_retire_tid{0};

std::atomic<pthread_mutex_t*> timer_native_mutex{nullptr};
std::atomic<bool> lock_attempted{false};
std::atomic<bool> callback_loaded{false}, permit_callback{false};
std::atomic<bool> callback_done{false}, deletion_done{false}, retired{false};
std::atomic<unsigned> stale_writes{0};
using Clock = std::chrono::steady_clock;
void Wait(const std::atomic<bool>& flag, const char* label) {
    const auto end = Clock::now() + std::chrono::seconds(5);
    while (!flag.load(std::memory_order_acquire)) {
        if (Clock::now() >= end) { fprintf(stderr, "FAIL timeout: %s\n", label); std::abort(); }
        std::this_thread::yield();
    }
}
void ThreadRelease() { engine->ReleaseCurrentThread(); }
uint32_t Run(uint32_t p, const std::vector<uint32_t>& a = {}) {
    const uint32_t r = engine->RunFunction(p, a); CHECK(!engine->HasFailed()); return r;
}
void Lock(uint32_t m) { CHECK(Run(originals.at("zg_LockMutex"), {m}) == 0); }
void Unlock(uint32_t m) { CHECK(Run(originals.at("zg_UnlockMutex"), {m}) == 0); }
uint32_t MakeMutex() {
    const uint32_t m = Run(image->GetSymbolAddress("SDL_CreateMutex"));
    CHECK(m && engine->GuestAllocSize(m) == 12 && word(m) == 0x4000);
    const auto native = TimerTestMutex(*engine, m); CHECK(native);
    timer_native_mutex.store(native); Lock(m);
    std::atomic<int> busy{-1};
    std::thread contender([&] {
        const int result = pthread_mutex_trylock(native); busy = result;
        if (!result) pthread_mutex_unlock(native);
    });
    contender.join(); CHECK(busy.load() == EBUSY); Unlock(m);
    CHECK(pthread_mutex_trylock(native) == 0); CHECK(pthread_mutex_unlock(native) == 0);
    return m;
}
void DropMutex(uint32_t m) { Run(image->GetSymbolAddress("SDL_DestroyMutex"), {m}); }
void SeedTimer(uint32_t id, uint32_t movie) {
    put(base + 0x2f539d4 + id * 32, base + 0x1b8eac);
    put(base + 0x2f539d4 + id * 32 + 12, movie);
}
void Race(bool repaired, uint32_t hook, uint32_t mutex) {
    constexpr uint32_t id = 3;
    const uint32_t movie = engine->GuestAlloc(112); CHECK(movie);
    put(movie + 20, 10); SeedTimer(id, movie);
    callback_loaded = false; permit_callback = false; callback_done = false;
    deletion_done = false; retired = false; stale_writes = 0; lock_attempted = false;
    std::thread callback([&] {
        Lock(mutex);
        const uint32_t fn = word(base + 0x2f539d4 + id * 32);
        const uint32_t user = word(base + 0x2f539d4 + id * 32 + 12);
        callback_loaded.store(true, std::memory_order_release);
        Wait(permit_callback, "release cached callback");
        if (retired.load(std::memory_order_acquire)) stale_writes.fetch_add(1);
        CHECK(Run(fn, {id, user}) == 11); // Actual original ARM callback.
        callback_done.store(true, std::memory_order_release);
        Unlock(mutex); ThreadRelease();
    });
    Wait(callback_loaded, "callback cached under timer mutex");
    std::thread deleter([&] {
        observe_retire_tid = repaired ? syscall(SYS_gettid) : 0;
        const uint32_t result = Run(repaired ? hook : base + timer_retire_original_va, {id});
        observe_retire_tid = 0;
        CHECK(result == id);
        CHECK(word(base + 0x2f539d4 + id * 32) == 0);
        // Quarantine memory instead of physically freeing it in the negative
        // control, so the stale write is an assertion rather than test UB.
        if (repaired) CHECK(callback_done.load(std::memory_order_acquire));
        retired.store(true, std::memory_order_release);
        deletion_done.store(true, std::memory_order_release); ThreadRelease();
    });
    if (repaired) {
        Wait(lock_attempted, "actual pthread lock acquisition attempt");
        CHECK(!deletion_done.load(std::memory_order_acquire));
        CHECK(!retired.load(std::memory_order_acquire));
    } else {
        Wait(deletion_done, "unrepaired deletion before callback");
        CHECK(!callback_done.load(std::memory_order_acquire));
    }
    permit_callback.store(true, std::memory_order_release);
    callback.join(); deleter.join();
    CHECK(stale_writes.load() == (repaired ? 0u : 1u));
    CHECK(word(movie + 20) == 11); engine->GuestFree(movie);
    printf("PASS %s: actual ARM delete + cached actual ARM callback; stale writes=%u\n",
        repaired ? "retirement barrier" : "negative control", stale_writes.load());
}
struct Snapshot { std::array<uint32_t, 4> regs; uint32_t fpscr, guest_errno; int native_errno; };
Snapshot Observe(uint32_t target, uint32_t id, uint32_t invoke) {
    Run(invoke, {target, id, 0x13579bdf, 0x2468ace0});
    Snapshot s{{engine->GetResultWord(0), engine->GetResultWord(1),
        engine->GetResultWord(2), engine->GetResultWord(3)}, engine->CurrentJit().Fpscr(),
        word(engine->GuestErrnoAddress()), errno};
    return s;
}
void ReturnAndRecursion(uint32_t hook, uint32_t mutex) {
    const uint32_t invoke = engine->GetThunkManager().RegisterThunk("timer_test_observe", [](Jit& j, Host& h) {
        const uint32_t target = j.Regs()[0], id = j.Regs()[1];
        j.SetFpscr(0x00400010); errno = EDOM; put(h.GuestErrnoAddress(), ERANGE);
        const uint32_t r = call(target, {id, 0x13579bdf, 0x2468ace0, 0x5a5a5a5a});
        const uint32_t returns[] = {r, h.GetResultWord(1), h.GetResultWord(2), h.GetResultWord(3)};
        for (unsigned i = 0; i < 4; ++i) j.Regs()[i] = returns[i];
    });
    const uint32_t real_lock = originals.at("zg_LockMutex"), real_unlock = originals.at("zg_UnlockMutex");
    // Deliberately clobber lock/unlock side effects after the real SDL action.
    // This exercises the proposed include itself, including restoration logic.
    const uint32_t dirty_lock = engine->GetThunkManager().RegisterThunk("timer_test_dirty_lock", [real_lock](Jit& j, Host& h) {
        const uint32_t r = call(real_lock, {j.Regs()[0]});
        errno = EINTR; put(h.GuestErrnoAddress(), EAGAIN); j.SetFpscr(0x00800001); j.Regs()[0] = r;
    });
    const uint32_t dirty_unlock = engine->GetThunkManager().RegisterThunk("timer_test_dirty_unlock", [real_unlock](Jit& j, Host& h) {
        const uint32_t r = call(real_unlock, {j.Regs()[0]});
        errno = ENOSPC; put(h.GuestErrnoAddress(), EBUSY); j.SetFpscr(0x00c00002); j.Regs()[0] = r;
    });
    originals["zg_LockMutex"] = dirty_lock; originals["zg_UnlockMutex"] = dirty_unlock;
    std::vector<unsigned char> timer_before(20 * 32), timer_after(timer_before.size());
    for (const uint32_t id : {0u, 1u, 19u, 20u, UINT32_MAX}) {
        memset(span(base + 0x2f539d4, timer_before.size()), 0x5a, timer_before.size());
        const auto old = Observe(base + timer_retire_original_va, id, invoke);
        memcpy(timer_before.data(), span(base + 0x2f539d4, timer_before.size()), timer_before.size());
        memset(span(base + 0x2f539d4, timer_after.size()), 0x5a, timer_after.size());
        const auto fixed = Observe(hook, id, invoke);
        memcpy(timer_after.data(), span(base + 0x2f539d4, timer_after.size()), timer_after.size());
        CHECK(old.regs == fixed.regs && old.fpscr == fixed.fpscr);
        CHECK(old.native_errno == fixed.native_errno && old.guest_errno == fixed.guest_errno);
        CHECK(old.fpscr == 0x00400010 && old.native_errno == EDOM && old.guest_errno == ERANGE);
        CHECK(timer_before == timer_after);
    }
    originals["zg_LockMutex"] = real_lock; originals["zg_UnlockMutex"] = real_unlock;
    Lock(mutex); const uint32_t depth = word(mutex + 4), owner = word(mutex + 8);
    CHECK(Run(hook, {3}) == 3); CHECK(word(mutex + 4) == depth && word(mutex + 8) == owner);
    Unlock(mutex);
    // Calling the unchanged service before timer startup remains a plain delete.
    put(base + timer_retire_mutex_va, 0); CHECK(Run(hook, {3}) == 3);
    put(base + timer_retire_mutex_va, mutex);
    printf("PASS valid/invalid IDs, timer bytes, R0-R3, errno, FPSCR, same-thread recursion, unstarted service\n");
}
}
extern "C" int __real_pthread_mutex_lock(pthread_mutex_t*);
extern "C" int __wrap_pthread_mutex_lock(pthread_mutex_t* p) {
    const long tid = syscall(SYS_gettid);
    if (tid == observe_retire_tid.load() && p == timer_native_mutex.load(std::memory_order_acquire))
        lock_attempted.store(true, std::memory_order_release);
    return __real_pthread_mutex_lock(p);
}
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0); CHECK(argc == 2);
    std::ifstream input(argv[1], std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    CHECK(!bytes.empty());
    Host h; engine = &h; CHECK(h.Initialize());
    // Load and relocate original engine without constructors or game startup.
    // No production API/seam is added for the standalone fixture.
    ElfLoader loader(h.GetGuestMemoryBase(), h.GetGuestMemorySize(), base, 0x50000000);
    image = &loader; CHECK(loader.LoadFromMemory(bytes.data(), bytes.size()));
    CHECK(loader.Relocate([&](const std::string& name, uint8_t type) {
        const uint32_t p = loader.GetSymbolAddress(name, type);
        return p ? p : h.GetThunkManager().ResolveSymbol(name, type);
    }));
    for (const auto& s : loader.GetSegments()) if (s.flags & PF_X) h.AddExecutableRange(base + s.vaddr, s.memsz);
    std::string error; CHECK(timer_retirement_validate(error));
    const uint32_t hook = h.GetThunkManager().RegisterThunk("grim_timer_retirement", timer_retirement_hook);
    put(base + timer_retire_slot_va, hook);
    const uint32_t mutex = MakeMutex(); put(base + timer_retire_mutex_va, mutex);
    Race(false, hook, mutex); Race(true, hook, mutex); ReturnAndRecursion(hook, mutex);
    memset(span(base + 0x2f539d4, 20 * 32), 0, 20 * 32);
    put(base + timer_retire_mutex_va, 0); DropMutex(mutex);
    CHECK(!h.HasFailed()); printf("PASS all %u timer retirement checks; host pages=%ld\n", checks.load(), sysconf(_SC_PAGESIZE));
    h.ReleaseCurrentThread(); return 0;
}
