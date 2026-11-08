#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "elf_loader.h"
#include <elf.h>
#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <time.h>
#include <unordered_map>
#include <vector>
#include <unistd.h>

namespace {
using Host = DynarmicHost;
using Jit = Dynarmic::A32::Jit;
Host* engine;
ElfLoader* image;
constexpr uint32_t base = 0x40000000;
std::unordered_map<std::string, uint32_t> originals;
unsigned checks;
const char* context = "setup";
#define CHECK(expr) do { ++checks; if (!(expr)) { fprintf(stderr, "FAIL %s line %d: %s\n", context, __LINE__, #expr); std::abort(); } } while (0)
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
uint32_t call(uint32_t p, const std::vector<uint32_t>& args = {}) { return engine->CallGuestNested(p, args); }
uint32_t call(const char* name, const std::vector<uint32_t>& args = {}) { return call(originals.at(name), args); }
#include "../src/grim_reference/save_compression.inc"

struct Guarded {
    static constexpr uint32_t guard = 32;
    uint32_t allocation, address, size;
    explicit Guarded(uint32_t n) : size(n) {
        allocation = engine->GuestAlloc(size + 2 * guard); CHECK(allocation);
        address = allocation + guard;
        memset(span(allocation, size + 2 * guard), 0xa5, size + 2 * guard);
        memset(data(), 0xcd, size);
    }
    Guarded(const Guarded&) = delete;
    Guarded& operator=(const Guarded&) = delete;
    ~Guarded() { engine->GuestFree(allocation); }
    uint8_t* data() const { return static_cast<uint8_t*>(span(address, size)); }
    void Verify() const {
        const auto* bytes = static_cast<const uint8_t*>(span(allocation, size + 2 * guard));
        CHECK(std::all_of(bytes, bytes + guard, [](uint8_t b) { return b == 0xa5; }));
        CHECK(std::all_of(bytes + guard + size, bytes + 2 * guard + size, [](uint8_t b) { return b == 0xa5; }));
    }
};
uint64_t Nanoseconds(clockid_t clock) {
    timespec t{}; CHECK(clock_gettime(clock, &t) == 0);
    return uint64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
}
struct Result {
    uint32_t status, length;
    uint64_t wall_us, cpu_us;
    std::vector<uint8_t> compressed;
};
Result Compress(uint32_t target, const std::vector<uint8_t>& plain, uint32_t capacity) {
    Guarded input(plain.size()), output(capacity), length(4);
    if (!plain.empty()) memcpy(input.data(), plain.data(), plain.size());
    put(length.address, capacity);
    const std::vector<uint32_t> args{output.address, length.address, input.address, uint32_t(plain.size())};
    const uint64_t cpu_start = Nanoseconds(CLOCK_THREAD_CPUTIME_ID), start = Nanoseconds(CLOCK_MONOTONIC);
    const uint32_t status = engine->RunFunction(target, args);
    const uint64_t wall_us = (Nanoseconds(CLOCK_MONOTONIC) - start) / 1000;
    const uint64_t cpu_us = (Nanoseconds(CLOCK_THREAD_CPUTIME_ID) - cpu_start) / 1000;
    CHECK(!engine->HasFailed());
    input.Verify(); output.Verify(); length.Verify();
    CHECK(plain.empty() || !memcmp(input.data(), plain.data(), plain.size()));
    Result result{status, word(length.address), wall_us, cpu_us, {}};
    if (!status) {
        CHECK(result.length <= capacity);
        result.compressed.assign(output.data(), output.data() + result.length);
    }
    return result;
}
void DecodeOriginal(const Result& result, const std::vector<uint8_t>& plain) {
    Guarded input(result.length), output(std::max<size_t>(plain.size(), 1)), length(4);
    if (result.length) memcpy(input.data(), result.compressed.data(), result.length);
    put(length.address, output.size);
    CHECK(engine->RunFunction(originals.at("uncompress"),
        {output.address, length.address, input.address, result.length}) == 0);
    CHECK(!engine->HasFailed());
    input.Verify(); output.Verify(); length.Verify();
    CHECK(word(length.address) == plain.size());
    CHECK(plain.empty() || !memcmp(output.data(), plain.data(), plain.size()));
    CHECK(!memcmp(input.data(), result.compressed.data(), result.length));
}
std::array<uint32_t, 2> Compare(uint32_t hook_plt, const std::vector<uint8_t>& plain, unsigned sample) {
    const uint32_t capacity = uint32_t(plain.size() + plain.size() / 1000 + 64);
    const Result original = Compress(originals.at("compress"), plain, capacity);
    const Result fixed = Compress(hook_plt, plain, capacity);
    CHECK(original.status == 0 && fixed.status == 0);
    DecodeOriginal(original, plain); DecodeOriginal(fixed, plain);
    printf("PASS case=%s sample=%u input=%zu native_bytes=%u native_wall_us=%" PRIu64
        " native_cpu_us=%" PRIu64 " host_bytes=%u host_wall_us=%" PRIu64 " host_cpu_us=%" PRIu64 "\n",
        context, sample, plain.size(), original.length, original.wall_us, original.cpu_us,
        fixed.length, fixed.wall_us, fixed.cpu_us);
    return {original.length, fixed.length};
}
void TightBuffer(uint32_t hook_plt, const std::vector<uint8_t>& plain, uint32_t original_length) {
    context = "synthetic_save_4MiB_tight_capacity";
    const Result fixed = Compress(hook_plt, plain, original_length);
    CHECK(fixed.status == 0 && fixed.length == original_length);
    DecodeOriginal(fixed, plain);
    printf("PASS case=%s capacity=%u fallback_bytes=%u wall_us=%" PRIu64 " cpu_us=%" PRIu64 "\n",
        context, original_length, fixed.length, fixed.wall_us, fixed.cpu_us);
}
void SmallBuffers(uint32_t hook_plt, const std::vector<uint8_t>& plain) {
    for (const uint32_t capacity : {0u, 1u, 5u}) {
        const Result original = Compress(originals.at("compress"), plain, capacity);
        const Result fixed = Compress(hook_plt, plain, capacity);
        CHECK(original.status != 0 && fixed.status == original.status);
        CHECK(original.length == capacity && fixed.length == original.length);
        // Partial bytes on failure are intentionally unspecified across zlib levels.
        printf("PASS case=%s capacity=%u status=%d length=%u guards=unchanged\n",
            context, capacity, static_cast<int32_t>(fixed.status), fixed.length);
    }
}
uint32_t Random(uint32_t& state) {
    state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state;
}
std::vector<uint8_t> SavePattern() {
    std::vector<uint8_t> data(4 * 1024 * 1024);
    uint32_t state = 0x13579bdf;
    constexpr char label[] = "actor_state costume scene inventory script local";
    for (size_t p = 0; p < data.size(); p += 256) {
        const uint32_t record = p / 256;
        for (unsigned i = 0; i < 4; ++i) {
            data[p + i] = record >> (i * 8);
            data[p + 4 + i] = (record / 8) >> (i * 8);
        }
        data[p + 8] = record % 23;
        memcpy(data.data() + p + 16, label, sizeof(label));
        for (unsigned i = 0; i < 64; ++i) data[p + 80 + i] = Random(state) >> 24;
    }
    return data;
}
void ValidateGuards() {
    std::string error; CHECK(save_compression_validate(error));
    for (uint32_t va : {0x1ac7b8u, 0x73b6cu, 0x2a3bc8u}) {
        const uint32_t saved = word(base + va); put(base + va, saved ^ 1);
        error.clear(); CHECK(!save_compression_validate(error) && !error.empty());
        put(base + va, saved);
    }
    error.clear(); CHECK(save_compression_validate(error));
    CHECK(binding("uncompress", 0x1b276c, error));
    CHECK(word(base + 0x2a4174) == originals.at("uncompress"));
    constexpr uint8_t plt[] = {0x02,0xc6,0x8f,0xe2,0x5b,0xca,0x8c,0xe2,0x70,0xf6,0xbc,0xe5};
    CHECK(preimage(0x48550, plt, sizeof(plt), "compress PLT", error));
    printf("PASS production binding/body/callsite rejection guards; original uncompress retained\n");
}
}
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0); CHECK(argc == 2);
    std::ifstream input(argv[1], std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    CHECK(bytes.size() == 2857456);
    Host h; engine = &h; CHECK(h.Initialize());
    // Relocate the pinned guest without constructors or application startup.
    ElfLoader loader(h.GetGuestMemoryBase(), h.GetGuestMemorySize(), base, 0x50000000);
    image = &loader; CHECK(loader.LoadFromMemory(bytes.data(), bytes.size()));
    CHECK(loader.Relocate([&](const std::string& name, uint8_t type) {
        const uint32_t p = loader.GetSymbolAddress(name, type);
        return p ? p : h.GetThunkManager().ResolveSymbol(name, type);
    }));
    for (const auto& s : loader.GetSegments()) if (s.flags & PF_X) h.AddExecutableRange(base + s.vaddr, s.memsz);
    ValidateGuards();
    const uint32_t hook = h.GetThunkManager().RegisterThunk("grim_test_save_compression", save_compression_hook);
    put(base + 0x2a3bc8, hook);
    // Exercise the real ARM import stub and the same GOT slot as production.
    constexpr uint32_t hook_plt = base + 0x48550;
    const std::array<const char*, 5> names{"empty", "short_binary", "repetitive_64KiB", "entropy_64KiB", "synthetic_save_4MiB"};
    std::array<std::vector<uint8_t>, 5> cases{{{}, {'G','r','i','m',0,0xff,1,2,3},
        std::vector<uint8_t>(65536, 'A'), std::vector<uint8_t>(65536), SavePattern()}};
    uint32_t state = 0x2468ace0;
    for (auto& b : cases[3]) b = Random(state) >> 24;
    for (unsigned i = 0; i < cases.size(); ++i) {
        context = names[i];
        const auto lengths = Compare(hook_plt, cases[i], 0);
        SmallBuffers(hook_plt, cases[i]);
        if (i + 1 == cases.size()) {
            CHECK(lengths[1] > lengths[0]); // Fast level 1 cannot fit the original result's capacity.
            TightBuffer(hook_plt, cases[i], lengths[0]);
        }
    }
    context = names.back();
    for (unsigned sample = 1; sample <= 2; ++sample) Compare(hook_plt, cases.back(), sample);
    CHECK(word(base + 0x2a4174) == originals.at("uncompress"));
    CHECK(!h.HasFailed());
    printf("PASS all %u save compression checks; host pages=%ld; timings include bridge call only\n", checks, sysconf(_SC_PAGESIZE));
    h.ReleaseCurrentThread(); return 0;
}
