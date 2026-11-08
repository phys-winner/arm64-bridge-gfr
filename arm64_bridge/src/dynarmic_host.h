#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <mutex>
#include <array>
#include <bitset>
#include <atomic>
#include <unordered_map>
#include <dynarmic/interface/A32/a32.h>
#include <dynarmic/interface/A32/config.h>
#include <dynarmic/interface/exclusive_monitor.h>

struct GuestModuleImage {
    std::string name;
    const uint8_t* data = nullptr;
    size_t size = 0;
    uint32_t base = 0;
    uint32_t limit = 0;
};
class ElfLoader;
class ThunkManager;

class DynarmicHost : public Dynarmic::A32::UserCallbacks {
public:
    static constexpr size_t GUEST_ADDRESS_SPACE = 0x100000000ULL;

    DynarmicHost();
    ~DynarmicHost() override;
    bool Initialize();
    bool LoadGame(const std::string& path);
    bool LoadGameFromMemory(const uint8_t* data, size_t size);
    bool LoadLibraries(const std::string& fmodex, const std::string& fmodevent, const std::string& game);
    bool LoadLibrariesFromMemory(const uint8_t* fmodex, size_t fmodex_size,
                                const uint8_t* fmodevent, size_t fmodevent_size,
                                const uint8_t* game, size_t game_size);
    // Input order is constructor order; all images are relocated before any constructor runs.
    bool LoadModulesFromMemory(const std::vector<GuestModuleImage>& modules);
    ElfLoader& GetElfLoader();
    ElfLoader* GetFmodExLoader();
    ElfLoader* GetFmodEventLoader();
    ElfLoader* FindModule(const std::string& name);
    std::recursive_mutex& GetMutex() { return m_compatibility_mutex; }
    // Retained for adapters using the previous API; nested calls now return synchronously.
    void DrainDeferred() {}
    bool RunSelfChecks();
    uint32_t GetResultHigh() const;
    // R0-R3 from the last completed call on this host thread; read immediately
    // before another nested guest call replaces this result record.
    uint32_t GetResultWord(unsigned index) const;
    bool RunLibraryConstructors(const std::string& name);
    uint32_t FindLibrarySymbol(const std::string& library, const std::string& symbol) const;
    uint32_t FindSymbol(const std::string& name);

    Dynarmic::A32::Jit& CurrentJit();
    uint32_t ReadStackWord(Dynarmic::A32::Jit& jit, uint32_t spilled_word_index);
    uint32_t RunFunction(uint32_t target_pc, const std::vector<uint32_t>& args = {});
    uint32_t CallGuestNested(uint32_t target_pc, const std::vector<uint32_t>& args = {});
    void ReleaseCurrentThread();
    void ExitCurrentGuestThread(uint32_t result);
    bool IsCurrentGuestThreadExiting() const;
    void BeginThreadCleanup();
    uint32_t GuestErrnoAddress();
    uint32_t GuestTlsAddress();
    uint32_t GuestTlsWritable();
    void SetGuestTlsAddress(uint32_t address);
    void SetGuestTlsWritable(uint32_t value);
    bool IsJitRunning() const;
    bool HasFailed() const { return m_failed.load(); }
    std::string FailureReason() const;
    void Fail(const char* reason);

    uint8_t* GetGuestMemoryBase() const { return m_memory; }
    size_t GetGuestMemorySize() const { return m_memory_size; }
    ThunkManager& GetThunkManager() { return *m_thunk_manager; }
    void InvalidateGuestCode(uint32_t addr, size_t size);
    uint32_t GuestAlloc(size_t size, size_t alignment = 8);
    void GuestFree(uint32_t addr);
    uint32_t GuestAllocSize(uint32_t addr);
    uint32_t GuestAllocMapping(size_t size, size_t alignment);
    void AddExecutableRange(uint32_t base, uint32_t size);
    bool IsExecutableAddress(uint32_t address) const;
    bool FinalizeReadOnlyMemory();

    std::optional<std::uint32_t> MemoryReadCode(std::uint32_t vaddr) override;
    std::uint8_t MemoryRead8(std::uint32_t vaddr) override;
    std::uint16_t MemoryRead16(std::uint32_t vaddr) override;
    std::uint32_t MemoryRead32(std::uint32_t vaddr) override;
    std::uint64_t MemoryRead64(std::uint32_t vaddr) override;
    bool IsReadOnlyMemory(std::uint32_t vaddr) override;
    void MemoryWrite8(std::uint32_t vaddr, std::uint8_t value) override;
    void MemoryWrite16(std::uint32_t vaddr, std::uint16_t value) override;
    void MemoryWrite32(std::uint32_t vaddr, std::uint32_t value) override;
    void MemoryWrite64(std::uint32_t vaddr, std::uint64_t value) override;
    bool MemoryWriteExclusive8(std::uint32_t vaddr, std::uint8_t value, std::uint8_t expected) override;
    bool MemoryWriteExclusive16(std::uint32_t vaddr, std::uint16_t value, std::uint16_t expected) override;
    bool MemoryWriteExclusive32(std::uint32_t vaddr, std::uint32_t value, std::uint32_t expected) override;
    bool MemoryWriteExclusive64(std::uint32_t vaddr, std::uint64_t value, std::uint64_t expected) override;
    void InterpreterFallback(std::uint32_t pc, std::size_t num_instructions) override;
    void CallSVC(std::uint32_t swi) override;
    void ExceptionRaised(std::uint32_t pc, Dynarmic::A32::Exception exception) override;
    void AddTicks(std::uint64_t) override {}
    std::uint64_t GetTicksRemaining() override { return UINT64_MAX; }

private:
    // Lazy, bounded JIT pools: one CPU per thread and synchronous callback depth.
    static constexpr size_t kMaxThreads = 64;
    static constexpr size_t kMaxDepth = 8;
    static constexpr size_t kMaxJits = kMaxThreads * kMaxDepth;
    static constexpr uint32_t kStackBase = 0x80000000;
    static constexpr uint32_t kStackStride = 0x00800000;
    static constexpr uint32_t kStackSize = 0x00400000;
    struct ThreadState;
    static thread_local std::unique_ptr<ThreadState> t_thread;
    ThreadState& EnsureThread();
    Dynarmic::A32::Jit& EnsureJit(ThreadState& thread, size_t depth);
    void RetireThread(ThreadState& thread);
    bool RuntimeSelfCheck();

    uint8_t* m_memory = nullptr;
    size_t m_memory_size = 0;
    size_t m_page_size = 0;
    std::unique_ptr<Dynarmic::ExclusiveMonitor> m_monitor;
    Dynarmic::A32::UserConfig m_config;
    mutable std::mutex m_jits_mutex;
    std::array<Dynarmic::A32::Jit*, kMaxJits> m_live_jits{};
    std::bitset<kMaxThreads> m_stack_slots;
    std::unique_ptr<ThunkManager> m_thunk_manager;
    std::recursive_mutex m_compatibility_mutex;
    std::atomic<bool> m_failed{false};
    mutable std::mutex m_failure_mutex;
    char m_failure_reason[241]{};
    struct Library {
        std::string name;
        std::unique_ptr<ElfLoader> elf;
        bool constructors_ran = false;
    };
    std::vector<Library> m_libraries;
    std::atomic<bool> m_libraries_ready{false};
    std::atomic<bool> m_read_only_memory_finalized{false};
    mutable std::mutex m_code_mutex;
    std::vector<std::pair<uint32_t, uint32_t>> m_code_ranges;

    static constexpr uint32_t kHeapBase = 0x50000000;
    static constexpr uint32_t kHeapLimit = 0x7E000000;
    static constexpr uint32_t kMapBase = 0xA0000000;
    static constexpr uint32_t kMapLimit = 0xF0000000;
    static constexpr int kMinClassShift = 5;
    static constexpr uint32_t kMaxClassSize = 1u << 16;
    static constexpr int kNumSizeClasses = 16 - kMinClassShift + 1;
    bool HeapSelfCheck();
    bool ValidAllocation(uint32_t address) const; // caller holds m_heap_mutex
    std::mutex m_heap_mutex;
    std::vector<uint32_t> m_free_small[kNumSizeClasses];
    std::unordered_map<uint32_t, std::vector<uint32_t>> m_free_huge;
    uint32_t m_heap_current = kHeapBase;
    uint32_t m_map_current = kMapBase;
};
