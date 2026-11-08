#pragma once

// One host presentation deadline. No guest call, timer substitution or GL getter.
#include <android/native_window.h>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <mutex>

namespace GrimFramePacing {
constexpr int kDefaultMode = 2;
constexpr int NormalizeMode(int value) { return value >= 0 && value <= 3 ? value : kDefaultMode; }
constexpr int MenuRequest(const char* text) {
    if (text[0] >= '0' && text[0] <= '9' && text[1] == '\0') return text[0] - '0';
    if ((text[0] == '1' || text[0] == '2') && text[1] >= '0' && text[1] <= '9' && text[2] == '\0') return (text[0] - '0') * 10 + text[1] - '0';
    if (text[0] == '3' && (text[1] == '0' || text[1] == '1') && text[2] == '\0') return 30 + text[1] - '0';
    return -1;
}
constexpr bool ValidHz(double hz) {
    // A usable nanosecond period must fit along with the monotonic epoch.
    return hz > 0 && hz <= std::numeric_limits<double>::max()
        && 1000000000.0 / hz < double(std::numeric_limits<int64_t>::max() / 4);
}
constexpr double EffectiveHz(int mode, double actual) {
    actual = ValidHz(actual) ? actual : 60.0;
    mode = NormalizeMode(mode);
    const double cap = mode == 0 ? 30.0 : mode == 1 ? 45.0 : 60.0;
    return mode == 3 || actual < cap ? actual : cap;
}
constexpr int64_t PeriodNs(double hz) {
    const double value = 1000000000.0 / (ValidHz(hz) ? hz : 60.0);
    const int64_t integral = int64_t(value);
    return integral + (value > double(integral) ? 1 : 0);
}
constexpr int kDebtPeriods = 4;
constexpr int64_t kLongPauseNs = 1000000000;
constexpr int64_t AdvanceDeadline(int64_t now, int64_t due, int64_t period) {
    if (!due || now - due >= kLongPauseNs) return now + period;
    const int64_t floor = now - kDebtPeriods * period;
    return (due < floor ? floor : due) + period;
}
static_assert(NormalizeMode(-1) == 2 && NormalizeMode(4) == 2 && NormalizeMode(3) == 3);
static_assert(MenuRequest("0") == 0 && MenuRequest("31") == 31 && MenuRequest("32") == -1);
static_assert(MenuRequest("") == -1 && MenuRequest("02") == -1 && MenuRequest("1x") == -1);
static_assert(EffectiveHz(0, 120) == 30 && EffectiveHz(1, 90) == 45);
static_assert(EffectiveHz(2, 59.94) == 59.94 && EffectiveHz(3, 119.88) == 119.88);
static_assert(EffectiveHz(3, 0) == 60 && EffectiveHz(1, -1) == 45);
static_assert(PeriodNs(30) == 33333334 && PeriodNs(45) == 22222223);
static_assert(PeriodNs(59.94) == 16683351 && PeriodNs(119.88) == 8341676);
static_assert(AdvanceDeadline(105, 100, 20) == 120 && AdvanceDeadline(150, 100, 20) == 120);
static_assert(AdvanceDeadline(250, 100, 20) == 190);
static_assert(AdvanceDeadline(1000000100, 100, 20) == 1000000120);
// Existing mutex thunks retain actual recursive, failed and unmatched semantics.
// The ledger only prevents added waits; it never unlocks or changes a guest call.
struct MutexOwnership {
    struct Entry { uint32_t address = 0, depth = 0; } held[64]{};
    uint32_t depth = 0;
    bool overflow = false;
    void Locked(uint32_t address, int result) {
        if (result || !address || overflow) return;
        Entry* empty = nullptr;
        for (auto& entry : held) {
            if (entry.address == address) {
                if (depth == UINT32_MAX || entry.depth == UINT32_MAX) { overflow = true; return; }
                ++entry.depth; ++depth; return;
            }
            if (!entry.address && !empty) empty = &entry;
        }
        if (!empty || depth == UINT32_MAX) { overflow = true; return; }
        *empty = {address, 1}; ++depth;
    }
    void Unlocked(uint32_t address, int result) {
        if (result || !address || overflow) return;
        for (auto& entry : held) if (entry.address == address) {
            if (!entry.depth || !depth) { overflow = true; return; }
            --entry.depth; --depth;
            if (!entry.depth) entry.address = 0;
            return;
        }
        // A successful unmatched unlock must not clear some other owned mutex.
    }
};
inline thread_local MutexOwnership guest_mutexes;
inline void GuestMutexLocked(uint32_t address, int result) { guest_mutexes.Locked(address, result); }
inline void GuestMutexUnlocked(uint32_t address, int result) { guest_mutexes.Unlocked(address, result); }

struct ErrnoKeeper {
    int saved = errno;
    ~ErrnoKeeper() { errno = saved; }
};
struct State {
    std::mutex mutex;
    std::condition_variable changed;
    ANativeWindow* window = nullptr;  // One retained Java game Surface reference.
    double actual_hz = 60;
    int display_mode = 0, selection = kDefaultMode;
    bool ready = false, suspended = false, quitting = false;
    uint32_t registry_errors = 0;
    uint64_t generation = 1;
    uintptr_t surface = 0;
    int64_t next_ns = 0;
};
inline State& Get() { static State state; return state; }
inline void Invalidate(State& state) {
    ++state.generation;
    state.surface = 0;
    state.next_ns = 0;
}
inline int64_t NowNs() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline int PolicyState() {
    ErrnoKeeper incoming;
    auto& state = Get();
    std::lock_guard lock(state.mutex);
    // Nonnegative JNI int: two enum bits, followed by a bounded error revision.
    return int((state.registry_errors << 2) | uint32_t(state.selection));
}
inline void SetMode(int mode) {
    ErrnoKeeper incoming;
    auto& state = Get();
    {
        std::lock_guard lock(state.mutex);
        mode = NormalizeMode(mode);
        if (state.selection == mode) return;
        state.selection = mode;
        Invalidate(state);
    }
    state.changed.notify_all();
}
inline void RegistryFailure() {
    ErrnoKeeper incoming;
    auto& state = Get();
    std::lock_guard lock(state.mutex);
    state.registry_errors = (state.registry_errors + 1) & 0x1fffffffu;
}
inline void Reset() {
    ErrnoKeeper incoming;
    auto& state = Get();
    { std::lock_guard lock(state.mutex); Invalidate(state); }
    state.changed.notify_all();
}
inline void BeginSession() {
    ErrnoKeeper incoming;
    auto& state = Get();
    {
        std::lock_guard lock(state.mutex);
        // A new SDL main may reuse the process after Activity teardown. Keep
        // the fresh Surface publication, reset quit/deadline and default60;
        // the original registry reapplies the saved enum at the first safe POST.
        state.quitting = false;
        state.suspended = false;
        state.selection = kDefaultMode;
        Invalidate(state);
    }
    state.changed.notify_all();
}
inline void Suspend(bool value) {
    ErrnoKeeper incoming;
    auto& state = Get();
    { std::lock_guard lock(state.mutex); state.suspended = value; Invalidate(state); }
    state.changed.notify_all();
}
inline void Quit() {
    ErrnoKeeper incoming;
    auto& state = Get();
    ANativeWindow* release;
    {
        std::lock_guard lock(state.mutex);
        state.quitting = true;
        state.ready = false;
        release = state.window;
        state.window = nullptr;
        Invalidate(state);
    }
    state.changed.notify_all();
    if (release) ANativeWindow_release(release);
}
// Takes ownership of the reference returned by ANativeWindow_fromSurface.
// A repeated pointer consumes/releases the extra reference, without resetting phase.
inline void Publish(ANativeWindow* window, double actual_hz, int mode, bool ready) {
    ErrnoKeeper incoming;
    auto& state = Get();
    ANativeWindow* release = nullptr;
    bool changed;
    ready = ready && window && ValidHz(actual_hz);
    if (!ready && window) { ANativeWindow_release(window); window = nullptr; }
    {
        std::lock_guard lock(state.mutex);
        changed = window != state.window || actual_hz != state.actual_hz
            || mode != state.display_mode || ready != state.ready;
        if (window == state.window) release = window;
        else { release = state.window; state.window = window; }
        state.actual_hz = ValidHz(actual_hz) ? actual_hz : 60;
        state.display_mode = mode;
        state.ready = ready;
        if (changed) Invalidate(state);
    }
    if (changed) state.changed.notify_all();
    if (release) ANativeWindow_release(release);
}
inline void BeforeSwap(uintptr_t surface, ANativeWindow* window, bool vsync_one) {
    ErrnoKeeper incoming;
    if (!surface || !window || guest_mutexes.depth || guest_mutexes.overflow) return;
    auto& state = Get();
    std::unique_lock lock(state.mutex);
    if (!state.ready || state.suspended || state.quitting || window != state.window) return;
    const double effective = EffectiveHz(state.selection, state.actual_hz);
    // Existing successful interval1 already limits an actual-Hz target. Waiting
    // another panel period would risk an unintended 2:1 divisor on that path.
    if (vsync_one && effective >= state.actual_hz) {
        state.next_ns = 0;
        state.surface = surface;
        return;
    }
    const int64_t period = PeriodNs(effective), now = NowNs();
    if (state.surface != surface || !state.next_ns) {
        state.surface = surface;
        state.next_ns = now + period;
        return;
    }
    if (now >= state.next_ns) {
        // Keep at most four periods of debt. A naturally expensive frame must
        // not force a following fast frame to wait; each call still submits once.
        // A pause of at least one second resets phase instead of retaining debt.
        state.next_ns = AdvanceDeadline(now, state.next_ns, period);
        return;
    }
    const uint64_t generation = state.generation;
    const int64_t due = state.next_ns;
    const auto deadline = std::chrono::steady_clock::time_point(std::chrono::nanoseconds(due));
    const bool cancelled = state.changed.wait_until(lock, deadline, [&] {
        return state.generation != generation;
    });
    // Guest ownership was checked before entering; wait_until releases this mutex.
    // This helper acquires no guest/QA/JIT lock and adds no nested guest call.
    if (!cancelled) state.next_ns = AdvanceDeadline(NowNs(), due, period);
    // Cancellation does not drop or add the caller's original eglSwapBuffers.
}
}  // namespace GrimFramePacing
