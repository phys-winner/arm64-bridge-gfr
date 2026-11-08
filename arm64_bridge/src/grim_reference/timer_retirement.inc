// Synchronize timer deletion with callbacks before the movie object is freed.
#include "timer_retirement_preimages.h"

constexpr uint32_t timer_retire_slot_va = 0x2b69c4;
constexpr uint32_t timer_retire_original_va = 0x16cfe4;
constexpr uint32_t timer_retire_mutex_va = 0x2f53d78;

bool timer_retirement_validate(std::string& error) {
    for (const auto& p : timer_retire_preimages)
        if (!preimage(p.va, p.bytes, p.size, p.label, error)) return false;
    if (!binding("zg_LockMutex", 0x18cb14, error) ||
        !binding("zg_UnlockMutex", 0x18cb18, error) ||
        !binding("SDL_LockMutex", 0x2015e8, error) ||
        !binding("SDL_UnlockMutex", 0x2016ec, error)) return false;
    if (!native_span(0x2f539d4, 0x280) || !native_span(0x2f53d74, 16) ||
        !native_span(0x2b69c0, 40)) {
        error = "Grim timer retirement native ranges"; return false;
    }
    // Pointer tables are relocated; validate relative addresses, not file bytes.
    for (const auto& s : timer_retire_slots)
        if (word(base + s.va) != (s.target ? base + s.target : 0u)) {
            error = "Grim timer retirement service table mismatch"; return false;
        }
    for (const auto& s : timer_retire_bindings)
        if (word(base + s.va) != originals.at(s.name)) {
            error = "Grim timer retirement mutex GOT mismatch"; return false;
        }
    return true;
}

void timer_retirement_hook(Jit& jit, Host& host) {
    const std::vector<uint32_t> args = {
        jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]};
    const uint32_t incoming_fpscr = jit.Fpscr();
    ErrorState incoming;
    const uint32_t mutex = args[0] >= 1 && args[0] <= 19
        ? word(base + timer_retire_mutex_va) : 0u;
    if (mutex) {
        // SDL's recursive mutex is malloc(12): pthread word, depth, owner token.
        // This bridge retains the guest pthread type word while locking it.
        if ((mutex & 3u) || host.GuestAllocSize(mutex) < 12 || word(mutex) != 0x4000u) {
            host.Fail("Grim timer retirement recursive mutex contract");
            incoming.restore(); jit.SetFpscr(incoming_fpscr); return;
        }
        if (call("zg_LockMutex", {mutex}) != 0) {
            host.Fail("Grim timer retirement mutex lock failed");
            incoming.restore(); jit.SetFpscr(incoming_fpscr); return;
        }
    }
    // Locking must not modify the original callback's observable inputs.
    incoming.restore(); jit.SetFpscr(incoming_fpscr);
    const uint32_t result = call(base + timer_retire_original_va, args);
    const uint32_t returns[] = {result, host.GetResultWord(1),
        host.GetResultWord(2), host.GetResultWord(3)};
    const uint32_t outgoing_fpscr = jit.Fpscr();
    ErrorState outgoing;
    if (mutex && call("zg_UnlockMutex", {mutex}) != 0)
        host.Fail("Grim timer retirement mutex unlock failed");
    outgoing.restore(); jit.SetFpscr(outgoing_fpscr);
    for (unsigned i = 0; i < 4; ++i) jit.Regs()[i] = returns[i];
}
