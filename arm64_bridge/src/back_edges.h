#pragma once
#include "grim_reference/mouse_snapshot.h"

struct BackContext {
    uint32_t flags, key, name, count, keymap, active, disabled, mapping, lua, pending;
    uint32_t remap[13];
    bool operator==(const BackContext&) const = default;
};
struct BackSample {
    uint32_t current, previous, raw[8];
    BackContext context;
};

static inline bool back_eligible(const BackContext& c) {
    if (c.active != 1 || c.disabled || c.mapping || c.pending || !c.lua
        || (c.flags & 5u) != 5u || c.key != 27 || c.count != 163 || c.keymap != 27) return false;
    for (uint32_t input : c.remap) if (input == 27) return false;
    return true;
}
static inline bool back_fresh(const BackSample& a, const BackSample& b,
                              uint64_t generation, uint64_t current_generation) {
    return generation == current_generation && back_eligible(a.context)
        && back_eligible(b.context) && a.context == b.context
        && a.current == a.previous && b.current != a.previous && b.current == b.previous
        && a.raw[2] <= 1 && b.raw[0] == a.raw[2] && b.raw[2] == a.raw[2] && !b.raw[5]
        && b.raw[1] == b.current && a.raw[3] == b.raw[3] && a.raw[4] == b.raw[4];
}
static inline bool back_same_publication(const BackSample& publication, const BackSample& now) {
    return now.current == publication.current && now.previous == publication.previous
        && now.raw[0] == 1 && !now.raw[2] && now.raw[1] == publication.raw[1]
        && now.raw[3] == publication.raw[3] && now.raw[4] == publication.raw[4]
        && now.raw[5] == publication.raw[5];
}
static inline void back_seed(ms_state* s, uint32_t live) {
    ms_reset(s, 0, 0);
    s->live_down = s->snapshot.down = int(live);
    // A held baseline is physical state, with no manufactured rising edge.
}
// Presses counts every accepted Down, including the final held Down. Preflight
// the whole batch before appending: never publish a truncated press sequence.
static inline bool back_submit(ms_state* s, uint32_t live, uint32_t presses) {
    const unsigned previous = unsigned(s->live_down);
    if (live > 1 || previous > 1 || (!presses && !previous && live)) {
        ms_reset(s, 0, 0); return false;
    }
    const uint64_t edges = 2ull * presses + previous - live;
    if (edges > MS_CAPACITY - s->count) {
        ++s->overflows; ms_reset(s, 0, 0); return false;
    }
    if (previous && (presses || !live)) ms_submit(s, MS_UP, 0, 0);
    for (uint32_t i = 0; i < presses; ++i) {
        ms_submit(s, MS_DOWN, 0, 0);
        if (i + 1 < presses || !live) ms_submit(s, MS_UP, 0, 0);
    }
    return true;
}

// Observe original accepted state changes, never infer a new generation from
// retained presses. Return MS_DOWN/MS_UP, 0 for a duplicate, -1 for a mismatch.
static inline int back_accepted(const BackSample& a, const BackSample& b,
                                uint32_t level, uint32_t timestamp,
                                uint64_t generation, uint64_t current_generation) {
    if (generation != current_generation || !back_eligible(a.context)
        || a.context != b.context || level > 1 || a.raw[2] > 1
        || b.raw[2] != level || b.raw[1] != timestamp) return -1;
    if (a.raw[2] == level) {
        return b.raw[0] == a.raw[0] && b.raw[5] == a.raw[5]
            && b.raw[3] == a.raw[3]
            && b.raw[4] == (level ? timestamp : a.raw[4]) ? 0 : -1;
    }
    if (b.raw[3] != timestamp) return -1;
    if (level) return b.raw[0] == 1 && b.raw[4] == timestamp
        && b.raw[5] == a.raw[5] + 1u ? MS_DOWN : -1;
    return b.raw[0] == a.raw[0] && b.raw[4] == a.raw[4]
        && b.raw[5] == a.raw[5] ? MS_UP : -1;
}

// The same native check runs before installing any hook. It checks reconstruction
// against accepted physical transitions, plus capacity, cancellation and epochs.
static inline bool back_edges_self_check() {
    for (unsigned initial = 0; initial < 2; ++initial) {
        for (unsigned length = 0; length <= 8; ++length) {
            for (unsigned bits = 0; bits < (1u << length); ++bits) {
                ms_state s{}; ms_init(&s); back_seed(&s, initial);
                unsigned live = initial, presses = 0, count = 0;
                unsigned expected[8]{};
                for (unsigned i = 0; i < length; ++i) {
                    const unsigned next = (bits >> i) & 1u;
                    if (next != live) { expected[count++] = next; presses += next; live = next; }
                }
                if (!back_submit(&s, live, presses) || s.count != count || unsigned(s.live_down) != live) return false;
                for (unsigned i = 0; i < count; ++i) {
                    if (!ms_advance(&s, i + 1) || unsigned(s.snapshot.down) != expected[i]) return false;
                    if (ms_advance(&s, i + 1)) return false;
                }
            }
        }
    }
    ms_state s{}; ms_init(&s);
    if (!back_submit(&s, 0, 32) || s.count != 64) return false;
    if (back_submit(&s, 1, 1) || s.count || s.owns_mouse || s.overflows != 1) return false;
    if (back_submit(&s, 0, UINT32_MAX) || s.count || s.overflows != 2) return false;
    back_seed(&s, 1);
    if (s.owns_mouse || !back_submit(&s, 0, 0) || s.count != 1) return false;
    ms_advance(&s, 42); ms_reset(&s, 0, 0);
    if (!back_submit(&s, 0, 1) || ms_advance(&s, 42) || s.snapshot.down) return false;
    if (!ms_advance(&s, 43) || !s.snapshot.down) return false;
    ms_reset(&s, 0, 0);
    if (s.count || s.snapshot.down || s.owns_mouse || ms_advance(&s, 43)) return false;
    BackSample a{}, b{};
    a.current = a.previous = 33096; b.current = b.previous = 33108;
    a.raw[1] = 33103; b.raw[1] = 33108;
    a.raw[0] = 1; a.raw[5] = 1;
    a.context = {5,27,1,163,27,1,0,0,1,0,{0}}; b.context = a.context;
    if (!back_fresh(a,b,7,7) || back_fresh(a,b,7,8)) return false;
    b.context.remap[12] = 27;
    if (back_fresh(a,b,7,7)) return false;
    b.context = a.context; b.context.name++;
    if (back_fresh(a,b,7,7)) return false;
    b.context = a.context; b.context.pending = 1;
    if (back_fresh(a,b,7,7)) return false;
    b.context = a.context; b.raw[0] = 1;
    if (!back_same_publication(b,b)) return false;
    auto now = b; now.raw[2] = 1;
    if (back_same_publication(b,now)) return false;
    now = b; now.raw[5] = 1;
    if (back_same_publication(b,now)) return false;
    now = b; now.current++;
    if (back_same_publication(b,now)) return false;
    // Old retained p is ignored. Only the original accepted edge is submitted.
    const uint32_t retained_press_counts[] = {0u, 1u, 7u, UINT32_MAX};
    for (uint32_t presses : retained_press_counts) {
        BackSample pre{}, post{};
        pre.context = {5,27,1,163,27,1,0,0,1,0,{0}};
        pre.raw[0] = 1; pre.raw[1] = 98; pre.raw[3] = 97;
        pre.raw[4] = 96; pre.raw[5] = presses;
        post = pre; post.raw[1] = 100;
        if (back_accepted(pre,post,0,100,7,7) != 0) return false;
        post.raw[2] = post.raw[0] = 1;
        post.raw[3] = post.raw[4] = 100; post.raw[5] = presses + 1u;
        if (back_accepted(pre,post,1,100,7,7) != MS_DOWN) return false;
        if (back_accepted(pre,post,1,100,7,8) != -1) return false;
        auto corrupt = post; corrupt.raw[5]++;
        if (back_accepted(pre,corrupt,1,100,7,7) != -1) return false;
        corrupt = post; corrupt.context.pending = 1;
        if (back_accepted(pre,corrupt,1,100,7,7) != -1) return false;
        ms_init(&s); back_seed(&s, pre.raw[2]);
        ms_submit(&s, MS_DOWN, 0, 0);
        pre = post; post.raw[1] = post.raw[3] = 101; post.raw[2] = 0;
        if (back_accepted(pre,post,0,101,7,7) != MS_UP) return false;
        ms_submit(&s, MS_UP, 0, 0);
        if (s.count != 2 || !ms_advance(&s, 102) || !s.snapshot.down
            || !ms_advance(&s, 103) || s.snapshot.down) return false;
        // A repeated held Down changes its timestamp, without another edge.
        post = pre; post.raw[1] = post.raw[4] = 104;
        if (back_accepted(pre,post,1,104,7,7) != 0) return false;
        // Invalidation followed by a late real Up cannot resurrect its Down.
        ms_reset(&s,0,0); back_seed(&s,pre.raw[2]);
        post = pre; post.raw[1] = post.raw[3] = 105; post.raw[2] = 0;
        if (back_accepted(pre,post,0,105,8,8) != MS_UP) return false;
        ms_submit(&s, MS_UP, 0, 0);
        if (s.count != 1 || !ms_advance(&s,106) || s.snapshot.down) return false;
    }
    return true;
}
