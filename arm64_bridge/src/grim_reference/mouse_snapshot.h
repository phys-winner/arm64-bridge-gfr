/* Ordered touch-to-mouse edges, advanced only by an actual engine input tick.
 * The caller serializes all operations. No timers, sleeps, SDL or allocation.
 */
#ifndef GF_MOUSE_SNAPSHOT_H
#define GF_MOUSE_SNAPSHOT_H
#include <stdint.h>

#define MS_CAPACITY 64u
enum ms_kind { MS_MOVE, MS_DOWN, MS_UP };
struct ms_event { int x, y; enum ms_kind kind; };
struct ms_snapshot { int x, y, down; };
struct ms_state {
    struct ms_event events[MS_CAPACITY];
    unsigned first, count;
    int live_down, owns_mouse, epoch_valid;
    uint32_t epoch;
    struct ms_snapshot snapshot;
    uint32_t resets, overflows;
};

static inline void ms_init(struct ms_state *s)
{
    s->first = s->count = 0;
    s->live_down = s->owns_mouse = s->epoch_valid = 0;
    s->epoch = 0;
    s->snapshot.x = s->snapshot.y = s->snapshot.down = 0;
    s->resets = s->overflows = 0;
}

/* Keep the last consumed epoch: reset then a second consumer in the same
 * engine tick must not accidentally advance a newly queued gesture.
 */
static inline void ms_reset(struct ms_state *s, int x, int y)
{
    s->first = s->count = 0;
    s->live_down = s->owns_mouse = 0;
    s->snapshot.x = x;
    s->snapshot.y = y;
    s->snapshot.down = 0;
    ++s->resets;
}

/* A real mouse takes ownership immediately; queued touch edges are discarded.
 * Lifecycle reset instead also releases the SDL producer (adapter contract).
 */
static inline void ms_physical_mouse(struct ms_state *s, int x, int y)
{
    ms_reset(s, x, y);
}

static inline int ms_submit(struct ms_state *s, enum ms_kind kind, int x, int y)
{
    if (kind == MS_DOWN) {
        if (s->live_down) return 0;
    } else if (kind == MS_UP) {
        if (!s->live_down) return 0;
    } else if (kind != MS_MOVE) return 0;

    if (kind == MS_MOVE) {
        if (!s->owns_mouse) return 0;
        if (s->count) {
            unsigned last = (s->first + s->count - 1u) % MS_CAPACITY;
            if (s->events[last].kind == MS_MOVE) {
                s->events[last].x = x;
                s->events[last].y = y;
                return 1;
            }
        }
    }
    if (s->count == MS_CAPACITY) {
        ++s->overflows;
        ms_reset(s, x, y);  /* fail released; adapter also releases SDL */
        return -1;
    }
    if (kind == MS_DOWN) {
        s->live_down = 1;
        s->owns_mouse = 1;
    } else if (kind == MS_UP) s->live_down = 0;
    unsigned end = (s->first + s->count) % MS_CAPACITY;
    s->events[end].kind = kind;
    s->events[end].x = x;
    s->events[end].y = y;
    ++s->count;
    return 1;
}

static inline void ms_pop(struct ms_state *s)
{
    s->first = (s->first + 1u) % MS_CAPACITY;
    --s->count;
}

/* Publish at most one DOWN/UP transition in this real input epoch. Movement
 * after that transition is coalesced up to the next transition. Every reader
 * gets this same immutable snapshot until another epoch or immediate reset.
 */
static inline int ms_advance(struct ms_state *s, uint32_t actual_epoch)
{
    if (s->epoch_valid && s->epoch == actual_epoch) return 0;
    s->epoch = actual_epoch;
    s->epoch_valid = 1;
    /* A completed touch releases ownership one epoch after its published UP.
     * Ordinary mouse/virtual-cursor polling resumes without a motion heuristic.
     */
    if (s->owns_mouse && !s->count && !s->live_down && !s->snapshot.down)
        s->owns_mouse = 0;
    int transition = 0;
    while (s->count) {
        struct ms_event event = s->events[s->first];
        if (event.kind != MS_MOVE && transition) break;
        s->snapshot.x = event.x;
        s->snapshot.y = event.y;
        if (event.kind != MS_MOVE) {
            s->snapshot.down = event.kind == MS_DOWN;
            transition = 1;
        }
        ms_pop(s);
    }
    return 1;
}
#endif
