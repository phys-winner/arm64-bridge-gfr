/* Independent Android pointer ownership. Secondary UP cannot release primary.
 * All input still reaches SDL; only the chosen primary produces mouse edges.
 */
#ifndef GF_TOUCH_PRIMARY_H
#define GF_TOUCH_PRIMARY_H
#define TP_CAPACITY 32
struct tp_finger { int device, pointer, active; float x, y, pressure; };
struct tp_state {
    struct tp_finger fingers[TP_CAPACITY];
    int primary;  /* index or -1; never silently hand off to an already held finger */
};
struct tp_result { int kind, selected; float x, y; };
static inline void tp_init(struct tp_state *s)
{
    s->primary = -1;
    for (int n = 0; n < TP_CAPACITY; ++n) s->fingers[n].active = 0;
}
static inline int tp_action(struct tp_state *s, int device, int pointer, int action,
                            float x, float y, float pressure, struct tp_result *result)
{
    result->selected = 0;
    result->kind = 0;
    result->x = x;
    result->y = y;
    int found = -1, empty = -1;
    for (int n = 0; n < TP_CAPACITY; ++n) {
        if (!s->fingers[n].active && empty < 0) empty = n;
        if (s->fingers[n].active && s->fingers[n].device == device && s->fingers[n].pointer == pointer) found = n;
    }
    if (action == 0 || action == 5) {
        if (found >= 0) return 0; /* duplicate DOWN does not create another edge */
        if (empty < 0) return -1;
        found = empty;
        s->fingers[found].device = device;
        s->fingers[found].pointer = pointer;
        s->fingers[found].active = 1;
        if (s->primary < 0) s->primary = found;
        result->kind = MS_DOWN;
    } else if (action == 1 || action == 6) {
        if (found < 0) return 0;
        result->kind = MS_UP;
    } else if (action == 2) {
        if (found < 0) return 0;
        result->kind = MS_MOVE;
    } else return 0;
    s->fingers[found].x = x;
    s->fingers[found].y = y;
    s->fingers[found].pressure = pressure;
    result->selected = found == s->primary;
    if (action == 1 || action == 6) {
        s->fingers[found].active = 0;
        if (result->selected) s->primary = -1;
    }
    return 0;
}
#endif
