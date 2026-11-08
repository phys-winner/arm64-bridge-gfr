/* Include after qa_dispatch.c. One copied command; no UI, allocation or Lua.
 * Mutex is held only while copying the slot, never during a game/API action.
 */
#ifndef GF_QA_ONE_SLOT_H
#define GF_QA_ONE_SLOT_H
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#define QA_SLOT_BUSY (-6)
struct qa_slot_request {
    enum qa_command command;
    uint64_t epoch, ticket, deadline_ms;
    char pending_key[32];
};
struct qa_one_slot {
    pthread_mutex_t lock;
    uint64_t epoch;
    uint64_t next_ticket;
    int pending;
    int reset_requested; /* lifecycle control flag, not a second command slot */
    struct qa_slot_request request;
};
static inline int qa_slot_init(struct qa_one_slot *slot)
{
    slot->epoch = 1;
    slot->next_ticket = 1;
    slot->pending = 0;
    slot->reset_requested = 0;
    return pthread_mutex_init(&slot->lock, NULL);
}
static inline uint64_t qa_slot_epoch(struct qa_one_slot *slot)
{
    pthread_mutex_lock(&slot->lock);
    uint64_t epoch = slot->epoch;
    pthread_mutex_unlock(&slot->lock);
    return epoch;
}
static inline int qa_slot_offer(struct qa_one_slot *slot, enum qa_command command,
                                uint64_t expected_epoch, const char *pending_key,
                                uint64_t now_monotonic_ms, uint64_t *ticket)
{
    if (command < QA_OPEN_CHEAT || command > QA_RESET) return QA_UNAVAILABLE;
    if (!pending_key) pending_key = "";
    size_t length = strnlen(pending_key, sizeof(slot->request.pending_key));
    if (length == sizeof(slot->request.pending_key)) return QA_UNAVAILABLE;
    pthread_mutex_lock(&slot->lock);
    int result = QA_OK;
    if (slot->epoch != expected_epoch) result = QA_STALE;
    else if (slot->reset_requested) result = QA_WAIT_SAFE_SLOT;
    else if (slot->pending) result = QA_SLOT_BUSY;
    else {
        slot->request.command = command;
        slot->request.epoch = expected_epoch;
        slot->request.ticket = slot->next_ticket++;
        if (slot->next_ticket > INT64_MAX) slot->next_ticket = 1;
        slot->request.deadline_ms = now_monotonic_ms > UINT64_MAX - 5000u ? UINT64_MAX : now_monotonic_ms + 5000u;
        memcpy(slot->request.pending_key, pending_key, length + 1);
        slot->pending = 1;
        *ticket = slot->request.ticket;
    }
    pthread_mutex_unlock(&slot->lock);
    return result;
}
static inline int qa_slot_peek(struct qa_one_slot *slot, struct qa_slot_request *request, uint64_t *current_epoch)
{
    pthread_mutex_lock(&slot->lock);
    int pending = slot->pending;
    if (pending) *request = slot->request;
    *current_epoch = slot->epoch;
    pthread_mutex_unlock(&slot->lock);
    return pending;
}
static inline void qa_slot_complete(struct qa_one_slot *slot, const struct qa_slot_request *request)
{
    pthread_mutex_lock(&slot->lock);
    if (slot->pending && slot->epoch == request->epoch && slot->request.epoch == request->epoch &&
        slot->request.ticket == request->ticket &&
        slot->request.command == request->command && !strcmp(slot->request.pending_key, request->pending_key))
        slot->pending = 0;
    pthread_mutex_unlock(&slot->lock);
}
static inline uint64_t qa_slot_invalidate(struct qa_one_slot *slot)
{
    pthread_mutex_lock(&slot->lock);
    if (++slot->epoch == 0) ++slot->epoch;
    slot->pending = 0;
    uint64_t epoch = slot->epoch;
    pthread_mutex_unlock(&slot->lock);
    return epoch;
}
static inline int qa_slot_expired(const struct qa_slot_request *request, uint64_t now_monotonic_ms)
{
    return now_monotonic_ms >= request->deadline_ms;
}
static inline uint64_t qa_slot_request_reset(struct qa_one_slot *slot)
{
    pthread_mutex_lock(&slot->lock);
    if (++slot->epoch == 0) ++slot->epoch;
    slot->pending = 0;
    slot->reset_requested = 1;
    uint64_t epoch = slot->epoch;
    pthread_mutex_unlock(&slot->lock);
    return epoch;
}
static inline int qa_slot_reset_pending(struct qa_one_slot *slot, uint64_t *epoch)
{
    pthread_mutex_lock(&slot->lock);
    int pending = slot->reset_requested;
    *epoch = slot->epoch;
    pthread_mutex_unlock(&slot->lock);
    return pending;
}
static inline void qa_slot_reset_ack(struct qa_one_slot *slot, uint64_t epoch)
{
    pthread_mutex_lock(&slot->lock);
    if (slot->epoch == epoch) slot->reset_requested = 0;
    pthread_mutex_unlock(&slot->lock);
}
#endif
