#pragma once
#include <stddef.h>
#include <stdint.h>

namespace arena_memory {
constexpr uint64_t kBytes = 0x100000000ULL;
constexpr uint64_t kTextLimit = 8 * 1024 * 1024;
constexpr size_t kLineLimit = 1024;
constexpr unsigned kVmaLimit = 32768, kAttempts = 61;
constexpr uint64_t kIntervalMs = 30000, kReadBudgetMs = 250;

inline bool space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
inline bool number(const char* s, size_t n, size_t& i, unsigned radix, uint64_t& value) {
    value = 0;
    size_t first = i;
    while (i < n) {
        unsigned d = unsigned(s[i] - '0');
        if (d > 9 && radix == 16) {
            if (s[i] >= 'a' && s[i] <= 'f') d = unsigned(s[i] - 'a') + 10;
            else if (s[i] >= 'A' && s[i] <= 'F') d = unsigned(s[i] - 'A') + 10;
        }
        if (d >= radix) break;
        if (value > (UINT64_MAX - d) / radix) return false;
        value = value * radix + d;
        ++i;
    }
    return i != first;
}
inline bool prefix(const char* s, size_t n, const char* p, size_t length) {
    if (n < length) return false;
    for (size_t i = 0; i < length; ++i) if (s[i] != p[i]) return false;
    return true;
}

// A complete per-VMA walk of one exact host reservation; no path heuristics.
struct Parser {
    uint64_t begin, end, covered = 0, rss_kib = 0, swap_kib = 0, text_bytes = 0;
    uint64_t last_end = 0, block_bytes = 0, values[3]{};
    unsigned headers = 0, arena_vmas = 0, fields = 0;
    bool selected = false, seen_header = false, done = false;
    const char* error = nullptr;

    Parser(uint64_t b, uint64_t e) : begin(b), end(e) {
        if (!b || e <= b || e - b != kBytes || (b & 1023) || (e & 1023)) error = "arena_range";
    }
    bool fail(const char* reason) { if (!error) error = reason; return false; }
    bool finish_block() {
        if (!selected) return true;
        if (fields != 7) return fail("missing_field");
        uint64_t kib = block_bytes / 1024;
        if (values[0] != kib || values[1] > kib || values[2] > kib || values[1] > kib - values[2])
            return fail("metric_range");
        if (covered > kBytes - block_bytes || rss_kib > UINT64_MAX - values[1] || swap_kib > UINT64_MAX - values[2])
            return fail("sum_overflow");
        covered += block_bytes; rss_kib += values[1]; swap_kib += values[2]; ++arena_vmas;
        selected = false;
        return true;
    }
    bool feed(const char* s, size_t n) {
        if (error || done) return !error;
        if (!s || !n || n > kLineLimit || s[n - 1] != '\n') return fail("line_incomplete");
        if (text_bytes > kTextLimit - n) return fail("text_cap");
        text_bytes += n;
        size_t token_end = 0, dash = n;
        while (token_end < n && !space(s[token_end])) {
            if (s[token_end] == '-') dash = token_end;
            ++token_end;
        }
        bool numeric_line = s[0] >= '0' && s[0] <= '9';
        if (dash != n || numeric_line) {
            size_t i = 0; uint64_t a, b;
            if (dash == n || !number(s, n, i, 16, a) || i != dash || s[i++] != '-' ||
                !number(s, n, i, 16, b) || i != token_end || a >= b || (a & 1023) || (b & 1023))
                return fail("vma_header");
            while (i < n && space(s[i])) ++i;
            if (n - i < 5 || (s[i] != 'r' && s[i] != '-') || (s[i + 1] != 'w' && s[i + 1] != '-') ||
                (s[i + 2] != 'x' && s[i + 2] != '-') || (s[i + 3] != 'p' && s[i + 3] != 's') || !space(s[i + 4]))
                return fail("vma_header");
            if (++headers > kVmaLimit) return fail("vma_cap");
            if (seen_header && a < last_end) return fail("vma_order");
            if (!finish_block()) return false;
            seen_header = true; last_end = b; fields = 0;
            if (a < end && b > begin) {
                if (a < begin || b > end) return fail("boundary_straddle");
                if (a != begin + covered) return fail("arena_gap");
                selected = true; block_bytes = b - a;
            } else if (a >= end) {
                if (covered != kBytes) return fail("arena_incomplete");
                done = true;
            }
            return true;
        }
        if (!selected) return true;
        unsigned field; size_t i;
        if (prefix(s, n, "Size:", 5)) { field = 0; i = 5; }
        else if (prefix(s, n, "Rss:", 4)) { field = 1; i = 4; }
        else if (prefix(s, n, "Swap:", 5)) { field = 2; i = 5; }
        else return true;
        if (fields & (1u << field)) return fail("duplicate_field");
        while (i < n && space(s[i])) ++i;
        uint64_t value;
        if (!number(s, n, i, 10, value)) return fail("metric_number");
        if (i >= n || !space(s[i])) return fail("metric_units");
        while (i < n && space(s[i])) ++i;
        if (n - i < 2 || s[i++] != 'k' || s[i++] != 'B') return fail("metric_units");
        while (i < n && space(s[i])) ++i;
        if (i != n) return fail("metric_units");
        values[field] = value; fields |= 1u << field;
        return true;
    }
    bool finish() {
        if (error) return false;
        if (!done && !finish_block()) return false;
        if (covered != kBytes || !arena_vmas) return fail("arena_incomplete");
        if (rss_kib > UINT64_MAX - swap_kib) return fail("sum_overflow");
        done = true; return true;
    }
};

// Linux stat comm may contain spaces and ')'; starttime is field22 after comm.
inline bool proc_identity(const char* s, size_t n, uint64_t& pid, uint64_t& start) {
    size_t i = 0;
    if (!s || !number(s, n, i, 10, pid) || !pid || n - i < 2 || s[i] != ' ' || s[i + 1] != '(') return false;
    size_t close = n;
    for (size_t k = i; k < n; ++k) if (s[k] == ')') close = k;
    if (close == n || close + 1 >= n || s[close + 1] != ' ') return false;
    i = close + 1;
    for (unsigned field = 3; field <= 22; ++field) {
        while (i < n && space(s[i])) ++i;
        size_t first = i;
        while (i < n && !space(s[i])) ++i;
        if (first == i) return false;
        if (field == 22) {
            size_t j = first;
            return i < n && number(s, i, j, 10, start) && j == i && start != 0;
        }
    }
    return false;
}

// Owned game-thread metadata only. UI lifecycle cancellation uses existing QA epoch.
struct Series {
    bool armed = false;
    uint64_t epoch = 0, arm = 0, seq = 0, due_ms = 0;
    unsigned attempts = 0;
    void stop() { armed = false; epoch = 0; attempts = 0; due_ms = 0; }
    bool start(uint64_t e, uint64_t now) {
        stop();
        if (!e || arm == UINT64_MAX) return false;
        ++arm; epoch = e; due_ms = now; armed = true; return true;
    }
    bool current(uint64_t e, uint64_t a) const { return armed && epoch == e && arm == a; }
    bool take(uint64_t e, uint64_t now) {
        if (!armed) return false;
        if (epoch != e || attempts >= kAttempts || seq == UINT64_MAX || now > UINT64_MAX - kIntervalMs) { stop(); return false; }
        if (now < due_ms) return false;
        ++attempts; ++seq; due_ms = now + kIntervalMs;
        return true;
    }
};
} // namespace arena_memory
