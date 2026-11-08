// The single ARM32 engine is interpreted. These are HOST64 callbacks: every
// engine pointer/callback remains a uint32_t guest address, never a C pointer.
#include "grim_hooks.h"
#include "frame_pacing.h"
#include "grim_cache.h"
#include "grim_runtime.h"
#include "grim_quit_guards.h"
#include "bridge_io.h"
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "jni_fake_env.h"
#include <android/log.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/syscall.h>
#include "arena_smaps.h"
#include <climits>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <memory>
#include <mutex>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace {
using Host = DynarmicHost;
using Jit = Dynarmic::A32::Jit;
Host* engine;
ElfLoader* image;
uint32_t base;
bool installed;
bool language_bootstrap = true;
bool back_ranges_ready;
std::mutex back_lock;
uint64_t back_input_generation = 1;
std::mutex bind_lock;
std::unordered_map<std::string, uint32_t> originals;
thread_local bool game_thread;
enum class QuitRequest : unsigned { Idle, Submitting, Pending, Retired };
std::atomic<QuitRequest> quit_request{QuitRequest::Idle};
std::atomic<unsigned> quit_witnesses{0};

void* span(uint32_t address, size_t bytes) {
    if ((!address && bytes) || uint64_t(address) + bytes > engine->GetGuestMemorySize()) {
        engine->Fail("Grim hook guest memory range");
        std::abort();
    }
    return address ? engine->GetGuestMemoryBase() + address : nullptr;
}
const char* string32(uint32_t address, size_t limit = 1024 * 1024) {
    if (!address) return nullptr;
    const char* text = static_cast<const char*>(span(address, 1));
    size_t available = std::min<size_t>(engine->GetGuestMemorySize() - address, limit);
    if (!memchr(text, 0, available)) {
        engine->Fail("Grim hook unterminated guest string");
        std::abort();
    }
    return text;
}
uint32_t word(uint32_t address) { return engine->MemoryRead32(address); }
uint8_t byte(uint32_t address) { return engine->MemoryRead8(address); }
void put(uint32_t address, uint32_t value) { engine->MemoryWrite32(address, value); }
uint32_t fbits(float value) { uint32_t bits; memcpy(&bits, &value, 4); return bits; }
float asfloat(uint32_t bits) { float value; memcpy(&value, &bits, 4); return value; }
uint32_t symbol(const char* name) {
    uint32_t address = engine->FindLibrarySymbol("libGrimFandango.so", name);
    return address ? address : engine->GetThunkManager().FindRegisteredSymbol(name);
}
uint32_t call(uint32_t address, const std::vector<uint32_t>& args = {}) {
    if (!address) { engine->Fail("Grim hook missing original"); std::abort(); }
    return engine->CallGuestNested(address, args);
}
uint32_t call(const char* name, const std::vector<uint32_t>& args = {}) {
    return call(originals.at(name), args);
}
struct GuestBytes {
    uint32_t address;
    explicit GuestBytes(size_t size) : address(engine->GuestAlloc(size)) {
        if (!address) { engine->Fail("Grim hook temporary allocation"); std::abort(); }
    }
    explicit GuestBytes(const char* text) : GuestBytes(strlen(text) + 1) {
        memcpy(span(address, strlen(text) + 1), text, strlen(text) + 1);
    }
    ~GuestBytes() { engine->GuestFree(address); }
    GuestBytes(const GuestBytes&) = delete;
};
struct ErrorState {
    int native = errno;
    uint32_t guest = word(engine->GuestErrnoAddress());
    void restore() const { errno = native; put(engine->GuestErrnoAddress(), guest); }
};
void file_result(Jit& jit, int64_t value) {
    int saved = errno;
    jit.Regs()[0] = static_cast<uint32_t>(value);
    if (value < 0) put(engine->GuestErrnoAddress(), saved);
}

// Read-only immutable ARM32 preimages. No host pointer-size assumptions occur
// in these byte tables. Relocated pointer tables are checked separately.
#include "grim_reference/mouse_snapshot.h"
#include "back_edges.h"
ms_state back_edges{};
BackContext back_context{};
BackSample back_publication{};
bool back_seeded, back_owned;
void back_retire_locked() { ++back_input_generation; ms_reset(&back_edges, 0, 0); back_seeded = false; }
void back_cancel() {
    const int saved = errno;
    { std::lock_guard lock(back_lock); back_retire_locked(); }
    errno = saved;
}
void back_release_owned();
#include "grim_reference/touch_primary.h"
#include "grim_reference/mouse_preimages.h"
#include "grim_reference/qa_export_preimages.h"
#include "grim_reference/qa_overlay_preimages.h"
#include "grim_reference/save_title_preimages.h"
#include "grim_reference/video_duration_preimage.h"
#include "grim_reference/vima_scratch_preimage.h"
#include "grim_reference/dsn_shutdown_preimage.h"
#include "grim_reference/shared_audio_shutdown_preimage.h"
#include "grim_reference/gl_upload_preimage.h"
#include "grim_reference/gl_full_prefix_orphan_preimage.h"
#include "grim_reference/texture_bulk_preimage.h"
#include "grim_reference/whole_zero_preimage.h"

bool native_span(uint32_t va, size_t size) {
    for (const auto& s : image->GetSegments())
        if (va >= s.vaddr && uint64_t(va) + size <= uint64_t(s.vaddr) + s.memsz) return true;
    return false;
}
bool preimage(uint32_t va, const void* bytes, size_t size, const char* label, std::string& error) {
    if (native_span(va, size) && !memcmp(span(base + va, size), bytes, size)) return true;
    error = std::string("Grim native preimage mismatch: ") + label;
    return false;
}
bool binding(const char* name, uint32_t va, std::string& error) {
    uint32_t address = symbol(name);
    if (address && (!va || address == base + va)) { originals[name] = address; return true; }
    error = std::string("Grim original binding mismatch: ") + name;
    return false;
}

#include "grim_reference/timer_retirement.inc"
#include "grim_reference/save_compression.inc"

// Virtual directories own a guest dirent buffer; ordinary directory handles
// remain entirely in the existing POSIX thunks and are forwarded there once.
struct CacheDir {
    DIR* directory;
    std::mutex lock;
    explicit CacheDir(DIR* d) : directory(d) {}
};
std::mutex dirs_lock;
std::unordered_map<uint32_t, std::shared_ptr<CacheDir>> dirs;
void fopen_hook(Jit& jit, Host& host) {
    FILE* file = GrimCacheOpen(string32(jit.Regs()[0]), string32(jit.Regs()[1]));
    uint32_t token = file ? AdoptHostFile(host, file) : 0;
    jit.Regs()[0] = token;
    if (!token) put(host.GuestErrnoAddress(), errno);
}
void stat_hook(Jit& jit, Host& host) {
    uint32_t out = jit.Regs()[1];
    struct stat value{};
    int result = GrimCacheStat(string32(jit.Regs()[0]), &value);
    if (!result && !WriteHostStat32(host, out, value)) result = -1;
    file_result(jit, result);
}
void opendir_hook(Jit& jit, Host&) {
    uint32_t path = jit.Regs()[0];
    if (!GrimCacheHasDirectory(string32(path))) {
        jit.Regs()[0] = call("opendir", {path}); return;
    }
    DIR* directory = GrimCacheOpenDir(string32(path));
    if (!directory) { jit.Regs()[0] = 0; put(engine->GuestErrnoAddress(), errno); return; }
    uint32_t token = engine->GuestAlloc(280, 8);
    if (!token) { GrimCacheCloseDir(directory); errno = ENOMEM; put(engine->GuestErrnoAddress(), errno); jit.Regs()[0] = 0; return; }
    std::lock_guard lock(dirs_lock);
    dirs.emplace(token, std::make_shared<CacheDir>(directory));
    jit.Regs()[0] = token;
}
void readdir_hook(Jit& jit, Host&) {
    uint32_t token = jit.Regs()[0];
    std::shared_ptr<CacheDir> dir;
    { std::lock_guard lock(dirs_lock); auto it = dirs.find(token); if (it != dirs.end()) dir = it->second; }
    if (!dir) { jit.Regs()[0] = call("readdir", {token}); return; }
    std::lock_guard lock(dir->lock);
    if (!dir->directory) { errno = EBADF; put(engine->GuestErrnoAddress(), errno); jit.Regs()[0] = 0; return; }
    const dirent* entry = GrimCacheReadDir(dir->directory);
    if (!entry) { jit.Regs()[0] = 0; return; }
    unsigned char* out = static_cast<unsigned char*>(span(token, 280));
    memset(out, 0, 280);
    uint64_t ino = entry->d_ino, off = entry->d_off;
    uint16_t length = 280;
    memcpy(out, &ino, 8); memcpy(out + 8, &off, 8); memcpy(out + 16, &length, 2);
    out[18] = entry->d_type;
    memcpy(out + 19, entry->d_name, std::min<size_t>(strlen(entry->d_name), 255));
    jit.Regs()[0] = token;
}
void closedir_hook(Jit& jit, Host&) {
    uint32_t token = jit.Regs()[0];
    std::shared_ptr<CacheDir> dir;
    { std::lock_guard lock(dirs_lock); auto it = dirs.find(token); if (it != dirs.end()) dir = it->second; }
    if (!dir) { jit.Regs()[0] = call("closedir", {token}); return; }
    int result;
    { std::lock_guard lock(dir->lock); result = dir->directory ? GrimCacheCloseDir(dir->directory) : -1; dir->directory = nullptr; }
    { std::lock_guard lock(dirs_lock); dirs.erase(token); }
    engine->GuestFree(token);
    file_result(jit, result);
}

uint32_t english;
std::mutex video_lock;
GrimCacheEntry selected_video;
bool video_valid;
void voice_hook(Jit& jit, Host&) {
    uint32_t caller = jit.Regs()[14];
    uint32_t result = call("zg_GetLanguageAlpha2");
    if (caller == base + 0xa8a78 && !GrimCacheLegacy()) {
        constexpr int banks[] = {-1, 4, 5, 6, 7, 8};
        int language = GrimGuestLanguage();
        if (language > 0 && language < 6 && !GrimCacheSourcePresent(banks[language])) result = english;
    }
    jit.Regs()[0] = result;
}
void language_hook(Jit& jit, Host&) {
    const int selection = GrimCacheLanguageSelection();
    // Save loading reinitializes system_prefs; Russian archives keep the English slot for this process.
    jit.Regs()[0] = call("zg_SetLanguage", {selection == 6 ? 0u : language_bootstrap && selection >= 0 ? uint32_t(selection) : jit.Regs()[0]});
}
void duration_hook(Jit& jit, Host&) {
    uint32_t path = jit.Regs()[0];
    uint32_t original = call("_Z27zg_Video_GetVideoDurationMSPKc", {path}), result = original;
    const char* file = string32(path);
    std::lock_guard lock(video_lock);
    if (original && original != UINT32_MAX && video_valid && selected_video.source == 3 && selected_video.duration_ms && file) {
        std::string name = std::string("movieshd/") + file;
        if (name.size() >= 4 && name.size() < PATH_MAX && name.compare(name.size() - 4, 4, ".snm") == 0) {
            name.replace(name.size() - 4, 4, ".mp4");
            if (name == selected_video.name) result = selected_video.duration_ms;
        }
    }
    jit.Regs()[0] = result;
}

ms_state mouse;
tp_state pointers;
std::mutex mouse_lock;
void touch_original(uint32_t env, int device, int pointer, int action, float x, float y, float pressure) {
    call("Java_org_libsdl_app_SDLActivity_onNativeTouch", {env, 0, uint32_t(device), uint32_t(pointer), uint32_t(action), fbits(x), fbits(y), fbits(pressure)});
}
void release_mouse(uint32_t env) {
    for (const auto& finger : pointers.fingers)
        if (finger.active) touch_original(env, finger.device, finger.pointer, 1, finger.x, finger.y, finger.pressure);
    tp_init(&pointers);
    call("SDL_ResetMouse");
    engine->MemoryWrite64(base + 0x2f71c18, 0);
    GuestBytes output(8);
    call("SDL_GetMouseState", {output.address, output.address + 4});
    ms_reset(&mouse, int(word(output.address)), int(word(output.address + 4)));
}
void mouse_position_hook(Jit& jit, Host&) {
    uint32_t x = jit.Regs()[0], y = jit.Regs()[1], caller = jit.Regs()[14];
    {
    std::lock_guard lock(mouse_lock);
    uint32_t result = call("zg_Input_GetMousePosition", {x, y});
    if (caller == base + 0x1630d8 && x && y) {
        uint32_t epoch = word(base + 0x2f39b94), previous = word(base + 0x2f39b98);
        if (epoch != previous) ms_advance(&mouse, epoch);
    }
    if (mouse.owns_mouse && mouse.epoch_valid && x && y) {
        put(x, mouse.snapshot.x); put(y, mouse.snapshot.y);
        result = (result & ~1u) | uint32_t(mouse.snapshot.down);
    }
    jit.Regs()[0] = result;
    }
}
void mouse_button_hook(Jit& jit, Host&) {
    uint32_t button = jit.Regs()[0];
    std::lock_guard lock(mouse_lock);
    uint32_t result = call("zg_Input_GetMouseButton", {button});
    if (button == 1 && mouse.owns_mouse) result = mouse.snapshot.down;
    jit.Regs()[0] = result;
}

uint32_t scratch_thunk;
void scratch_hook(Jit& jit, Host&) {
    uint32_t old = jit.Regs()[0], bytes = jit.Regs()[1], file = jit.Regs()[2], line = jit.Regs()[3];
    bool scratch = jit.Regs()[14] == base + 0xd15e0 && file == base + 0x27c065 && line == 0xa3e && bytes && bytes <= UINT32_MAX - 0x21;
    uint32_t result = call("daRealloc", {old, bytes + unsigned(scratch), file, line});
    ErrorState outgoing;
    if (scratch && result) engine->MemoryWrite8(result + bytes, 0);
    outgoing.restore(); jit.Regs()[0] = result;
}
void services_hook(Jit& jit, Host&) {
    uint32_t table = jit.Regs()[0];
    uint32_t result = call("stdPlatform_InitServices", {table});
    ErrorState outgoing;
    if (table && word(table + 0x28) == originals.at("daRealloc")) put(table + 0x28, scratch_thunk);
    outgoing.restore(); jit.Regs()[0] = result;
}
void dsn_join_hook(Jit& jit, Host&) {
    uint32_t thread = jit.Regs()[0], caller = jit.Regs()[14];
    ErrorState incoming;
    if (caller == base + 0x15b4a8 && thread && thread == word(base + 0x2f21404) && word(base + 0x2f59474) && word(base + 0x2f594b4)) {
        __atomic_store_n(static_cast<uint8_t*>(span(thread + 8, 1)), uint8_t(0), __ATOMIC_RELEASE);
        call("zg_Audio_ProducePost", {1});
    }
    incoming.restore();
    jit.Regs()[0] = call("zg_Thread_DestroyAndWait", {thread});
}
void shared_shutdown_hook(Jit& jit, Host&) {
    uint32_t type = jit.Regs()[0], caller = jit.Regs()[14];
    ErrorState incoming;
    if ((type == 0 && caller == base + 0xdadfc) || (type == 1 && caller == base + 0x1582e8)) {
        uint32_t g = base + 0x2f59460, id = word(g + 12);
        uint32_t ready[] = {word(g + 24), word(g + 28), word(g + 32)};
        bool valid = id >= 1 && id <= 16 && word(g + 8) && !(word(g + 8) & 3) && word(g) < 3;
        for (uint32_t p : ready) valid &= p && !(p & 3);
        uint32_t device = valid ? word(base + 0x2f704a8 + 4 * (id - 1)) : 0;
        valid &= device && !(device & 3);
        if (valid && word(device + 16) == base + 0x18adac && word(device) == 48000 && engine->MemoryRead16(device + 4) == 0x8010 && byte(device + 6) == 2 && engine->MemoryRead16(device + 8) == 1536 && word(device + 12) == 6144 && word(device + 0x84) == 1) {
            __atomic_store_n(static_cast<uint32_t*>(span(device + 0x84, 4)), 0u, __ATOMIC_RELEASE);
            for (uint32_t p : ready) call("zg_PostSemaphore", {p, 2});
            call("SDL_CloseAudioDevice", {id});
            put(g + 12, 0);
        }
    }
    incoming.restore(); jit.Regs()[0] = call("zg_Audio_Shutdown", {type});
}

void orphan_hook(Jit& jit, Host&) {
    auto args = std::vector<uint32_t>{jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]};
    ErrorState incoming;
    uint32_t capacity = 0;
    if (jit.Regs()[14] == base + 0x190d90 && game_thread && args[0] == 0x8a11 && !args[1] && int32_t(args[2]) >= 0 && args[3] && byte(base + 0x2b7579) == 1 && byte(base + 0x2b757a) == 1 && byte(base + 0x2f59a63) == 1) {
        uint32_t frame = word(base + 0x2f598e4), cycles = word(base + 0x2b7584);
        if (frame && !(frame & 3) && cycles && cycles <= 0x7ff) {
            uint32_t gpu = cycles << 20, cpu = word(frame + 0x28), used = word(frame + 0x2c);
            if (cpu && cpu <= gpu && used <= cpu && args[2] == used && args[3] == word(frame + 0x34) && word(frame + 0x60)) capacity = gpu;
        }
    }
    if (capacity) { incoming.restore(); call("glBufferData", {args[0], capacity, 0, 0x88e8}); }
    incoming.restore(); call("glBufferSubData", args);
}
void texture_hook(Jit& jit, Host& host) {
    std::vector<uint32_t> a{jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]};
    for (unsigned i = 0; i < 5; ++i) a.push_back(host.ReadStackWord(jit, i));
    ErrorState incoming;
    uint32_t caller = jit.Regs()[14] - base, bytes = 0, s = a[0], src = a[1], w = a[2], h = a[3];
    if (game_thread && (caller == 0x19dc04 || caller == 0x19dec4) && s && src && !(s & 3) && !a[5] && a[4] == 16 && a[8] == 1 && w && h > 1 && w <= UINT32_MAX / 2) {
        uint32_t row = w * 2, dst = word(s + 0x18);
        if (word(s) == w && word(s + 4) == h && !word(s + 8) && word(s + 12) == 13 && word(s + 0x24) == row && dst && !word(s + 0x1c) && !byte(s + 0x29) && h <= UINT32_MAX / row) {
            uint32_t n = h * row;
            if (n <= UINT32_MAX - src && n <= UINT32_MAX - dst && !(src < dst + n && dst < src + n)) bytes = n;
        }
    }
    incoming.restore();
    if (!bytes) { jit.Regs()[0] = call("_Z13uploadTextureP9zgSurfacePvjjjS1_jjj", a); return; }
    GuestBytes output(8);
    uint32_t context = call("zg_RenderContext_Get");
    call("zg_Surface_Lock", {context, s, output.address, output.address + 4});
    call("__aeabi_memcpy", {word(output.address), src, bytes});
    jit.Regs()[0] = call("zg_Surface_Unlock", {s, output.address});
}
void zero_hook(Jit& jit, Host&) {
    uint32_t dest = jit.Regs()[0], size = jit.Regs()[1], caller = jit.Regs()[14] - base, frame = jit.Regs()[4];
    ErrorState incoming;
    uint32_t capacity = 0, pointer = 0;
    switch (caller) { case 0x18e924: capacity = 0x28; pointer = 0x34; break; case 0x18e930: capacity = 0x38; pointer = 0x44; break; case 0x18e93c: capacity = 0x48; pointer = 0x54; break; }
    bool cleared = false;
    if (capacity && game_thread && size == 0x100000 && dest && frame && !(frame & 3) && word(base + 0x2f598e4) == frame && word(frame + capacity) == size && word(frame + pointer) == dest) {
        size_t page = size_t(sysconf(_SC_PAGESIZE));
        uintptr_t start = reinterpret_cast<uintptr_t>(span(dest, size));
        if (page && !(page & (page - 1)) && page <= size) {
            uintptr_t end = start + size, low = (start + page - 1) & ~(page - 1), high = end & ~(page - 1);
            if (high > low && !madvise(reinterpret_cast<void*>(low), high - low, MADV_FREE) && !madvise(reinterpret_cast<void*>(low), high - low, MADV_DONTNEED)) {
                if (low != start) { incoming.restore(); call("__aeabi_memclr", {dest, uint32_t(low - start)}); }
                if (high != end) { incoming.restore(); call("__aeabi_memclr", {dest + uint32_t(high - start), uint32_t(end - high)}); }
                cleared = true;
            }
        }
    }
    if (!cleared) { incoming.restore(); call("__aeabi_memclr", {dest, size}); }
    incoming.restore();
    // RTABI: do not replace any incoming register/FP state in the outer JIT.
}

// Original fixed-source QA dispatcher with explicit guest32 state words.
#include "grim_reference/qa_guard_source.h"
#include "grim_reference/qa_menu_source.h"
typedef uint32_t lua_object;
struct qa_api {
    void (*beginblock)(void);
    void (*endblock)(void);
    lua_object (*getglobal)(const char *);
    int (*isfunction)(lua_object);
    int (*isstring)(lua_object);
    const char *(*getstring)(lua_object);
    int (*callfunction)(lua_object);
    int (*dostring)(const char *);
    uint32_t *state;
    uint32_t *main_state;
    int *exit_requested;
    int *fps;
    int *perf;
};
struct qa_consumer {
    struct qa_api api;
    pthread_t owner;
    int owner_bound;
    int executing;
    int helpers_installed;
    int overlays_changed;
    int old_fps;
    int old_perf;
};
enum qa_command { QA_OPEN_CHEAT, QA_CANCEL, QA_CONFIRM, QA_FPS_ON, QA_FPS_OFF,
                  QA_PERF_ON, QA_PERF_OFF, QA_RESET };
enum qa_result { QA_OK = 0, QA_UNAVAILABLE = -1, QA_WRONG_THREAD = -2,
                 QA_WAIT_SAFE_SLOT = -3, QA_STALE = -4, QA_LUA_ERROR = -5 };

static const char qa_forget_helpers[] =
    "GF_Port_QA_Block=nil;GF_Port_QA_Ready=nil;GF_Port_QA_ValidSet=nil;"
    "GF_Port_QA_AllowedSet=nil;GF_Port_QA_RestoreRoomView=nil;"
    "GF_Port_QA_HideRoomMenu=nil;GF_Port_QA_FilterRoomView=nil;"
    "GF_Port_QA_ClearPending=nil;GF_Port_QA_Select=nil;GF_Port_QA_OpenCheat=nil;"
    "GF_Port_QA_Cancel=nil;GF_Port_QA_Confirm=nil;GF_Port_QA_Stop=nil;"
    "GF_Port_QA_status=nil;GF_Port_QA_sequence=nil;GF_Port_QA_original_teleport=nil;"
    "GF_Port_QA_original_hide=nil;GF_Port_QA_original_set_table=nil;GF_Port_QA_original_set_count=nil;"
    "GF_Port_QA_pending_set=nil;GF_Port_QA_pending_name=nil;GF_Port_QA_pending_file=nil;"
    "GF_Port_QA_pending_key=nil;GF_Port_QA_origin_set=nil;GF_Port_QA_origin_actor=nil;"
    "GF_Port_QA_owns_pending_pause=nil";

/* Parent must call from a positively identified game/render callback.
 * Do not bind ownership from a Java onCreate/JNI initialization call.
 */
void qa_bind_game_owner(struct qa_consumer *q)
{
    q->owner = pthread_self();
    q->owner_bound = 1;
}

static uint32_t state_word(uint32_t state, size_t offset)
{
    uint32_t value;
    memcpy(&value, span(state + offset, 4), sizeof(value));
    return value;
}

static int safe_slot(struct qa_consumer *q)
{
    if (!q->owner_bound || !pthread_equal(q->owner, pthread_self())) return QA_WRONG_THREAD;
    if (q->executing || !q->api.state || !*q->api.state || *q->api.exit_requested) return QA_WAIT_SAFE_SLOT;
    /* Pinned engine ABI. L+24 is a saved/restored context counter and protected
     * Lua errors can leave it nonzero after native execution has returned.
     * Use the exact game-loop caller contract plus the idle root context:
     * +0 execution frame, +4 suspended previous frame, +8 protected/break depth,
     * +52 active protected error jump, +188 outstanding native API blocks.
     * Child tasks can have suspended heap frames; they are never this QA slot.
     */
    uint32_t state = *q->api.state;
    if (!q->api.main_state || state != *q->api.main_state) return QA_WAIT_SAFE_SLOT;
    if (state_word(state, 0) != 0 || state_word(state, 4) != 0 ||
        state_word(state, 8) != 0 || state_word(state, 52) != 0 ||
        state_word(state, 188) != 0) return QA_WAIT_SAFE_SLOT;
    return QA_OK;
}

static void copy_global(struct qa_api *a, const char *name, char *out, size_t capacity)
{
    lua_object object = a->getglobal(name);
    const char *value = object && a->isstring(object) ? a->getstring(object) : NULL;
    if (!capacity) return;
    if (!value) value = "";
    size_t n = strnlen(value, capacity - 1);
    memcpy(out, value, n);
    out[n] = '\0';
}

/* Called at the same safe game slot. Native copies only cross back to Android.
 * Parent shows per-room confirmation when key becomes non-empty/changes.
 */
int qa_pending(struct qa_consumer *q, char key[32], char room[260])
{
    int result = safe_slot(q);
    if (result != QA_OK) return result;
    q->executing = 1;
    q->api.beginblock();
    copy_global(&q->api, "GF_Port_QA_pending_key", key, 32);
    copy_global(&q->api, "GF_Port_QA_pending_file", room, 260);
    q->api.endblock();
    q->executing = 0;
    return QA_OK;
}

/* Request strings are copied at enqueue time; no untrusted Lua text is accepted.
 * epoch changes on new/load/pause/surface loss; discard old queued UI commands.
 * pending_key is mandatory for CONFIRM and pending CANCEL.
 */
int qa_execute(struct qa_consumer *q, enum qa_command command,
               uint64_t request_epoch, uint64_t game_epoch, const char *pending_key,
               char status[260])
{
    int result = safe_slot(q);
    if (result != QA_OK) return result;
    if (request_epoch != game_epoch) return QA_STALE;
    if (command < QA_OPEN_CHEAT || command > QA_RESET) return QA_UNAVAILABLE;
    if (command >= QA_FPS_ON && command <= QA_PERF_OFF) {
        if (!q->overlays_changed) {
            q->old_fps = *q->api.fps;
            q->old_perf = *q->api.perf;
            q->overlays_changed = 1;
        }
        if (command == QA_FPS_ON || command == QA_FPS_OFF) *q->api.fps = command == QA_FPS_ON;
        else *q->api.perf = command == QA_PERF_ON;
        strcpy(status, "Overlay selection applied");
        return QA_OK;
    }
    const char *function = NULL;
    lua_object object = 0;
    q->executing = 1;
    uint32_t state_at_entry = *q->api.state;
    q->api.beginblock();
    if (command == QA_OPEN_CHEAT && !q->api.isfunction(q->api.getglobal("GF_Port_QA_OpenCheat"))) {
        q->helpers_installed = 1; /* retain dirty flag even after a partial error */
        if (q->api.dostring(qa_guard_source) != 0) { result = QA_LUA_ERROR; goto finish; }
    }
    if (command == QA_OPEN_CHEAT) q->helpers_installed = 1;
    if (command == QA_CONFIRM || command == QA_CANCEL) {
        char current_key[32];
        copy_global(&q->api, "GF_Port_QA_pending_key", current_key, sizeof(current_key));
        if (!pending_key || !*current_key || strcmp(current_key, pending_key) != 0) {
            result = QA_STALE;
            goto finish;
        }
    }
    function = command == QA_OPEN_CHEAT ? "GF_Port_QA_OpenCheat" :
        command == QA_CANCEL ? "GF_Port_QA_Cancel" : command == QA_CONFIRM ? "GF_Port_QA_Confirm" : "GF_Port_QA_Stop";
    object = q->api.getglobal(function);
    if (object && q->api.isfunction(object)) {
        result = q->api.callfunction(object) == 0 ? QA_OK : QA_LUA_ERROR;
    } else if (command != QA_RESET) {
        result = QA_UNAVAILABLE;
    }
    copy_global(&q->api, "GF_Port_QA_status", status, 260);
    if (command == QA_RESET && result == QA_OK) {
        if (q->api.dostring(qa_forget_helpers) != 0) result = QA_LUA_ERROR;
        if (result == QA_OK) q->helpers_installed = 0;
        if (q->overlays_changed) {
            *q->api.fps = q->old_fps;
            *q->api.perf = q->old_perf;
            q->overlays_changed = 0;
        }
    }
finish:
    if (*q->api.state != state_at_entry) {
        q->executing = 0;
        return QA_LUA_ERROR;
    }
    q->api.endblock();
    q->executing = 0;
    return result;
}
/* Include after qa_dispatch.c in the same ARM32 translation unit.
 * Parent owns queue/epoch, hook installation and module preimage verification.
 */
static int qa_main_loop_caller(uintptr_t base, uintptr_t caller)
{
    return caller == base + 0x18983cu || caller == base + 0x1899acu ||
           caller == base + 0x189d7cu;
}

/* PRE Main_Service. All engine Save/New/Load requests are deferred flags and
 * begin processing inside its UpdateManual call. Only active injected state
 * requires reset: startup restore with no QA state must proceed normally.
 * Return QA_OK to call original; any other result defers this whole service.
 */
static int qa_before_main_service(struct qa_consumer *q, uintptr_t base, uintptr_t caller)
{
    if (!qa_main_loop_caller(base, caller)) return QA_WRONG_THREAD;
    if (!q->owner_bound) qa_bind_game_owner(q);
    if (!pthread_equal(q->owner, pthread_self())) return QA_WRONG_THREAD;
    const volatile unsigned char *flags = static_cast<const volatile unsigned char *>(span(base + 0x16c7d30u, 5));
    if (!(flags[1] || flags[2] || flags[4])) return QA_OK;
    if (!q->helpers_installed && !q->overlays_changed) return QA_OK;
    char status[260] = {0};
    /* Internal mandatory reset has no stale UI epoch. The parent separately
     * invalidates queued UI command epochs before new/load/teardown.
     */
    return qa_execute(q, QA_RESET, 0, 0, NULL, status);
}

/* POST UpdateManual, before Main_Service draws overlays/display. Caller+thread
 * are necessary; actual L+24/L+188/exit/executing guards still apply per action.
 */
static int qa_after_update_slot(struct qa_consumer *q, uintptr_t base, uintptr_t caller)
{
    if (caller != base + 0x512a4u) return QA_WRONG_THREAD;
    return safe_slot(q);
}

/* Direct SDL_QUIT teardown has no SaveGlobals. Never wait for UI shutdown or
 * invoke Lua from that event/filter thread. Parent discards its queue/replies
 * and increments game epoch before original shutdown closes the Lua state.
 */
static void qa_forget_after_teardown(struct qa_consumer *q)
{
    /* Original shutdown has destroyed Lua; the containing engine module is
     * still mapped while its trampoline POST runs. Restore plain native ints
     * without any Lua/API/state access, then discard their bookkeeping.
     */
    if (q->overlays_changed) {
        *q->api.fps = q->old_fps;
        *q->api.perf = q->old_perf;
    }
    q->owner_bound = 0;
    q->executing = 0;
    q->helpers_installed = 0;
    q->overlays_changed = 0;
}
#include "grim_reference/qa_one_slot.h"
static const struct {
    const char *name;
    uintptr_t va;
    unsigned size;
    unsigned char bytes[60];
} qa_ui_contracts[] = {
    {"lua_setglobal", 0x51b6cu, 16u, {
        0x10,0x40,0x2d,0xe9,0x00,0x40,0xa0,0xe1,
        0x44,0x00,0x9f,0xe5,0x00,0x00,0x9f,0xe7}},
    {"lua_isnil", 0x52a24u, 60u, {
        0x00,0x10,0xa0,0xe1,0x01,0x00,0xa0,0xe3,0x00,0x00,0x51,0xe3,
        0x1e,0xff,0x2f,0x01,0x20,0x00,0x9f,0xe5,0x00,0x00,0x9f,0xe7,
        0x00,0x00,0x90,0xe5,0x20,0x00,0x90,0xe5,0x01,0x02,0x80,0xe0,
        0x08,0x10,0x10,0xe5,0x00,0x00,0xa0,0xe3,0x07,0x00,0x71,0xe3,
        0x01,0x00,0x00,0x03,0x1e,0xff,0x2f,0xe1,0x14,0x3c,0x25,0x00}},
    {"zg_Platform_GetBackBuffer", 0x191998u, 40u, {
        0x00,0x00,0x50,0xe3,0x18,0x20,0x9f,0x15,0x02,0x20,0x8f,0x10,
        0x04,0x20,0x92,0x15,0x00,0x20,0x80,0x15,0x00,0x00,0x51,0xe3,
        0x00,0x00,0xa0,0x13,0x00,0x00,0x81,0x15,0x1e,0xff,0x2f,0xe1,
        0xb8,0x80,0xdc,0x02}},
    {"zg_RenderTarget_GetInfo", 0x192524u, 40u, {
        0x00,0x00,0x51,0xe3,0x00,0xc0,0x90,0x15,0x00,0xc0,0x81,0x15,
        0x00,0x00,0x52,0xe3,0x04,0x10,0x90,0x15,0x00,0x10,0x82,0x15,
        0x00,0x00,0x53,0xe3,0x08,0x00,0x90,0x15,0x00,0x00,0x83,0x15,
        0x1e,0xff,0x2f,0xe1}}
};

uint32_t text_call(const char* name, const char* value) {
    GuestBytes text(value); return call(name, {text.address});
}
void qb_begin() { call("lua_beginblock"); }
void qb_end() { call("lua_endblock"); }
lua_object qb_global(const char* name) { return text_call("lua_getglobal", name); }
int qb_function(lua_object object) { return int(call("lua_isfunction", {object})); }
int qb_string(lua_object object) { return int(call("lua_isstring", {object})); }
const char* qb_getstring(lua_object object) { return string32(call("lua_getstring", {object})); }
int qb_call(lua_object object) { return int(call("lua_callfunction", {object})); }
int qb_execute(const char* source) { return int(text_call("lua_dostring", source)); }
qa_consumer qa_game{};
qa_one_slot qa_commands{};
int qa_last_flags;
std::mutex qa_game_lock, qa_reply_lock;
bool qa_menu_dirty;
// Restore only the FPS preference and live stock gauge after a failed disk commit.
// All four sources are fixed; no closure or caller string is serialized.
static const char* const fps_registry_rollback[] = {
    R"LUA(WriteRegistryValue("PortFPSLimitMode",0);GF_Port_FPS_mode=0;local k,e=next(GF_Port_Options_menu.navigate,nil);while k do if type(e)=="table" and e.gauge==GF_Port_FPS_gauge then e.gauge.value=0;e.gauge:update() end;k,e=next(GF_Port_Options_menu.navigate,k) end)LUA",
    R"LUA(WriteRegistryValue("PortFPSLimitMode",1);GF_Port_FPS_mode=1;local k,e=next(GF_Port_Options_menu.navigate,nil);while k do if type(e)=="table" and e.gauge==GF_Port_FPS_gauge then e.gauge.value=1;e.gauge:update() end;k,e=next(GF_Port_Options_menu.navigate,k) end)LUA",
    R"LUA(WriteRegistryValue("PortFPSLimitMode",2);GF_Port_FPS_mode=2;local k,e=next(GF_Port_Options_menu.navigate,nil);while k do if type(e)=="table" and e.gauge==GF_Port_FPS_gauge then e.gauge.value=2;e.gauge:update() end;k,e=next(GF_Port_Options_menu.navigate,k) end)LUA",
    R"LUA(WriteRegistryValue("PortFPSLimitMode",3);GF_Port_FPS_mode=3;local k,e=next(GF_Port_Options_menu.navigate,nil);while k do if type(e)=="table" and e.gauge==GF_Port_FPS_gauge then e.gauge.value=3;e.gauge:update() end;k,e=next(GF_Port_Options_menu.navigate,k) end)LUA"
};
uint64_t qa_menu_sequence, qa_menu_epoch;
uint64_t language_sequence;
int language_requested, language_accepted = -1, language_rollback = -1;
struct {
    uint64_t ticket;
    int result, fps, perf;
    char status[260], key[32], room[260];
} qa_reply{};
struct {
    uint32_t width = 0, height = 0, state = 0;
    bool dirty = true;
} qa_layout;
constexpr unsigned kOverlayRows = 13, kOverlayLine = 384;
struct Overlay {
    char fps[kOverlayLine]{}, perf[kOverlayRows][kOverlayLine]{};
    bool fps_valid = false, perf_valid = false;
};
Overlay overlay;
char overlay_stage[kOverlayRows][kOverlayLine]{};
unsigned overlay_next;
std::mutex overlay_lock;
void clear_overlay() { std::lock_guard lock(overlay_lock); overlay = {}; memset(overlay_stage, 0, sizeof(overlay_stage)); overlay_next = 0; }
void clear_reply(bool retain) {
    clear_overlay();
    std::lock_guard lock(qa_reply_lock);
    qa_menu_epoch = 0;
    if (retain && qa_reply.ticket) { qa_reply.fps = qa_reply.perf = 0; memset(qa_reply.key, 0, sizeof(qa_reply.key)); memset(qa_reply.room, 0, sizeof(qa_reply.room)); }
    else qa_reply = {};
}

int remove_additional_menu() {
    if (!qa_menu_dirty) return QA_OK;
    int result = safe_slot(&qa_game);
    if (result != QA_OK) return result;
    ErrorState incoming;
    qa_game.executing = 1;
    uint32_t state = *qa_game.api.state;
    qb_begin();
    result = qb_execute(qa_menu_remove_source) ? QA_LUA_ERROR : QA_OK;
    if (*qa_game.api.state == state) qb_end();
    else result = QA_LUA_ERROR;
    qa_game.executing = 0;
    if (result == QA_OK) qa_menu_dirty = false;
    incoming.restore();
    return result;
}

void update_additional_menu() {
    const bool transition = byte(base + 0x16c7d31) || byte(base + 0x16c7d32) || byte(base + 0x16c7d34);
    if (transition && !qa_menu_dirty) return;
    ErrorState incoming;
    qa_game.executing = 1;
    uint32_t state = *qa_game.api.state;
    qb_begin();
    int result = QA_OK;
    if (!qa_menu_dirty && !transition && !call("lua_isnil", {qb_global("bootComplete")}) &&
        call("lua_istable", {qb_global("special_menu")})) {
        // Mark dirty before execution so a partial protected error must also
        // be restored before the engine can serialize any Lua globals.
        qa_menu_dirty = true;
        language_bootstrap = false;
        const char* label = GrimCacheRussianText()
            ? "\xc4\xee\xef\xee\xeb\xed\xe8\xf2\xe5\xeb\xfc\xed\xfb\xe5\x20\xe2\xee\xe7\xec\xee\xe6\xed\xee\xf1\xf2\xe8"
            : "Additional features";
        text_call("lua_pushstring", label);
        text_call("lua_setglobal", "GF_Port_Options_label");
        text_call("lua_pushstring", GrimCacheRussianText() ? "\xce\xe3\xf0\xe0\xed\xe8\xf7\xe5\xed\xe8\xe5\x20\x46\x50\x53" : "FPS limit");
        text_call("lua_setglobal", "GF_Port_FPS_label");
        text_call("lua_pushstring", GrimCacheRussianText() ? "\xd7\xe0\xf1\xf2\xee\xf2\xe0\x20\xfd\xea\xf0\xe0\xed\xe0" : "Display Hz");
        text_call("lua_setglobal", "GF_Port_FPS_dynamic_label");
        int language;
        {
            std::lock_guard lock(qa_reply_lock);
            if (language_accepted < 0) {
                language_accepted = GrimCacheLanguageSelection();
                if (language_accepted < 0) language_accepted = GrimGuestLanguage();
                if (language_accepted < 0 || language_accepted > 6) language_accepted = 0;
                if (language_accepted == 6 && !GrimCacheSourcePresent(2) && !GrimCacheSourcePresent(3)) language_accepted = 0;
            }
            language = language_accepted;
        }
        call("lua_pushnumber", {fbits(float(language))});
        text_call("lua_setglobal", "GF_Port_Language_selection");
        call("lua_pushnumber", {fbits(float(GrimCacheSourcePresent(2) || GrimCacheSourcePresent(3)))});
        text_call("lua_setglobal", "GF_Port_Language_available");
        call("lua_pushnumber", {fbits(float(GrimCacheLanguageSelection() == 6))});
        text_call("lua_setglobal", "GF_Port_Language_active_russian");
        text_call("lua_pushstring", GrimCacheRussianText() ? "\xd0\xf3\xf1\xf1\xea\xe8\xe9" : "Russian");
        text_call("lua_setglobal", "GF_Port_Language_russian_label");
        text_call("lua_pushstring", GrimCacheRussianText() ? "\xc0\xed\xe3\xeb\xe8\xe9\xf1\xea\xe8\xe9" : "English");
        text_call("lua_setglobal", "GF_Port_Language_english_label");
        result = qb_execute(qa_menu_install_source) ? QA_LUA_ERROR : QA_OK;
        if (result != QA_OK) __android_log_print(ANDROID_LOG_ERROR, "GrimCache", "Additional menu installation failed");
    }
    if (result == QA_OK && qa_menu_dirty && *qa_game.api.state == state) {
        int rollback;
        {
            std::lock_guard lock(qa_reply_lock);
            rollback = language_rollback;
            language_rollback = -1;
        }
        if (rollback >= 0) {
            char source[256];
            snprintf(source,sizeof(source),"GF_Port_Language_selection=%d;if GF_Port_Language_active_russian~=1 and %d<6 then GF_Port_FPS_write(GF_Port_FPS_prefs,'Language',%d) end;if GF_Port_Language_gauge then GF_Port_Language_gauge:set_value(%d) end",rollback,rollback,rollback,rollback);
            result = qb_execute(source) ? QA_LUA_ERROR : QA_OK;
        }
        char language[4]{};
        if (result == QA_OK) copy_global(&qa_game.api,"GF_Port_Language_requested",language,sizeof(language));
        if (language[0] >= '0' && language[0] <= '6' && !language[1]) {
            result = qb_execute("GF_Port_Language_requested=nil") ? QA_LUA_ERROR : QA_OK;
            if (result == QA_OK && *qa_game.api.state == state) {
                std::lock_guard lock(qa_reply_lock);
                language_requested = language[0] - '0';
                ++language_sequence;
            }
        }
        char requested[4]{};
        if (result == QA_OK && *qa_game.api.state == state)
            copy_global(&qa_game.api, "GF_Port_Options_requested", requested, sizeof(requested));
        int request = result == QA_OK ? GrimFramePacing::MenuRequest(requested) : -1;
        if (request >= 0) {
            result = qb_execute("GF_Port_Options_requested=nil;GF_Port_FPS_additional=0;GF_Port_FPS_failed=0;GF_Port_FPS_commit=0") ? QA_LUA_ERROR : QA_OK;
            if (result == QA_OK && *qa_game.api.state == state) {
                // The same safe POST signal carries mode, launch, failure and
                // one-shot commit bits; no extra per-frame Lua polling is added.
                if (request & 16) {
                    const int previous = GrimFramePacing::PolicyState() & 3;
                    // Raw whole176B body: zero args, native BOOL1 means success.
                    // Bootstrap/load publication has no commit bit; write only
                    // after an actual successful FPS memory readback.
                    const uint32_t saved = call("wuRegistry_SaveRegistry");
                    if (*qa_game.api.state != state || engine->HasFailed()) result = QA_LUA_ERROR;
                    else if (saved != 1) {
                        result = qb_execute(fps_registry_rollback[previous]) ? QA_LUA_ERROR : QA_OK;
                        request = previous | (request & 4) | 8;
                        if (result != QA_OK) __android_log_print(ANDROID_LOG_ERROR, "GrimCache", "FPS registry rollback failed");
                    }
                }
                if (result == QA_OK && *qa_game.api.state == state) {
                    GrimFramePacing::SetMode(request & 3);
                } else {
                    request = (GrimFramePacing::PolicyState() & 3) | 8;
                    __android_log_print(ANDROID_LOG_ERROR, "GrimCache", "FPS registry operation changed or failed the safe Lua state");
                }
                if (request & 8) {
                    GrimFramePacing::RegistryFailure();
                    __android_log_print(ANDROID_LOG_WARN, "GrimCache", "FPS registry write or commit failed; previous mode retained");
                }
                if ((request & 4) && !transition) {
                    uint64_t epoch = qa_slot_epoch(&qa_commands);
                    std::lock_guard lock(qa_reply_lock);
                    ++qa_menu_sequence;
                    qa_menu_epoch = epoch;
                }
            }
        }
    }
    if (*qa_game.api.state == state) qb_end();
    qa_game.executing = 0;
    incoming.restore();
}
uint64_t now_ms() {
    timespec t{}; clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000 + uint64_t(t.tv_nsec) / 1000000;
}
void overlay_hook(Jit& jit, Host&) {
    uint32_t text = jit.Regs()[0], x = jit.Regs()[1], y = jit.Regs()[2], lr = jit.Regs()[14];
    bool fps = lr == base + 0x51358 && y == 4;
    bool perf = lr == base + 0x513cc && y >= 30 && y <= 270 && (y - 30) % 20 == 0;
    if (text == base + 0x306c5cc && x == 4 && (fps || perf)) {
        char line[kOverlayLine]{}; bool valid = false;
        const char* source = static_cast<const char*>(span(text, kOverlayLine));
        for (unsigned i = 0; i < kOverlayLine; ++i) {
            unsigned char c = source[i];
            if (!c) { valid = true; break; }
            if (i == kOverlayLine - 1 || c < 32 || c > 126) break;
            line[i] = char(c);
        }
        std::lock_guard lock(overlay_lock);
        if (fps) { overlay.fps_valid = valid; memcpy(overlay.fps, valid ? line : "", valid ? sizeof(line) : 1); }
        else {
            unsigned row = (y - 30) / 20;
            if (!row) overlay_next = 0;
            if (!valid || row != overlay_next) { overlay_next = 0; overlay.perf_valid = false; }
            else { memcpy(overlay_stage[row], line, sizeof(line)); if (++overlay_next == kOverlayRows) { memcpy(overlay.perf, overlay_stage, sizeof(overlay_stage)); overlay.perf_valid = true; overlay_next = 0; } }
        }
    }
    jit.Regs()[0] = call("stdDisplay_TextOut", {text, x, y});
}

void ui_reflow(uint32_t caller) {
    ErrorState incoming;
    if (qa_after_update_slot(&qa_game, base, caller) != QA_OK) return;
    GuestBytes output(12);
    call("zg_Platform_GetBackBuffer", {output.address, 0});
    uint32_t target = word(output.address);
    if (!target) { incoming.restore(); return; }
    call("zg_RenderTarget_GetInfo", {target, output.address + 4, output.address + 8, 0});
    uint32_t width = word(output.address + 4), height = word(output.address + 8), entry = *qa_game.api.state;
    if (!width || !height) { incoming.restore(); return; }
    if (width != qa_layout.width || height != qa_layout.height || entry != qa_layout.state) { GrimFramePacing::Reset(); qa_layout.dirty = true; }
    qa_layout.width = width; qa_layout.height = height; qa_layout.state = entry;
    if (!qa_layout.dirty || byte(base + 0x16c7d32) || byte(base + 0x16c7d34)) { incoming.restore(); return; }
    qa_game.executing = 1;
    qb_begin();
    bool ready = !call("lua_isnil", {qb_global("bootComplete")}) && qb_function(qb_global("DestroyAllUIButtonsImmediately")) && qb_function(qb_global("UpdateUIButtons"));
    if (*qa_game.api.state != entry) { qa_layout.dirty = false; qa_game.executing = 0; incoming.restore(); return; }
    qb_end();
    if (ready) {
        qa_layout.dirty = false; // consumed once, including a protected failure
        for (const char* function : {"DestroyAllUIButtonsImmediately", "UpdateUIButtons"}) {
            qb_begin();
            lua_object handle = qb_global(function);
            int result = qb_function(handle) ? (qb_call(handle) ? QA_LUA_ERROR : QA_OK) : QA_UNAVAILABLE;
            if (*qa_game.api.state != entry) break;
            qb_end();
            if (result != QA_OK) break;
        }
    }
    qa_game.executing = 0; incoming.restore();
}
// Source-only fragment inserted before service_pre; existing owner/QA locks apply.
arena_memory::Series arena_series;
struct ArenaErrno {
    int saved = errno;
    ~ArenaErrno() { errno = saved; }
};
struct ArenaFd {
    int value;
    ~ArenaFd() { if (value >= 0) ::close(value); }
};
void arena_memory_control(qa_command command, uint64_t epoch) {
    ArenaErrno incoming;
    if (command == QA_PERF_ON && epoch == qa_slot_epoch(&qa_commands)) arena_series.start(epoch, now_ms());
    else if (command == QA_PERF_OFF || command == QA_RESET) arena_series.stop();
}
bool arena_memory_eligible(uint32_t caller) {
    uint64_t epoch;
    return installed && engine && game_thread && !engine->HasFailed() &&
        caller == base + 0x512a4 && qa_after_update_slot(&qa_game, base, caller) == QA_OK &&
        quit_request.load(std::memory_order_acquire) == QuitRequest::Idle &&
        !qa_slot_reset_pending(&qa_commands, &epoch) && *qa_game.api.perf &&
        !byte(base + 0x16c7d31) && !byte(base + 0x16c7d32) && !byte(base + 0x16c7d34);
}
struct ArenaRead {
    arena_memory::Parser parser;
    uint64_t procstart = 0;
    int io_errno = 0;
    const char* failure = nullptr;
    ArenaRead(uint64_t b, uint64_t e) : parser(b, e) {}
};
void arena_memory_read(ArenaRead& result, uint64_t started) {
    if (result.parser.error) { result.failure = result.parser.error; return; }
    {
        ArenaFd stat{::open("/proc/self/stat", O_RDONLY | O_CLOEXEC)};
        if (stat.value < 0) { result.failure = "stat_open"; result.io_errno = errno; return; }
        char text[4096];
        ssize_t length = ::read(stat.value, text, sizeof(text));
        uint64_t pid = 0;
        if (length <= 0) { result.failure = "stat_read"; result.io_errno = length < 0 ? errno : 0; return; }
        if (size_t(length) == sizeof(text) || !arena_memory::proc_identity(text, size_t(length), pid, result.procstart) || pid != uint64_t(getpid())) {
            result.failure = "stat_identity"; return;
        }
    }
    if (now_ms() - started > arena_memory::kReadBudgetMs) { result.failure = "time_cap"; return; }
    ArenaFd smaps{::open("/proc/self/smaps", O_RDONLY | O_CLOEXEC)};
    if (smaps.value < 0) { result.failure = "smaps_open"; result.io_errno = errno; return; }
    char block[4096], line[arena_memory::kLineLimit];
    size_t used = 0;
    uint64_t read_bytes = 0;
    while (!result.parser.done) {
        if (now_ms() - started > arena_memory::kReadBudgetMs) { result.failure = "time_cap"; return; }
        ssize_t length = ::read(smaps.value, block, sizeof(block));
        if (length < 0) { result.failure = "smaps_read"; result.io_errno = errno; return; }
        if (!length) {
            if (used) { result.failure = "line_incomplete"; return; }
            if (!result.parser.finish()) result.failure = result.parser.error;
            break;
        }
        if (read_bytes > arena_memory::kTextLimit - uint64_t(length)) { result.failure = "text_cap"; return; }
        read_bytes += uint64_t(length);
        for (ssize_t i = 0; i < length && !result.parser.done; ++i) {
            if (used == sizeof(line)) { result.failure = "line_cap"; return; }
            line[used++] = block[i];
            if (block[i] == '\n') {
                if (!result.parser.feed(line, used)) { result.failure = result.parser.error; return; }
                used = 0;
            }
        }
    }
    if (now_ms() - started > arena_memory::kReadBudgetMs) result.failure = "time_cap";
    else if (!result.parser.finish()) result.failure = result.parser.error;
}
void arena_memory_post(uint32_t caller) {
    ArenaErrno incoming;
    if (caller != base + 0x512a4 || !game_thread || !arena_series.armed) return;
    uint64_t epoch, arm, seq, started, begin, end, bytes;
    unsigned attempt;
    Host* observed;
    {
        std::lock_guard lock(qa_game_lock);
        if (!qa_game.owner_bound || !pthread_equal(qa_game.owner, pthread_self())) return;
        epoch = qa_slot_epoch(&qa_commands);
        if (!arena_memory_eligible(caller) || (arena_series.armed && arena_series.epoch != epoch)) { arena_series.stop(); return; }
        started = now_ms();
        if (!arena_series.take(epoch, started)) return;
        observed = engine; arm = arena_series.arm; seq = arena_series.seq; attempt = arena_series.attempts;
        begin = uint64_t(reinterpret_cast<uintptr_t>(observed->GetGuestMemoryBase()));
        bytes = uint64_t(observed->GetGuestMemorySize());
        end = bytes <= UINT64_MAX - begin ? begin + bytes : 0;
    }
    long page = sysconf(_SC_PAGESIZE);
    ArenaRead result(begin, end);
    if (page < 4096 || (uint64_t(page) & (uint64_t(page) - 1)) || bytes != arena_memory::kBytes ||
        !begin || !end || begin % uint64_t(page) || end % uint64_t(page)) result.failure = "arena_range";
    else arena_memory_read(result, started);
    uint64_t ended = now_ms();
    {
        std::lock_guard lock(qa_game_lock);
        if (!arena_memory_eligible(caller) || qa_slot_epoch(&qa_commands) != epoch ||
            !arena_series.current(epoch, arm) || engine != observed ||
            uint64_t(reinterpret_cast<uintptr_t>(engine->GetGuestMemoryBase())) != begin ||
            uint64_t(engine->GetGuestMemorySize()) != bytes) { result.failure = "context_changed"; arena_series.stop(); }
    }
    if (!result.failure && ended - started > arena_memory::kReadBudgetMs) result.failure = "time_cap";
    char metrics[128];
    if (!result.failure) snprintf(metrics, sizeof(metrics), "rss_kib=%llu swap_kib=%llu sum_kib=%llu",
        static_cast<unsigned long long>(result.parser.rss_kib), static_cast<unsigned long long>(result.parser.swap_kib),
        static_cast<unsigned long long>(result.parser.rss_kib + result.parser.swap_kib));
    else snprintf(metrics, sizeof(metrics), "rss_kib=NA swap_kib=NA sum_kib=NA");
    __android_log_print(ANDROID_LOG_INFO, "GrimCache",
        "arena_mem schema=1 status=%s reason=%s seq=%llu arm=%llu attempt=%u last=%u pid=%d procstart=%llu uid=%u tid=%ld epoch=%llu begin=%016llx end=%016llx bytes=%llu page=%ld coverage_bytes=%llu vmas=%u begin_ms=%llu end_ms=%llu cost_ms=%llu io_errno=%d %s",
        result.failure ? "UNAVAILABLE" : "OK", result.failure ? result.failure : "complete", static_cast<unsigned long long>(seq),
        static_cast<unsigned long long>(arm), attempt, attempt == arena_memory::kAttempts ? 1u : 0u, int(getpid()),
        static_cast<unsigned long long>(result.procstart), unsigned(getuid()), long(syscall(SYS_gettid)), static_cast<unsigned long long>(epoch),
        static_cast<unsigned long long>(begin), static_cast<unsigned long long>(end), static_cast<unsigned long long>(bytes), page,
        static_cast<unsigned long long>(result.parser.covered), result.parser.arena_vmas, static_cast<unsigned long long>(started),
        static_cast<unsigned long long>(ended), static_cast<unsigned long long>(ended - started), result.io_errno, metrics);
    if (arena_series.arm == arm && attempt == arena_memory::kAttempts) arena_series.stop();
}

bool service_pre(uint32_t caller) {
    if (!qa_main_loop_caller(base, caller)) return true;
    std::lock_guard lock(qa_game_lock);
    if (!qa_game.owner_bound) qa_bind_game_owner(&qa_game);
    game_thread = pthread_equal(qa_game.owner, pthread_self());
    if (byte(base + 0x16c7d32) || byte(base + 0x16c7d34)) qa_layout.dirty = true;
    bool pending = byte(base + 0x16c7d31) || byte(base + 0x16c7d32) || byte(base + 0x16c7d34);
    if (pending) arena_series.stop();
    if (pending && !qa_last_flags) { GrimFramePacing::Reset(); back_cancel(); qa_slot_invalidate(&qa_commands); clear_reply(true); }
    back_release_owned();
    qa_last_flags = pending;
    uint64_t epoch; int result = QA_OK;
    if (pending) result = remove_additional_menu();
    if (qa_slot_reset_pending(&qa_commands, &epoch)) {
        if (result == QA_OK) result = remove_additional_menu();
        if (result == QA_OK && (qa_game.helpers_installed || qa_game.overlays_changed)) { char status[260]{}; result = qa_execute(&qa_game, QA_RESET, epoch, epoch, nullptr, status); }
        if (result == QA_OK) qa_slot_reset_ack(&qa_commands, epoch);
    }
    if (result == QA_OK) result = qa_before_main_service(&qa_game, base, caller);
    return result == QA_OK;
}
void update_post(uint32_t caller) {
    if (caller != base + 0x512a4) return;
    std::lock_guard lock(qa_game_lock);
    if (qa_after_update_slot(&qa_game, base, caller) != QA_OK) return;
    update_additional_menu();
    ui_reflow(caller);
    qa_slot_request request{}; uint64_t epoch;
    if (qa_slot_peek(&qa_commands, &request, &epoch)) {
        char status[260]{};
        int result = qa_slot_expired(&request, now_ms()) ? QA_STALE : qa_execute(&qa_game, request.command, request.epoch, epoch, request.pending_key, status);
        if (result == QA_OK && ((request.command == QA_OPEN_CHEAT && strcmp(status, "Room menu opened")) || (request.command == QA_CONFIRM && strcmp(status, "Room transition requested")))) result = QA_UNAVAILABLE;
        if (result != QA_WAIT_SAFE_SLOT) {
            if (result == QA_OK) arena_memory_control(request.command, request.epoch);
            if (result == QA_OK && request.command >= QA_FPS_ON) clear_overlay();
            qa_slot_complete(&qa_commands, &request);
            std::lock_guard reply(qa_reply_lock);
            qa_reply.ticket = request.ticket; qa_reply.result = result; memcpy(qa_reply.status, status, sizeof(status));
        }
    }
    char key[32]{}, room[260]{};
    if (qa_game.helpers_installed) qa_pending(&qa_game, key, room);
    std::lock_guard reply(qa_reply_lock);
    memcpy(qa_reply.key, key, sizeof(key)); memcpy(qa_reply.room, room, sizeof(room));
    qa_reply.fps = *qa_game.api.fps; qa_reply.perf = *qa_game.api.perf;
}
void raw_forward(Jit& jit, const char* name, const std::vector<uint32_t>& args) {
    call(name, args);
    // Snapshot before POST helpers run more guest functions.
    std::array<uint32_t, 4> result{};
    for (unsigned i = 0; i < 4; ++i) result[i] = engine->GetResultWord(i);
    for (unsigned i = 0; i < 4; ++i) jit.Regs()[i] = result[i];
}

bool service_quit(uint32_t caller) {
    // This LR is reached only after successful startup and SetEventFilter's flush.
    if (!qa_main_loop_caller(base, caller) ||
        quit_request.load(std::memory_order_acquire) != QuitRequest::Pending) return false;
    const unsigned ready = byte(base + 0x2f59458);
    const uint32_t done = word(base + 0x2f59454);
    const bool qualified = caller == base + 0x18983c && ready == 1 && !done;
    bool owner_bound, owner_match;
    unsigned long long owner;
    {
        std::lock_guard lock(qa_game_lock);
        if (qualified && !qa_game.owner_bound) qa_bind_game_owner(&qa_game);
        owner_bound = qa_game.owner_bound;
        owner_match = owner_bound && pthread_equal(qa_game.owner, pthread_self());
        owner = owner_bound ? static_cast<unsigned long long>(qa_game.owner) : 0;
    }
    const unsigned witness = qualified ? 2u : 1u;
    if (!(quit_witnesses.fetch_or(witness, std::memory_order_relaxed) & witness))
        __android_log_print(ANDROID_LOG_INFO, "GrimCache",
            "guest quit pending edge: caller=%08x ready=%u done=%u owner_bound=%u owner_match=%u owner=%llx self=%llx qualified=%u",
            caller, ready, done, owner_bound ? 1u : 0u, owner_match ? 1u : 0u, owner,
            static_cast<unsigned long long>(pthread_self()), qualified ? 1u : 0u);
    if (!qualified || !owner_match) return false;
    ErrorState incoming;
    const uint32_t present = call("SDL_HasEvent", {0x100});
    uint32_t queued = present;
    if (!engine->HasFailed() && !present) queued = call("SDL_SendQuit");
    incoming.restore();
    if (!engine->HasFailed() && queued != 1)
        engine->Fail("Owner SDL quit event was not queued");
    __android_log_print(ANDROID_LOG_INFO, "GrimCache",
        "guest quit replay: caller=%08x present=%u queued=%u failed=%u",
        caller, present, queued, engine->HasFailed() ? 1u : 0u);
    // Return directly to the original loop; its next EventUpdate owns teardown.
    return true;
}
void service_hook(Jit& jit, Host&) {
    uint32_t caller = jit.Regs()[14];
    std::vector<uint32_t> args{jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]};
    if (service_quit(caller)) { jit.Regs()[0] = jit.Regs()[1] = 0; return; }
    if (service_pre(caller)) {
        raw_forward(jit, "Main_Service", args);
    }
    else { jit.Regs()[0] = jit.Regs()[1] = 0; }
}
void update_hook(Jit& jit, Host&) {
    uint32_t caller = jit.Regs()[14];
    raw_forward(jit, "grimlib_UpdateManual", {jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]});
    update_post(caller);
    arena_memory_post(caller);
}
BackSample back_sample() {
    BackSample sample{};
    sample.current = word(base + 0x2f39b94); sample.previous = word(base + 0x2f39b98);
    for (unsigned i = 0; i < 8; ++i) sample.raw[i] = word(base + 0x2f35aa8 + 4 * i);
    const uint32_t d = base + 0x2b6b38;
    sample.context = {word(d),word(d+4),word(d+12),word(base+0x2b7568),word(base+0x2f70c04),
        word(base+0x2ae990),word(base+0x2ae988),word(base+0x2a86a8),word(base+0x2bac30),
        uint32_t(bool(byte(base+0x16c7d31) || byte(base+0x16c7d32) || byte(base+0x16c7d34))),{0}};
    for (unsigned i = 0; i < 13; ++i) sample.context.remap[i] = word(base + 0x2f59700 + 4 * i);
    return sample;
}
// Only the qualified owner writes guest memory. UI invalidation below changes
// metadata, using this same mutex as the final admission check and publication.
void back_release_locked(const BackSample& sample) {
    if (back_seeded || !back_owned) return;
    if (back_same_publication(back_publication, sample)) put(base + 0x2f35aa8, 0);
    back_owned = false;
}
void back_release_owned() {
    if (!installed || !game_thread || !back_ranges_ready || engine->HasFailed()) return;
    ErrorState incoming;
    { std::lock_guard lock(back_lock); back_release_locked(back_sample()); }
    incoming.restore();
}
void update_key_hook(Jit& jit, Host&) {
    const uint32_t caller = jit.Regs()[14];
    std::vector<uint32_t> args{jit.Regs()[0],jit.Regs()[1],jit.Regs()[2],jit.Regs()[3]};
    if (!installed || !game_thread || !back_ranges_ready || engine->HasFailed()
        || quit_request.load(std::memory_order_acquire) != QuitRequest::Idle
        || args[0] != 27 || args[1] > 1 || args[3] != 0
        || (caller != base + 0x189a48 && caller != base + 0x189b98)) {
        raw_forward(jit, "UpdateKey", args); return;
    }
    ErrorState incoming;
    BackSample before{}; uint64_t generation;
    {
        std::lock_guard lock(back_lock);
        before = back_sample();
        if (back_seeded && (!back_eligible(before.context) || before.context != back_context)) back_retire_locked();
        back_release_locked(before);
        before = back_sample();
        generation = back_input_generation;
    }
    incoming.restore();
    raw_forward(jit, "UpdateKey", args);
    ErrorState outgoing;
    {
        std::lock_guard lock(back_lock);
        const auto after = back_sample();
        const int edge = back_accepted(before,after,args[1],args[2],generation,back_input_generation);
        if (edge < 0) { back_retire_locked(); back_release_locked(after); }
        else {
            if (back_seeded && uint32_t(back_edges.live_down) != before.raw[2]) back_retire_locked();
            if (!back_seeded) {
                back_seed(&back_edges,before.raw[2]);
                back_context = before.context; back_seeded = true; back_owned = false;
            }
            if (edge && ms_submit(&back_edges,static_cast<ms_kind>(edge),0,0) < 0) {
                back_retire_locked(); back_release_locked(after);
            }
        }
    }
    outgoing.restore();
}
void read_controls_hook(Jit& jit, Host&) {
    const uint32_t caller = jit.Regs()[14];
    std::vector<uint32_t> args{jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]};
    if (!installed || !game_thread || !back_ranges_ready || engine->HasFailed()
        || quit_request.load(std::memory_order_acquire) != QuitRequest::Idle || caller != base + 0xa02c0) {
        raw_forward(jit, "stdControl_ReadControls", args); return;
    }
    ErrorState incoming;
    BackSample before{}; uint64_t generation;
    {
        std::lock_guard lock(back_lock);
        before = back_sample();
        if (back_seeded && (!back_eligible(before.context) || before.context != back_context)) back_retire_locked();
        back_release_locked(before);
        generation = back_input_generation;
    }
    incoming.restore();
    raw_forward(jit, "stdControl_ReadControls", args);
    ErrorState outgoing;
    {
        std::lock_guard lock(back_lock);
        const auto after = back_sample();
        if (generation != back_input_generation || !back_eligible(before.context)
            || !back_eligible(after.context) || before.context != after.context) {
            back_retire_locked(); back_release_locked(after);
        } else if (before.current == before.previous && after.current == before.previous
                   && after.current == after.previous) {
            // Original early return: neither consume counters nor advance again.
        } else if (!back_fresh(before, after, generation, back_input_generation)) {
            back_retire_locked(); back_release_locked(after);
        } else if (!back_seeded) {
            back_seed(&back_edges, after.raw[2]);
            back_edges.epoch = after.current; back_edges.epoch_valid = 1;
            back_context = after.context; back_seeded = true; back_owned = false;
        } else {
            back_owned = false; // original fresh copy has replaced the old publication
            if (uint32_t(back_edges.live_down) != after.raw[2]) {
                back_retire_locked(); back_release_locked(after);
            } else if (ms_advance(&back_edges, after.current) && back_edges.owns_mouse) {
                put(base + 0x2f35aa8, uint32_t(back_edges.snapshot.down));
                if (back_edges.snapshot.down && !after.raw[2]) { back_publication = after; back_owned = true; }
            }
        }
    }
    outgoing.restore();
}
void shutdown_hook(Jit& jit, Host&) {
    GrimFramePacing::Quit();
    back_cancel(); back_release_owned();
    quit_request.store(QuitRequest::Retired, std::memory_order_release);
    std::unique_lock lock(qa_game_lock);
    arena_series.stop();
    __android_log_print(ANDROID_LOG_INFO, "GrimCache", "guest shutdown begin: caller=%08x pLuaHS=%08x",
                        jit.Regs()[14], word(base + 0x2bac18));
    qa_slot_invalidate(&qa_commands); clear_reply(false);
    raw_forward(jit, "Main_Shutdown", {jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]});
    qa_forget_after_teardown(&qa_game); qa_menu_dirty = false; qa_last_flags = 0; qa_layout = {}; game_thread = false;
    __android_log_print(ANDROID_LOG_INFO, "GrimCache", "guest shutdown end: pLuaHS=%08x failed=%u",
                        word(base + 0x2bac18), engine->HasFailed() ? 1u : 0u);
}

uint32_t rawglobal(const char* key) { return text_call("lua_rawgetglobal", key); }
void pushtext(const char* key) { text_call("lua_pushstring", key); }
uint32_t tablefield(uint32_t table, const char* key) { call("lua_pushobject", {table}); pushtext(key); return call("lua_rawgettable"); }
uint32_t tableindex(uint32_t table, unsigned index) { call("lua_pushobject", {table}); call("lua_pushnumber", {fbits(float(index))}); return call("lua_rawgettable"); }
bool istable(uint32_t object) { return object && call("lua_istable", {object}); }
const char* tablestring(uint32_t object) { return object && int(call("lua_tag", {object})) == -2 && call("lua_isstring", {object}) ? string32(call("lua_getstring", {object})) : nullptr; }
bool tablenumber(uint32_t object, float& value) {
    if (!object || int(call("lua_tag", {object})) != -1 || !call("lua_isnumber", {object})) return false;
    value = asfloat(call("lua_getnumber", {object})); return true;
}
bool copy_save_title(unsigned index, char output[128]) {
    if (qa_game.helpers_installed && int(call("lua_tag", {rawglobal("GF_Port_QA_original_set_table")})) != -7) return false;
    uint32_t system = rawglobal("system");
    if (!istable(system)) return false;
    float count;
    if (!tablenumber(tablefield(system, "setCount"), count) || !(count > 0 && count <= 256) || float(unsigned(count)) != count || index >= unsigned(count)) return false;
    uint32_t rooms = tablefield(system, "setTable"); if (!istable(rooms)) return false;
    uint32_t room = tableindex(rooms, index); if (!istable(room)) return false;
    float ordinal; if (!tablenumber(tablefield(room, "number"), ordinal) || ordinal != float(index)) return false;
    const char* file = tablestring(tablefield(room, "setFile"));
    if (!file) return false;
    size_t length = strnlen(file, 8); if (length != 6 && length != 7) return false;
    unsigned prefix = unsigned(length - 4); char key[4]{};
    for (unsigned i = 0; i < prefix; ++i) { unsigned char c = file[i]; if (c >= 'A' && c <= 'Z') c += 'a' - 'A'; if (c < 'a' || c > 'z') return false; key[i] = char(c); }
    if (strcmp(file + prefix, ".set")) return false;
    if (key[0] == 'd' && key[1] == 'o' && !key[2]) key[2] = 'm';
    uint32_t descriptions = rawglobal("set_description"); if (!istable(descriptions)) return false;
    uint32_t description = tablefield(descriptions, key); if (!istable(description)) return false;
    const char* id = tablestring(tableindex(description, 1));
    if (!id || strnlen(id, 10) != 9 || memcmp(id, "/sytx", 5) || id[8] != '/') return false;
    unsigned number = 0;
    for (unsigned i = 5; i < 8; ++i) { if (id[i] < '0' || id[i] > '9') return false; number = number * 10 + unsigned(id[i] - '0'); }
    if (number < 424 || number > 540) return false;
    GuestBytes key32(id);
    const char* translated = string32(call("PolyglotGetString", {key32.address}));
    if (!translated || !*translated || !strcmp(translated, id)) return false;
    length = strnlen(translated, 128); if (!length || length == 128) return false;
    memcpy(output, translated, length + 1); return true;
}
void save_title_hook(Jit& jit, Host&) {
    uint32_t raw = jit.Regs()[0];
    if (jit.Regs()[14] != base + 0x7e494) { call("lua_pushstring", {raw}); return; }
    uint32_t index = word(jit.Regs()[5] - 0x104), entry = jit.Regs()[7], key = jit.Regs()[11], state = word(base + 0x2bac30);
    char translated[128]{}; bool found = false;
    if (raw && state && index < 256 && word(state + 188) < 10 && word(state + 32) && word(state + 28) >= word(state + 32) && word(state + 28) <= word(state + 36) && !((word(state + 28) - word(state + 32)) & 15) && word(state + 40) <= (word(state + 28) - word(state + 32)) / 16 && (word(state + 28) - word(state + 32)) / 16 - word(state + 40) == 2 && key == base + 0x279852 && istable(entry)) {
        qb_begin(); found = copy_save_title(index, translated); qb_end();
        call("lua_pushobject", {entry}); call("lua_pushstring", {key});
    }
    if (found) pushtext(translated); else call("lua_pushstring", {raw});
}

bool validate_native(std::string& error) {
    if (!binding("UpdateKey", 0x163dac, error)) return false;
    if (word(base + 0x2a4288) != originals.at("UpdateKey")) { error = "UpdateKey original slot mismatch"; return false; }
    static const unsigned char back_ingress_guard_0[] = {0xf0,0x48,0x2d,0xe9,0x00,0x70,0xa0,0xe1,0x44,0x01,0x9f,0xe5,0x03,0x50,0xa0,0xe1,0x02,0x40,0xa0,0xe1,0x01,0x60,0xa0,0xe1,0x00,0x00,0x9f,0xe7,0x00,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x07,0x00,0xa0,0xe1,0x05,0x00,0x00,0x1a,0x86,0x99,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x07,0x00,0xa0,0xe1,0x01,0x00,0x00,0x0a,0x07,0x00,0xa0,0xe1,0x2a,0xa6,0xfb,0xeb,0x00,0x20,0xa0,0xe1,0x08,0x11,0x9f,0xe5,0x1f,0x2f,0xde,0xe7,0x01,0x01,0x10,0xe3,0x22,0x31,0x00,0xe3,0x03,0x00,0x82,0x10,0x01,0x10,0x8f,0xe0,0x80,0x12,0x81,0xe0,0x04,0x40,0x81,0xe5,0x08,0x20,0xb1,0xe5,0x06,0x00,0x52,0xe1,0x06,0x00,0x00,0x1a,0x00,0x00,0x56,0xe3,0xf0,0x88,0xbd,0x08,0xec,0x10,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x80,0x02,0x81,0xe0,0x10,0x40,0x80,0xe5,0xf0,0x88,0xbd,0xe8,0x01,0x2c,0x47,0xe2,0x22,0x00,0x52,0xe3,0x08,0x00,0x00,0x3a,0x00,0x00,0x56,0xe3,0xb4,0x20,0x9f,0x15,0x02,0x20,0x9f,0x17,0x00,0x20,0x92,0x15,0x00,0x00,0x52,0x13,0x02,0x00,0x00,0x0a,0x07,0x00,0xa0,0xe1,0xf0,0x48,0xbd,0xe8,0xe2,0xa7,0xfb,0xea,0x00,0x00,0x56,0xe3,0x1b,0x00,0x00,0x0a,0x94,0x20,0x9f,0xe5,0x02,0x20,0x8f,0xe0,0x80,0x22,0x82,0xe0,0x10,0x30,0xb2,0xe5,0x03,0x30,0x44,0xe0,0xa3,0x30,0xa0,0xe1,0xe0,0x00,0x53,0xe3,0x04,0x00,0x00,0x8a,0x78,0x30,0x9f,0xe5,0x01,0x70,0xa0,0xe3,0x03,0x30,0x8f,0xe0,0x80,0x32,0x83,0xe0,0x18,0x70,0x83,0xe5,0x68,0x30,0x9f,0xe5,0x00,0x00,0x55,0xe3,0x00,0x60,0x81,0xe5,0x03,0x10,0x8f,0xe0,0x80,0x32,0x81,0xe0,0x0c,0x40,0x83,0xe5,0x14,0x70,0x93,0xe5,0x01,0x70,0x87,0xe2,0x14,0x70,0x83,0xe5,0x80,0x62,0x81,0xe7,0x00,0x00,0xa0,0xe3,0x01,0x00,0x00,0x03,0x00,0x40,0x82,0xe5,0x1c,0x00,0x83,0xe5,0xf0,0x88,0xbd,0xe8,0x20,0x20,0x9f,0xe5,0x00,0x30,0xa0,0xe3,0x00,0x30,0x81,0xe5,0x02,0x10,0x8f,0xe0,0x80,0x02,0x81,0xe0,0x0c,0x40,0x80,0xe5,0xf0,0x88,0xbd,0xe8,0x90,0x2c,0x14,0x00,0x38,0x19,0xdd,0x02,0x04,0x2c,0x14,0x00,0x50,0x18,0xdd,0x02,0xc8,0x18,0xdd,0x02,0xa4,0x18,0xdd,0x02,0x8c,0x18,0xdd,0x02,0x14,0x19,0xdd,0x02};
    if (!preimage(0x163dac, back_ingress_guard_0, sizeof(back_ingress_guard_0), "Complete UpdateKey", error)) return false;
    static const unsigned char back_ingress_guard_1[] = {0x0c,0x20,0x9d,0xe5,0x00,0x30,0xa0,0xe3,0x14,0x10,0xdd,0xe5,0x1c,0x00,0x9d,0xe5,0xd3,0xff,0xfa,0xeb};
    if (!preimage(0x189a34, back_ingress_guard_1, sizeof(back_ingress_guard_1), "Keyboard drain 1", error)) return false;
    static const unsigned char back_ingress_guard_2[] = {0x0c,0x20,0x9d,0xe5,0x00,0x30,0xa0,0xe3,0x14,0x10,0xdd,0xe5,0x1c,0x00,0x9d,0xe5,0x7f,0xff,0xfa,0xeb};
    if (!preimage(0x189b84, back_ingress_guard_2, sizeof(back_ingress_guard_2), "Keyboard drain 2", error)) return false;

    static const unsigned char back_edge_guard_0[] = {0xf0,0x4b,0x2d,0xe9,0x08,0xd0,0x4d,0xe2,0xac,0x08,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x10,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x25,0x02,0x00,0x0a,0x67,0xa8,0xfb,0xeb,0x98,0x08,0x9f,0xe5,0x01,0x20,0xa0,0xe3,0x94,0x18,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x01,0x40,0x8f,0xe0,0x0c,0x20,0x80,0xe5,0xcd,0xae,0xfb,0xeb,0x04,0x00,0x84,0xe5,0x08,0x10,0x94,0xe5,0x01,0x00,0x50,0xe1,0x19,0x02,0x00,0x0a,0x74,0x18,0x9f,0xe5,0x50,0x00,0xc0,0xf2,0x40,0x34,0x04,0xe3,0x00,0x70,0xa0,0xe3,0x01,0x10,0x8f,0xe0,0x40,0x20,0x81,0xe2,0x8f,0x0a,0x42,0xf4,0x34,0x20,0x81,0xe2,0x8f,0x0a,0x42,0xf4,0x24,0x20,0x81,0xe2,0x14,0x10,0x81,0xe2,0x8f,0x0a,0x42,0xf4,0x48,0x28,0x9f,0xe5,0x8f,0x0a,0x41,0xf4,0x00,0x10,0xa0,0xe3,0x02,0x20,0x8f,0xe0,0x07,0x60,0x82,0xe0,0x04,0x00,0x86,0xe5,0x08,0x50,0x96,0xe5,0x07,0x50,0x82,0xe7,0x20,0x70,0x87,0xe2,0x03,0x00,0x57,0xe1,0x14,0x10,0x86,0xe5,0x18,0x10,0x86,0xe5,0xf6,0xff,0xff,0x1a,0x18,0x08,0x9f,0xe5,0x00,0x60,0x8f,0xe0,0x18,0x00,0xd6,0xe4,0x01,0x00,0x50,0xe3,0x79,0x00,0x00,0x1a,0x08,0x08,0x9f,0xe5,0x00,0x40,0xa0,0xe3,0x01,0x5c,0xa0,0xe3,0x00,0x90,0x8f,0xe0,0xfc,0x07,0x9f,0xe5,0x00,0x80,0x9f,0xe7,0xf8,0x07,0x9f,0xe5,0x00,0x70,0x8f,0xe0,0x04,0x01,0x99,0xe7,0x00,0x00,0x50,0xe3,0x04,0x01,0x98,0x17,0x00,0x00,0x50,0x13,0x67,0x00,0x00,0x0a,0x04,0x00,0xa0,0xe1,0x00,0x10,0xa0,0xe3,0x65,0xa4,0xfb,0xeb,0x04,0x00,0x06,0xe5,0x04,0x00,0xa0,0xe1,0x01,0x10,0xa0,0xe3,0x61,0xa4,0xfb,0xeb,0x00,0x00,0x86,0xe5,0x04,0x00,0xa0,0xe1,0x00,0x10,0xa0,0xe3,0xb6,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x05,0x00,0xa0,0xe1,0x00,0x30,0xa0,0xe3,0x94,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x01,0x10,0xa0,0xe3,0xae,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x01,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x8c,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x02,0x10,0xa0,0xe3,0xa6,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x02,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x84,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x03,0x10,0xa0,0xe3,0x9e,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x03,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x7c,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x04,0x10,0xa0,0xe3,0x96,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x04,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x74,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x05,0x10,0xa0,0xe3,0x8e,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x05,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x6c,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x06,0x10,0xa0,0xe3,0x86,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x06,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x64,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x07,0x10,0xa0,0xe3,0x7e,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x07,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x5c,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x08,0x10,0xa0,0xe3,0x76,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x08,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x54,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x09,0x10,0xa0,0xe3,0x6e,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x09,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x4c,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x0a,0x10,0xa0,0xe3,0x66,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x0a,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x44,0x9a,0xfb,0xeb,0x04,0x00,0xa0,0xe1,0x0b,0x10,0xa0,0xe3,0x5e,0xac,0xfb,0xeb,0x04,0x20,0x97,0xe5,0x00,0x10,0xa0,0xe1,0x0b,0x00,0x85,0xe2,0x00,0x30,0xa0,0xe3,0x3c,0x9a,0xfb,0xeb,0x0e,0x50,0x85,0xe2,0x18,0x60,0x86,0xe2,0x01,0x40,0x84,0xe2,0x47,0x0f,0x55,0xe3,0x8d,0xff,0xff,0x1a,0x2c,0x06,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x14,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x78,0x01,0x00,0x0a,0x04,0x00,0x8d,0xe2,0x0d,0x10,0xa0,0xe1,0x85,0xac,0xfb,0xeb,0x04,0x00,0x9d,0xe5,0x00,0x18,0x0a,0xe3,0xfd,0x1f,0x4f,0xe3,0x49,0x36,0x0d,0xe3,0xb9,0x32,0x4f,0xe3,0x00,0x01,0x80,0xe0,0x80,0x03,0x81,0xe0,0xb7,0x10,0x06,0xe3,0x0b,0x16,0x4b,0xe3,0x10,0x01,0x50,0xe7,0x40,0x15,0xa0,0xe1,0xa0,0x0f,0x81,0xe0,0x00,0x10,0x9d,0xe5,0x04,0x00,0x8d,0xe5,0x01,0x12,0x61,0xe0,0x81,0x22,0xa0,0xe1,0x12,0xf3,0x52,0xe7,0xcc,0x35,0x9f,0xe5,0x03,0x40,0x8f,0xe0,0x44,0x30,0x84,0xe2,0x81,0x12,0x82,0xe0,0x41,0x25,0xa0,0xe1,0xa1,0x1f,0x82,0xe0,0x00,0x20,0xa0,0xe3,0x00,0x10,0x8d,0xe5,0x07,0x00,0x83,0xe8,0x01,0x00,0xa0,0xe3,0x58,0xb1,0xfb,0xeb,0x00,0x50,0xa0,0xe1,0xa0,0x05,0x9f,0xe5,0x04,0x60,0x94,0xe5,0x47,0x4f,0xa0,0xe3,0x00,0x00,0x9f,0xe7,0x00,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x05,0x00,0x00,0x1a,0xa2,0x9c,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x02,0x00,0x00,0x0a,0x47,0x0f,0xa0,0xe3,0x47,0xa9,0xfb,0xeb,0x00,0x40,0xa0,0xe1,0x04,0x10,0xa0,0xe1,0x6c,0x05,0x9f,0xe5,0x1f,0x1f,0xde,0xe7,0x01,0x01,0x14,0xe3,0x22,0x21,0x00,0xe3,0x02,0x40,0x81,0x10,0x00,0x00,0x8f,0xe0,0x84,0x02,0x80,0xe0,0x04,0x60,0x80,0xe5,0x08,0x10,0xb0,0xe5,0x05,0x00,0x51,0xe1,0x05,0x00,0x00,0x1a,0x00,0x00,0x55,0xe3,0x50,0x05,0x9f,0x15,0x00,0x00,0x8f,0x10,0x84,0x02,0x80,0x10,0x10,0x60,0x80,0x15,0x21,0x00,0x00,0xea,0x00,0x00,0x55,0xe3,0x19,0x00,0x00,0x0a,0x24,0x15,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x84,0x12,0x81,0xe0,0x10,0x20,0xb1,0xe5,0x02,0x20,0x46,0xe0,0xa2,0x20,0xa0,0xe1,0xe0,0x00,0x52,0xe3,0x04,0x00,0x00,0x8a,0x08,0x25,0x9f,0xe5,0x01,0x30,0xa0,0xe3,0x02,0x20,0x8f,0xe0,0x84,0x22,0x82,0xe0,0x18,0x30,0x82,0xe5,0xf8,0x24,0x9f,0xe5,0x00,0x50,0x80,0xe5,0x02,0x00,0x8f,0xe0,0x84,0x22,0x80,0xe0,0x0c,0x60,0x82,0xe5,0x14,0x30,0x92,0xe5,0x01,0x30,0x83,0xe2,0x14,0x30,0x82,0xe5,0x84,0x52,0x80,0xe7,0x00,0x00,0xa0,0xe3,0x00,0x60,0x81,0xe5,0x1c,0x00,0x82,0xe5,0x05,0x00,0x00,0xea,0xc8,0x14,0x9f,0xe5,0x00,0x20,0xa0,0xe3,0x00,0x20,0x80,0xe5,0x01,0x00,0x8f,0xe0,0x84,0x02,0x80,0xe0,0x0c,0x60,0x80,0xe5,0x02,0x00,0xa0,0xe3,0x14,0xb1,0xfb,0xeb,0x00,0x40,0xa0,0xe1,0xac,0x04,0x9f,0xe5,0xac,0x14,0x9f,0xe5,0x1d,0x51,0x00,0xe3,0x00,0x00,0x9f,0xe7,0x01,0x10,0x8f,0xe0,0x04,0x60,0x91,0xe5,0x00,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x05,0x00,0x00,0x1a,0x5c,0x9c,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x02,0x00,0x00,0x0a,0x1d,0x01,0x00,0xe3,0x01,0xa9,0xfb,0xeb,0x00,0x50,0xa0,0xe1,0x05,0x10,0xa0,0xe1,0x74,0x04,0x9f,0xe5,0x1f,0x1f,0xde,0xe7,0x01,0x01,0x15,0xe3,0x22,0x21,0x00,0xe3,0x02,0x50,0x81,0x10,0x00,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x04,0x60,0x80,0xe5,0x08,0x10,0xb0,0xe5,0x04,0x00,0x51,0xe1,0x05,0x00,0x00,0x1a,0x00,0x00,0x54,0xe3,0x58,0x04,0x9f,0x15,0x00,0x00,0x8f,0x10,0x85,0x02,0x80,0x10,0x10,0x60,0x80,0x15,0x21,0x00,0x00,0xea,0x00,0x00,0x54,0xe3,0x19,0x00,0x00,0x0a,0x2c,0x14,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x85,0x12,0x81,0xe0,0x10,0x20,0xb1,0xe5,0x02,0x20,0x46,0xe0,0xa2,0x20,0xa0,0xe1,0xe0,0x00,0x52,0xe3,0x04,0x00,0x00,0x8a,0x10,0x24,0x9f,0xe5,0x01,0x30,0xa0,0xe3,0x02,0x20,0x8f,0xe0,0x85,0x22,0x82,0xe0,0x18,0x30,0x82,0xe5,0x00,0x24,0x9f,0xe5,0x00,0x40,0x80,0xe5,0x02,0x00,0x8f,0xe0,0x85,0x22,0x80,0xe0,0x0c,0x60,0x82,0xe5,0x14,0x30,0x92,0xe5,0x01,0x30,0x83,0xe2,0x14,0x30,0x82,0xe5,0x85,0x42,0x80,0xe7,0x00,0x00,0xa0,0xe3,0x00,0x60,0x81,0xe5,0x1c,0x00,0x82,0xe5,0x05,0x00,0x00,0xea,0xd0,0x13,0x9f,0xe5,0x00,0x20,0xa0,0xe3,0x00,0x20,0x80,0xe5,0x01,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x0c,0x60,0x80,0xe5,0x03,0x00,0xa0,0xe3,0xce,0xb0,0xfb,0xeb,0x00,0x40,0xa0,0xe1,0xb4,0x03,0x9f,0xe5,0xb4,0x13,0x9f,0xe5,0x1e,0x51,0x00,0xe3,0x00,0x00,0x9f,0xe7,0x01,0x10,0x8f,0xe0,0x04,0x60,0x91,0xe5,0x00,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x05,0x00,0x00,0x1a,0x16,0x9c,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x02,0x00,0x00,0x0a,0x1e,0x01,0x00,0xe3,0xbb,0xa8,0xfb,0xeb,0x00,0x50,0xa0,0xe1,0x05,0x10,0xa0,0xe1,0x7c,0x03,0x9f,0xe5,0x1f,0x1f,0xde,0xe7,0x01,0x01,0x15,0xe3,0x22,0x21,0x00,0xe3,0x02,0x50,0x81,0x10,0x00,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x04,0x60,0x80,0xe5,0x08,0x10,0xb0,0xe5,0x04,0x00,0x51,0xe1,0x05,0x00,0x00,0x1a,0x00,0x00,0x54,0xe3,0x60,0x03,0x9f,0x15,0x00,0x00,0x8f,0x10,0x85,0x02,0x80,0x10,0x10,0x60,0x80,0x15,0x21,0x00,0x00,0xea,0x00,0x00,0x54,0xe3,0x19,0x00,0x00,0x0a,0x34,0x13,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x85,0x12,0x81,0xe0,0x10,0x20,0xb1,0xe5,0x02,0x20,0x46,0xe0,0xa2,0x20,0xa0,0xe1,0xe0,0x00,0x52,0xe3,0x04,0x00,0x00,0x8a,0x18,0x23,0x9f,0xe5,0x01,0x30,0xa0,0xe3,0x02,0x20,0x8f,0xe0,0x85,0x22,0x82,0xe0,0x18,0x30,0x82,0xe5,0x08,0x23,0x9f,0xe5,0x00,0x40,0x80,0xe5,0x02,0x00,0x8f,0xe0,0x85,0x22,0x80,0xe0,0x0c,0x60,0x82,0xe5,0x14,0x30,0x92,0xe5,0x01,0x30,0x83,0xe2,0x14,0x30,0x82,0xe5,0x85,0x42,0x80,0xe7,0x00,0x00,0xa0,0xe3,0x00,0x60,0x81,0xe5,0x1c,0x00,0x82,0xe5,0x05,0x00,0x00,0xea,0xd8,0x12,0x9f,0xe5,0x00,0x20,0xa0,0xe3,0x00,0x20,0x80,0xe5,0x01,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x0c,0x60,0x80,0xe5,0x04,0x00,0xa0,0xe3,0x88,0xb0,0xfb,0xeb,0x00,0x40,0xa0,0xe1,0xbc,0x02,0x9f,0xe5,0xbc,0x12,0x9f,0xe5,0x1f,0x51,0x00,0xe3,0x00,0x00,0x9f,0xe7,0x01,0x10,0x8f,0xe0,0x04,0x60,0x91,0xe5,0x00,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x05,0x00,0x00,0x1a,0xd0,0x9b,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x02,0x00,0x00,0x0a,0x1f,0x01,0x00,0xe3,0x75,0xa8,0xfb,0xeb,0x00,0x50,0xa0,0xe1,0x05,0x10,0xa0,0xe1,0x84,0x02,0x9f,0xe5,0x1f,0x1f,0xde,0xe7,0x01,0x01,0x15,0xe3,0x22,0x21,0x00,0xe3,0x02,0x50,0x81,0x10,0x00,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x04,0x60,0x80,0xe5,0x08,0x10,0xb0,0xe5,0x04,0x00,0x51,0xe1,0x05,0x00,0x00,0x1a,0x00,0x00,0x54,0xe3,0x68,0x02,0x9f,0x15,0x00,0x00,0x8f,0x10,0x85,0x02,0x80,0x10,0x10,0x60,0x80,0x15,0x21,0x00,0x00,0xea,0x00,0x00,0x54,0xe3,0x19,0x00,0x00,0x0a,0x3c,0x12,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x85,0x12,0x81,0xe0,0x10,0x20,0xb1,0xe5,0x02,0x20,0x46,0xe0,0xa2,0x20,0xa0,0xe1,0xe0,0x00,0x52,0xe3,0x04,0x00,0x00,0x8a,0x20,0x22,0x9f,0xe5,0x01,0x30,0xa0,0xe3,0x02,0x20,0x8f,0xe0,0x85,0x22,0x82,0xe0,0x18,0x30,0x82,0xe5,0x10,0x22,0x9f,0xe5,0x00,0x40,0x80,0xe5,0x02,0x00,0x8f,0xe0,0x85,0x22,0x80,0xe0,0x0c,0x60,0x82,0xe5,0x14,0x30,0x92,0xe5,0x01,0x30,0x83,0xe2,0x14,0x30,0x82,0xe5,0x85,0x42,0x80,0xe7,0x00,0x00,0xa0,0xe3,0x00,0x60,0x81,0xe5,0x1c,0x00,0x82,0xe5,0x05,0x00,0x00,0xea,0xe0,0x11,0x9f,0xe5,0x00,0x20,0xa0,0xe3,0x00,0x20,0x80,0xe5,0x01,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x0c,0x60,0x80,0xe5,0x01,0x00,0xa0,0xe3,0x42,0xb0,0xfb,0xeb,0x00,0x40,0xa0,0xe1,0xc4,0x01,0x9f,0xe5,0xc4,0x11,0x9f,0xe5,0x12,0x5e,0xa0,0xe3,0x00,0x00,0x9f,0xe7,0x01,0x10,0x8f,0xe0,0x04,0x60,0x91,0xe5,0x00,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x05,0x00,0x00,0x1a,0x8a,0x9b,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x02,0x00,0x00,0x0a,0x12,0x0e,0xa0,0xe3,0x2f,0xa8,0xfb,0xeb,0x00,0x50,0xa0,0xe1,0x05,0x10,0xa0,0xe1,0x8c,0x01,0x9f,0xe5,0x1f,0x1f,0xde,0xe7,0x01,0x01,0x15,0xe3,0x22,0x21,0x00,0xe3,0x02,0x50,0x81,0x10,0x00,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x04,0x60,0x80,0xe5,0x08,0x10,0xb0,0xe5,0x04,0x00,0x51,0xe1,0x05,0x00,0x00,0x1a,0x00,0x00,0x54,0xe3,0x70,0x01,0x9f,0x15,0x00,0x00,0x8f,0x10,0x85,0x02,0x80,0x10,0x10,0x60,0x80,0x15,0x21,0x00,0x00,0xea,0x00,0x00,0x54,0xe3,0x19,0x00,0x00,0x0a,0x44,0x11,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x85,0x12,0x81,0xe0,0x10,0x20,0xb1,0xe5,0x02,0x20,0x46,0xe0,0xa2,0x20,0xa0,0xe1,0xe0,0x00,0x52,0xe3,0x04,0x00,0x00,0x8a,0x28,0x21,0x9f,0xe5,0x01,0x30,0xa0,0xe3,0x02,0x20,0x8f,0xe0,0x85,0x22,0x82,0xe0,0x18,0x30,0x82,0xe5,0x18,0x21,0x9f,0xe5,0x00,0x40,0x80,0xe5,0x02,0x00,0x8f,0xe0,0x85,0x22,0x80,0xe0,0x0c,0x60,0x82,0xe5,0x14,0x30,0x92,0xe5,0x01,0x30,0x83,0xe2,0x14,0x30,0x82,0xe5,0x85,0x42,0x80,0xe7,0x00,0x00,0xa0,0xe3,0x00,0x60,0x81,0xe5,0x1c,0x00,0x82,0xe5,0x05,0x00,0x00,0xea,0xe8,0x10,0x9f,0xe5,0x00,0x20,0xa0,0xe3,0x00,0x20,0x80,0xe5,0x01,0x00,0x8f,0xe0,0x85,0x02,0x80,0xe0,0x0c,0x60,0x80,0xe5,0xd8,0x00,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x04,0x10,0x90,0xe5,0x08,0x10,0x80,0xe5,0x08,0xd0,0x8d,0xe2,0xf0,0x8b,0xbd,0xe8,0x60,0xbb,0x14,0x00,0x40,0xbb,0x14,0x00,0x4c,0x6d,0xdd,0x02,0x20,0x6d,0xdd,0x02,0xac,0x28,0xdd,0x02,0xc8,0x6c,0xdd,0x02,0x5c,0x28,0xdd,0x02,0x34,0x37,0x14,0x00,0x9c,0x6c,0xdd,0x02,0xbc,0xb8,0x14,0x00,0x68,0x6a,0xdd,0x02,0xfc,0x38,0x14,0x00,0xa8,0x25,0xdd,0x02,0x6c,0x25,0xdd,0x02,0x48,0x25,0xdd,0x02,0x34,0x25,0xdd,0x02,0xfc,0x24,0xdd,0x02,0x88,0x25,0xdd,0x02,0xec,0x37,0x14,0x00,0x1c,0x69,0xdd,0x02,0x90,0x24,0xdd,0x02,0x54,0x24,0xdd,0x02,0x30,0x24,0xdd,0x02,0x1c,0x24,0xdd,0x02,0xe4,0x23,0xdd,0x02,0x70,0x24,0xdd,0x02,0xd4,0x36,0x14,0x00,0x04,0x68,0xdd,0x02,0x78,0x23,0xdd,0x02,0x3c,0x23,0xdd,0x02,0x18,0x23,0xdd,0x02,0x04,0x23,0xdd,0x02,0xcc,0x22,0xdd,0x02,0x58,0x23,0xdd,0x02,0xbc,0x35,0x14,0x00,0xec,0x66,0xdd,0x02,0x60,0x22,0xdd,0x02,0x24,0x22,0xdd,0x02,0x00,0x22,0xdd,0x02,0xec,0x21,0xdd,0x02,0xb4,0x21,0xdd,0x02,0x40,0x22,0xdd,0x02,0xa4,0x34,0x14,0x00,0xd4,0x65,0xdd,0x02,0x48,0x21,0xdd,0x02,0x0c,0x21,0xdd,0x02,0xe8,0x20,0xdd,0x02,0xd4,0x20,0xdd,0x02,0x9c,0x20,0xdd,0x02,0x28,0x21,0xdd,0x02,0xd4,0x64,0xdd,0x02};
    if (!preimage(0x162e0c, back_edge_guard_0, sizeof(back_edge_guard_0), "ReadControls complete", error)) return false;
    static const unsigned char back_edge_guard_1[] = {0x52,0x00,0x00,0x40,0x51,0x00,0x00,0x40,0x50,0x00,0x00,0x40,0x4f,0x00,0x00,0x40,0xe1,0x00,0x00,0x40,0x65,0x00,0x00,0x00,0x75,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x69,0x00,0x00,0x00,0x7f,0x00,0x00,0x00,0x2e,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x7a,0x00,0x00,0x00};
    if (!preimage(0x283310, back_edge_guard_1, sizeof(back_edge_guard_1), "remap outputs", error)) return false;
    {
        const uint32_t va = 0x2f59700; const size_t size = 52;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back edge static context range"; return false;
        }
    }
    {
        const uint32_t va = 0x2b6b38; const size_t size = 16;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back edge static context range"; return false;
        }
    }
    {
        const uint32_t va = 0x2bac30; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back edge static context range"; return false;
        }
    }
    {
        const uint32_t va = 0x16c7d31; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back edge static context range"; return false;
        }
    }

    if (!back_edges_self_check()) { error = "Escape edge fixture failed"; return false; }
    static const unsigned char back_sample_caller[] = {0xf0,0x48,0x2d,0xe9,0x00,0x40,0xa0,0xe1,0x70,0x00,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x08,0x00,0x90,0xe5,0x01,0x00,0x50,0xe3,0xf0,0x88,0xbd,0xb8,0xca,0xa1,0xfe,0xeb,0x5c,0x00,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x08,0x00,0x90,0xe5,0x01,0x00,0x50,0xe3,0x10,0x00,0x00,0xba,0x4c,0x10,0x9f,0xe5,0x00,0x50,0xa0,0xe3,0x01,0x60,0x8f,0xe0,0x44,0x10,0x9f,0xe5,0x01,0x70,0x8f,0xe0,0x05,0x11,0x86,0xe0,0x0c,0x10,0x91,0xe5,0x00,0x00,0x51,0xe3,0x04,0x00,0x00,0x0a,0x04,0x00,0xa0,0xe1,0x31,0xff,0x2f,0xe1,0x00,0x00,0x50,0xe3,0x03,0x00,0x00,0x1a,0x08,0x00,0x97,0xe5,0x01,0x50,0x85,0xe2,0x00,0x00,0x55,0xe1,0xf3,0xff,0xff,0xba,0xf0,0x48,0xbd,0xe8,0x41,0xb8,0xfe,0xea,0x2c,0x06,0x6c,0x01,0x14,0x06,0x6c,0x01,0xfc,0x05,0x6c,0x01,0xf4,0x05,0x6c,0x01};
    if (!preimage(0xa02a0, back_sample_caller, sizeof(back_sample_caller), "ReadControls caller before callbacks", error)) return false;
    if (!binding("stdControl_ReadControls", 0x162e0c, error) || word(base + 0x2a3d50) != originals.at("stdControl_ReadControls")) {
        if (error.empty()) error = "ReadControls original GOT mismatch"; return false;
    }
    bool writable = false;
    for (const auto& segment : image->GetSegments())
        writable |= (segment.flags & (PF_R | PF_W)) == (PF_R | PF_W) && 0x2f35aa8 >= segment.vaddr && uint64_t(0x2f35aac) <= uint64_t(segment.vaddr) + segment.memsz;
    if (!writable) { error = "Escape sampled field not writable"; return false; }

    static const unsigned char back_guard_0[] = {0xac,0x08,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x10,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x25,0x02,0x00,0x0a,0x67,0xa8,0xfb,0xeb,0x98,0x08,0x9f,0xe5,0x01,0x20,0xa0,0xe3,0x94,0x18,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x01,0x40,0x8f,0xe0,0x0c,0x20,0x80,0xe5,0xcd,0xae,0xfb,0xeb,0x04,0x00,0x84,0xe5,0x08,0x10,0x94,0xe5,0x01,0x00,0x50,0xe1,0x19,0x02,0x00,0x0a};
    if (!preimage(0x162e14, back_guard_0, sizeof(back_guard_0), "back ReadControls_gate_and_epoch", error)) return false;
    static const unsigned char back_guard_1[] = {0x07,0x60,0x82,0xe0,0x04,0x00,0x86,0xe5,0x08,0x50,0x96,0xe5,0x07,0x50,0x82,0xe7,0x20,0x70,0x87,0xe2,0x03,0x00,0x57,0xe1,0x14,0x10,0x86,0xe5,0x18,0x10,0x86,0xe5,0xf6,0xff,0xff,0x1a};
    if (!preimage(0x162e98, back_guard_1, sizeof(back_guard_1), "back ReadControls_escape_snapshot_reset", error)) return false;
    static const unsigned char back_guard_2[] = {0x2c,0x06,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x14,0x00,0x90,0xe5,0x00,0x00,0x50,0xe3,0x78,0x01,0x00,0x0a,0x04,0x00,0x8d,0xe2,0x0d,0x10,0xa0,0xe1,0x85,0xac,0xfb,0xeb};
    if (!preimage(0x1630b8, back_guard_2, sizeof(back_guard_2), "back ReadControls_mouse_call", error)) return false;
    static const unsigned char back_guard_3[] = {0xd8,0x00,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x04,0x10,0x90,0xe5,0x08,0x10,0x80,0xe5};
    if (!preimage(0x1636b0, back_guard_3, sizeof(back_guard_3), "back ReadControls_previous_epoch_commit", error)) return false;
    static const unsigned char back_guard_4[] = {0x60,0xbb,0x14,0x00,0x40,0xbb,0x14,0x00,0x4c,0x6d,0xdd,0x02,0x20,0x6d,0xdd,0x02,0xac,0x28,0xdd,0x02,0xc8,0x6c,0xdd,0x02,0x5c,0x28,0xdd,0x02,0x34,0x37,0x14,0x00,0x9c,0x6c,0xdd,0x02,0xbc,0xb8,0x14,0x00};
    if (!preimage(0x1636c8, back_guard_4, sizeof(back_guard_4), "back ReadControls_literals", error)) return false;
    static const unsigned char back_guard_5[] = {0xd4,0x64,0xdd,0x02};
    if (!preimage(0x163790, back_guard_5, sizeof(back_guard_5), "back ReadControls_epoch_end_literal", error)) return false;
    static const unsigned char back_guard_6[] = {0x30,0x48,0x2d,0xe9,0x24,0xc1,0x9f,0xe5,0x00,0xe0,0xa0,0xe1,0x1f,0xef,0xde,0xe7,0x01,0x01,0x10,0xe3,0x0c,0xc0,0x8f,0xe0,0x22,0x41,0x00,0xe3,0x04,0x00,0x8e,0x10,0x10,0x50,0x9c,0xe5,0x00,0x00,0x55,0xe3,0x34,0x00,0x00,0x0a,0x08,0x50,0x9c,0xe5,0x00,0x00,0x55,0xe3,0x31,0x00,0x00,0x1a,0xf4,0x50,0x9f,0xe5,0x05,0x50,0x8f,0xe0,0x0c,0x50,0x95,0xe5,0x00,0x00,0x55,0xe3,0x07,0x00,0x00,0x0a,0xe4,0x50,0x9f,0xe5,0x05,0x50,0x8f,0xe0,0x80,0x52,0x95,0xe7,0x00,0x00,0x55,0xe3,0xd8,0x50,0x9f,0x15,0x00,0x40,0xa0,0x13,0x05,0x50,0x8f,0x10,0x0c,0x40,0x85,0x15};
    if (!preimage(0x163ab8, back_guard_6, sizeof(back_guard_6), "back ReadKey_active_disable_idle", error)) return false;
    static const unsigned char back_guard_7[] = {0xac,0xae,0x14,0x00,0x84,0xae,0x14,0x00,0x38,0x1c,0xdd,0x02,0x5c,0xae,0x14,0x00};
    if (!preimage(0x163be8, back_guard_7, sizeof(back_guard_7), "back ReadKey_gate_literals", error)) return false;
    static const unsigned char back_guard_8[] = {0x01,0x10,0x8f,0xe0,0x80,0x12,0x81,0xe0,0x04,0x40,0x81,0xe5,0x08,0x20,0xb1,0xe5,0x06,0x00,0x52,0xe1,0x06,0x00,0x00,0x1a,0x00,0x00,0x56,0xe3,0xf0,0x88,0xbd,0x08,0xec,0x10,0x9f,0xe5,0x01,0x10,0x8f,0xe0,0x80,0x02,0x81,0xe0,0x10,0x40,0x80,0xe5,0xf0,0x88,0xbd,0xe8,0x01,0x2c,0x47,0xe2,0x22,0x00,0x52,0xe3,0x08,0x00,0x00,0x3a,0x00,0x00,0x56,0xe3,0xb4,0x20,0x9f,0x15,0x02,0x20,0x9f,0x17,0x00,0x20,0x92,0x15,0x00,0x00,0x52,0x13,0x02,0x00,0x00,0x0a,0x07,0x00,0xa0,0xe1,0xf0,0x48,0xbd,0xe8,0xe2,0xa7,0xfb,0xea,0x00,0x00,0x56,0xe3,0x1b,0x00,0x00,0x0a,0x94,0x20,0x9f,0xe5,0x02,0x20,0x8f,0xe0,0x80,0x22,0x82,0xe0,0x10,0x30,0xb2,0xe5,0x03,0x30,0x44,0xe0,0xa3,0x30,0xa0,0xe1,0xe0,0x00,0x53,0xe3,0x04,0x00,0x00,0x8a,0x78,0x30,0x9f,0xe5,0x01,0x70,0xa0,0xe3,0x03,0x30,0x8f,0xe0,0x80,0x32,0x83,0xe0,0x18,0x70,0x83,0xe5,0x68,0x30,0x9f,0xe5,0x00,0x00,0x55,0xe3,0x00,0x60,0x81,0xe5,0x03,0x10,0x8f,0xe0,0x80,0x32,0x81,0xe0,0x0c,0x40,0x83,0xe5,0x14,0x70,0x93,0xe5,0x01,0x70,0x87,0xe2,0x14,0x70,0x83,0xe5,0x80,0x62,0x81,0xe7,0x00,0x00,0xa0,0xe3,0x01,0x00,0x00,0x03,0x00,0x40,0x82,0xe5,0x1c,0x00,0x83,0xe5,0xf0,0x88,0xbd,0xe8,0x20,0x20,0x9f,0xe5,0x00,0x30,0xa0,0xe3,0x00,0x30,0x81,0xe5,0x02,0x10,0x8f,0xe0,0x80,0x02,0x81,0xe0,0x0c,0x40,0x80,0xe5,0xf0,0x88,0xbd,0xe8,0x90,0x2c,0x14,0x00,0x38,0x19,0xdd,0x02,0x04,0x2c,0x14,0x00,0x50,0x18,0xdd,0x02,0xc8,0x18,0xdd,0x02,0xa4,0x18,0xdd,0x02,0x8c,0x18,0xdd,0x02};
    if (!preimage(0x163e08, back_guard_8, sizeof(back_guard_8), "back UpdateKey_record_and_down_up", error)) return false;
    static const unsigned char back_guard_9[] = {0x09,0x00,0xa0,0xe1,0x00,0x10,0xe0,0xe3,0x08,0x80,0x8f,0xe0,0x06,0x30,0x88,0xe0,0x06,0x40,0xc3,0xe5,0x64,0x42,0xf9,0xeb,0x01,0x00,0x50,0xe3,0xc0,0xff,0xff,0x1a,0x82,0x20,0x86,0xe2,0x00,0x30,0x98,0xe5,0x0c,0x40,0xcd,0xe5,0x0d,0x00,0xa0,0xe1,0x02,0x21,0x98,0xe7,0x00,0x00,0x53,0xe3,0x0d,0xa0,0xcd,0xe5,0x10,0x60,0x8d,0xe5,0x14,0x20,0x8d,0xe5,0xb8,0x71,0xcd,0xe1,0x04,0x30,0x93,0x15,0x00,0x90,0x8d,0xe5,0x08,0x30,0x8d,0xe5,0x62,0x56,0xf9,0xeb,0x00,0x00,0x50,0xe3,0x00,0x00,0xa0,0xd3};
    if (!preimage(0x1fa070, back_guard_9, sizeof(back_guard_9), "back SDL_escape_live_write_event_query", error)) return false;
    static const unsigned char back_guard_10[] = {0xd8,0x68,0xd7,0x02};
    if (!preimage(0x1fa248, back_guard_10, sizeof(back_guard_10), "back SDL_keyboard_literal", error)) return false;
    static const unsigned char back_guard_11[] = {0xf8,0x40,0x2d,0xe9,0x50,0x64,0xe7,0xe7,0xe0,0x30,0x9f,0xe5,0x00,0x50,0xa0,0xe1,0x06,0x61,0xa0,0xe1,0x70,0x40,0xef,0xe6,0x03,0x30,0x8f,0xe0,0x06,0x30,0x83,0xe0,0x08,0x30,0x93,0xe5,0x00,0x00,0x53,0xe3,0x22,0x00,0x00,0x0a,0xa4,0x02,0xa0,0xe1,0x1f,0xc0,0x04,0xe2,0x01,0x20,0xa0,0xe3,0x00,0x01,0x93,0xe7,0x12,0x0c,0x10,0xe0,0x00,0x20,0xa0,0x13,0x02,0x70,0xa0,0x11,0x0c,0x00,0x00,0x0a,0x02,0x00,0x51,0xe1,0x08,0x00,0x00,0x0a,0x00,0x00,0x51,0xe3,0x0a,0x00,0x00,0x0a,0x01,0x00,0x51,0xe3,0x04,0x00,0x00,0x1a,0xa4,0x22,0xa0,0xe1,0x1f,0x40,0x04,0xe2,0x02,0x01,0x93,0xe7,0x11,0x14,0xc0,0xe1,0x02,0x11,0x83,0xe7,0x07,0x00,0xa0,0xe1,0xf8,0x80,0xbd,0xe8,0x02,0x70,0xa0,0xe1,0xf0,0xff,0xff,0xea,0x00,0x00,0x53,0xe3};
    if (!preimage(0x1f835c, back_guard_11, sizeof(back_guard_11), "back SDL_event_disabled_bits", error)) return false;
    static const unsigned char back_guard_12[] = {0xc4,0x81,0xd7,0x02};
    if (!preimage(0x1f844c, back_guard_12, sizeof(back_guard_12), "back SDL_event_disabled_table_literal", error)) return false;
    static const unsigned char back_guard_13[] = {0x01,0x10,0x8f,0xe0,0x08,0x20,0x81,0xe5,0x00,0x10,0xa0,0xe3,0x00,0x00,0x90,0xe5,0xed,0xe1,0xff,0xeb};
    if (!preimage(0x51290, back_guard_13, sizeof(back_guard_13), "back Main_Service_update_call", error)) return false;
    static const unsigned char back_guard_14[] = {0x95,0x04,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x00,0x00,0x00,0x1a,0x7d,0xfb,0xfa,0xeb,0x08,0x00,0x94,0xe5};
    if (!preimage(0x18982c, back_guard_14, sizeof(back_guard_14), "back startup_event_service_order", error)) return false;
    static const unsigned char back_guard_15[] = {0x00,0x48,0x2d,0xe9,0x39,0x04,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x00,0x00,0x00,0x1a,0x21,0xfb,0xfa,0xeb,0x00,0x00,0xa0,0xe3,0x00,0x88,0xbd,0xe8};
    if (!preimage(0x189998, back_guard_15, sizeof(back_guard_15), "back AppUpdate_event_service_order", error)) return false;
    static const unsigned char back_guard_16[] = {0x00,0x48,0x2d,0xe9,0x45,0x03,0xfb,0xeb,0x00,0x00,0x50,0xe3,0x00,0x00,0x00,0x1a,0x2d,0xfa,0xfa,0xeb,0x14,0x00,0x9f,0xe5,0x00,0x00,0x8f,0xe0};
    if (!preimage(0x189d68, back_guard_16, sizeof(back_guard_16), "back SDLCallback_service", error)) return false;
    {
        const uint32_t va = 0x2f70987; const size_t size = 1;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: SDL.live_escape"; return false;
        }
    }
    {
        const uint32_t va = 0x2f70c04; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: SDL.keymap41"; return false;
        }
    }
    {
        const uint32_t va = 0x2f70554; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: SDL.event_page3_ptr"; return false;
        }
    }
    {
        const uint32_t va = 0x2f35aa8; const size_t size = 32;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: stdControl.escape"; return false;
        }
    }
    {
        const uint32_t va = 0x2f39b94; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: stdControl.epoch_current"; return false;
        }
    }
    {
        const uint32_t va = 0x2f39b98; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: stdControl.epoch_previous"; return false;
        }
    }
    {
        const uint32_t va = 0x2ae980; const size_t size = 20;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: stdControl.gates"; return false;
        }
    }
    {
        const uint32_t va = 0x2b6b38; const size_t size = 16;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: sputControl.escape_entry"; return false;
        }
    }
    {
        const uint32_t va = 0x2b7568; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: sputControl.symbol_count"; return false;
        }
    }
    {
        const uint32_t va = 0x2a86a8; const size_t size = 4;
        bool readable = false;
        for (const auto& segment : image->GetSegments())
            readable |= (segment.flags & PF_R) && va >= segment.vaddr && uint64_t(va) + size <= uint64_t(segment.vaddr) + segment.memsz;
        if (!readable || uint64_t(base) + va + size > UINT32_MAX || uint64_t(base) + va + size > engine->GetGuestMemorySize()) {
            error = "Back static field range: sputControl.mapping_mode"; return false;
        }
    }
    back_ranges_ready = true;
    static const unsigned char resource_ceiling[] = {0x00,0x00,0x80,0x01};
    if (!preimage(0x2a7b80, resource_ceiling, sizeof(resource_ceiling), "resource cache ceiling", error)) return false;
    for (const auto& g : grim_quit_guards)
        if (!preimage(g.va, g.bytes, g.size, g.name, error)) return false;
    if (!native_span(0x2f59458, 1) || !native_span(0x2f59454, 4)) {
        error = "Grim quit state globals out of range"; return false;
    }
    for (const auto& g : ms_preimages) if (!preimage(uint32_t(g.va), g.bytes, g.size, "mouse", error)) return false;
    for (const auto& g : qo_preimages) if (!preimage(uint32_t(g.va), g.bytes, g.size, "QA overlay", error)) return false;
    for (const auto& g : qa_export_contracts) {
        if (!binding(g.name, uint32_t(g.va), error)) return false;
        if (g.preimage_size && !preimage(uint32_t(g.va), g.bytes, g.preimage_size, g.name, error)) return false;
    }
    for (const auto& g : qa_ui_contracts)
        if (!binding(g.name, uint32_t(g.va), error) || !preimage(uint32_t(g.va), g.bytes, g.size, g.name, error)) return false;
    for (const auto& g : save_title_guards) if (!preimage(uint32_t(g.va), g.bytes, g.length, g.name, error)) return false;
    for (const auto& g : vsg_guards) if (!preimage(uint32_t(g.va), g.bytes, g.length, g.name, error)) return false;
    for (const auto& g : dsn_shutdown_guards) if (!preimage(uint32_t(g.va), g.bytes, g.length, g.name, error)) return false;
    for (const auto& g : shared_audio_guards) if (!preimage(uint32_t(g.va), g.bytes, g.length, g.name, error)) return false;
    for (const auto& g : sp_upload_guards)
        if (!binding(g.name, uint32_t(g.va), error) || !preimage(uint32_t(g.va), g.bytes, g.size, g.name, error)) return false;
    for (const auto& g : sp_orphan_guards)
        if (!binding(g.name, uint32_t(g.va), error) || !preimage(uint32_t(g.va), g.bytes, g.size, g.name, error)) return false;
    for (const auto& g : texture_bulk_guards) {
        if (g.name && !binding(g.name, g.va, error)) return false;
        if (!preimage(g.va, g.bytes, g.size, g.label, error)) return false;
    }
    for (const auto& g : whole_zero_guards) {
        if (g.name && !binding(g.name, uint32_t(g.va), error)) return false;
        if (!preimage(uint32_t(g.va), g.bytes, g.size, g.label, error)) return false;
    }
    static const unsigned char alpha[] = {0x14,0x00,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x04,0x10,0x90,0xe4,0x06,0x00,0x51,0xe3,0x01,0x01,0x80,0xb0,0x00,0x00,0x90,0xe5,0x1e,0xff,0x2f,0xe1,0x04,0x8e,0x14,0x00};
    static const unsigned char sayline[] = {0x3c,0x8e,0xfe,0xeb,0x00,0x10,0xd0,0xe5,0x2c,0x10,0xcd,0xe5,0x08,0x10,0x8d,0xe2,0x01,0x00,0xd0,0xe5,0x2d,0x00,0xcd,0xe5,0x5f,0x00,0xa0,0xe3,0x2e,0x00,0xcd,0xe5};
    if (!preimage(0x16dc60, alpha, sizeof(alpha), "voice Alpha2", error) || !preimage(0xa8a74, sayline, sizeof(sayline), "voice SayLine", error)) return false;
    if (!preimage(0x48dd0, sp_upload_plt, sizeof(sp_upload_plt), "SubData PLT", error) || !preimage(0x48db8, sp_orphan_plt, sizeof(sp_orphan_plt), "BufferData PLT", error)) return false;
    static const unsigned char fps_registry_preimage[] = {
        0x70,0x40,0x2d,0xe9,0x00,0x00,0xa0,0xe3,0x1c,0x13,0x04,0xe3,0x00,0x60,0xa0,0xe3,
        0x77,0x81,0xfb,0xeb,0x00,0x40,0xa0,0xe1,0x80,0x10,0x9f,0xe5,0x08,0x03,0x04,0xe3,
        0x02,0x20,0xa0,0xe3,0x04,0x50,0xa0,0xe1,0x01,0x10,0x8f,0xe0,0x00,0x20,0x85,0xe6,
        0x04,0x00,0x84,0xe2,0x43,0x2c,0xa0,0xe3,0x43,0x84,0xfb,0xeb,0x60,0x00,0x9f,0xe5,
        0x04,0x23,0x04,0xe3,0x5c,0x10,0x9f,0xe5,0x00,0x00,0x8f,0xe0,0x09,0x00,0x90,0xe8,
        0x02,0x00,0x84,0xe7,0x01,0x00,0x8f,0xe0,0x04,0x00,0x80,0xe2,0x00,0x30,0x85,0xe5,
        0x0c,0x13,0x04,0xe3,0x8f,0x0a,0x60,0xf4,0x01,0x00,0x84,0xe0,0x1c,0x13,0x04,0xe3,
        0x01,0x20,0xa0,0xe3,0x0f,0x0a,0x40,0xf4,0x04,0x00,0xa0,0xe1,0xc8,0x84,0xfb,0xeb,
        0x00,0x50,0xa0,0xe1,0x00,0x00,0x55,0xe3,0x1c,0x00,0x9f,0x05,0x00,0x60,0xcf,0x07,
        0x04,0x00,0xa0,0xe1,0x3e,0x7a,0xfb,0xeb,0x05,0x00,0xa0,0xe1,0x70,0x80,0xbd,0xe8,
        0x64,0x64,0xde,0x02,0x44,0xa7,0xde,0x02,0x48,0xa7,0xde,0x02,0x10,0xa7,0xde,0x02
    };
    if (!preimage(0x16d90c, fps_registry_preimage, sizeof(fps_registry_preimage), "FPS registry commit", error)) return false;
    static const unsigned char language_preimage[] = {0x04,0x10,0x9f,0xe5,0x01,0x00,0x8f,0xe7,0x1e,0xff,0x2f,0xe1,0x24,0x8e,0x14,0x00};
    if (!preimage(0x16dc40,language_preimage,sizeof(language_preimage),"language carrier",error)) return false;
    struct Named { const char* name; uint32_t va; };
    static const Named functions[] = {
        {"wuRegistry_SaveRegistry",0x16d90c},
        {"zg_GetLanguage",0}, {"zg_SetLanguage",0x16dc40}, {"zg_GetLanguageAlpha2",0x16dc60}, {"_externalFileDir",0x2f76fc4}, {"pLuaHS",0x2bac18},
        {"Java_org_libsdl_app_SDLActivity_onNativeTouch",0x1f4a94}, {"SDL_SendMouseButton",0x1fb508}, {"SDL_SendMouseMotion",0x1fb1d4},
        {"zg_Input_GetMousePosition",0x18c390}, {"zg_Input_GetMouseButton",0x18c3a4}, {"SDL_GetMouseState",0x1faccc}, {"SDL_ResetMouse",0x1fb7c0}, {"SDL_GetWindowSize",0x207334}, {"Android_Window",0x2f71c20},
        {"SDL_HasEvent",0x1f7de8}, {"SDL_SendQuit",0x1fbb98}, {"zg_App_bDone",0x2f59454},
        {"stdDisplay_TextOut",0x164f78}, {"std_genBuffer",0x306c5cc},
        {"lua_rawgetglobal",0x5294c}, {"lua_rawgettable",0x52658}, {"lua_istable",0x52a60}, {"lua_tag",0x52b84}, {"lua_isnumber",0x52c28},
        {"lua_pushobject",0x533e4}, {"lua_pushnumber",0x53184}, {"lua_getnumber",0x52e20}, {"lua_pushstring",0x53214}, {"PolyglotGetString",0x70294},
        {"zg_Thread_DestroyAndWait",0x193a38}, {"zg_Audio_ProducePost",0x18afa8}, {"dsn_fill_thread",0x15b200},
        {"zg_Audio_Shutdown",0x18a9a8}, {"SDL_CloseAudioDevice",0x1d16ec}, {"zg_PostSemaphore",0x18cb2c},
        {"stdPlatform_InitServices",0x16c49c}, {"daRealloc",0x16a6c8}, {"iRes_FREAD",0xd1418}, {"SoundsInitialize",0xcf7a4},
        {"_Z27zg_Video_GetVideoDurationMSPKc",0}, {"_Z13uploadTextureP9zgSurfacePvjjjS1_jjj",0},
        {"zg_RenderContext_Get",0}, {"zg_Surface_Lock",0}, {"zg_Surface_Unlock",0},
        {"glBufferData",0}, {"glBufferSubData",0}, {"__aeabi_memcpy",0}, {"__aeabi_memclr",0},
        {"fopen",0}, {"stat",0}, {"opendir",0}, {"readdir",0}, {"closedir",0}
    };
    for (const auto& f : functions) if (!binding(f.name, f.va, error)) return false;
    if (!preimage(originals.at("_Z27zg_Video_GetVideoDurationMSPKc") - base, video_duration_preimage, sizeof(video_duration_preimage), "video duration", error)) return false;
    struct Slot { uint32_t va; const char* name; };
    static const Slot slots[] = {{0x2a4500,"wuRegistry_SaveRegistry"},{0x2a6808,"daRealloc"},{0x2a7c18,"SoundsInitialize"},{0x2a3e9c,"glBufferSubData"},{0x2a3e94,"glBufferData"},{0x2a3fbc,"_Z13uploadTextureP9zgSurfacePvjjjS1_jjj"},{0x2a625c,"zg_RenderContext_Get"},{0x2a4e40,"zg_Surface_Lock"},{0x2a4bb8,"zg_Surface_Unlock"},{0x2a5d70,"__aeabi_memcpy"},{0x2a4508,"__aeabi_memclr"}};
    for (const auto& s : slots) if (word(base + s.va) != originals.at(s.name)) { error = std::string("Grim original GOT mismatch: ") + s.name; return false; }
    for (const auto& s : whole_zero_bindings)
        if (!binding(s.name, uint32_t(s.va), error) || word(base + uint32_t(s.got)) != originals.at(s.name)) { if (error.empty()) error = std::string("Grim allocation binding mismatch: ") + s.name; return false; }
    if (word(base + 0x2a8078) != base + 0x278ca8 || word(base + 0x2a807c) != base + 0x7e3a0) { error = "Grim FindSaveGames registration mismatch"; return false; }
    return true;
}

struct Hook { const char* name; ThunkHandler callback; uint32_t slot = 0, thunk = 0; };
bool locate_hooks(std::vector<Hook>& hooks, std::string& error) {
    const auto* header = static_cast<const Elf32_Ehdr*>(span(base, sizeof(Elf32_Ehdr)));
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) || header->e_ident[EI_CLASS] != ELFCLASS32 || header->e_machine != EM_ARM || header->e_phentsize != sizeof(Elf32_Phdr) || header->e_phnum > 32) { error = "Grim guest ELF32 header mismatch"; return false; }
    if (!native_span(header->e_phoff, size_t(header->e_phnum) * sizeof(Elf32_Phdr))) { error = "Grim guest program headers out of range"; return false; }
    const auto* ph = static_cast<const Elf32_Phdr*>(span(base + header->e_phoff, size_t(header->e_phnum) * sizeof(Elf32_Phdr)));
    uint32_t dyn = 0, dynbytes = 0;
    for (unsigned i = 0; i < header->e_phnum; ++i) if (ph[i].p_type == PT_DYNAMIC) { dyn = ph[i].p_vaddr; dynbytes = ph[i].p_memsz; }
    if (!dyn || !native_span(dyn, dynbytes)) { error = "Grim guest dynamic table missing"; return false; }
    uint32_t sym = 0, str = 0, rel = 0, relbytes = 0, strbytes = 0;
    const auto* table = static_cast<const Elf32_Dyn*>(span(base + dyn, dynbytes));
    for (unsigned i = 0; i < dynbytes / sizeof(Elf32_Dyn) && table[i].d_tag != DT_NULL; ++i) {
        switch (table[i].d_tag) { case DT_SYMTAB: sym = table[i].d_un.d_ptr; break; case DT_STRTAB: str = table[i].d_un.d_ptr; break; case DT_STRSZ: strbytes = table[i].d_un.d_val; break; case DT_JMPREL: rel = table[i].d_un.d_ptr; break; case DT_PLTRELSZ: relbytes = table[i].d_un.d_val; break; }
    }
    if (!sym || !str || !rel || !strbytes || relbytes % sizeof(Elf32_Rel) || !native_span(rel, relbytes) || !native_span(str, strbytes)) { error = "Grim guest relocation table mismatch"; return false; }
    const auto* rows = static_cast<const Elf32_Rel*>(span(base + rel, relbytes));
    for (unsigned i = 0; i < relbytes / sizeof(Elf32_Rel); ++i) {
        if (ELF32_R_TYPE(rows[i].r_info) != R_ARM_JUMP_SLOT) continue;
        uint64_t sva = uint64_t(sym) + uint64_t(ELF32_R_SYM(rows[i].r_info)) * sizeof(Elf32_Sym);
        if (sva > UINT32_MAX || !native_span(uint32_t(sva), sizeof(Elf32_Sym))) { error = "Grim guest symbol out of range"; return false; }
        const auto* s = static_cast<const Elf32_Sym*>(span(base + uint32_t(sva), sizeof(Elf32_Sym)));
        if (s->st_name >= strbytes) { error = "Grim guest symbol name out of range"; return false; }
        const char* name = string32(base + str + s->st_name, strbytes - s->st_name);
        for (auto& h : hooks) if (!strcmp(name, h.name)) {
            if (h.slot || !native_span(rows[i].r_offset, 4) || word(base + rows[i].r_offset) != originals.at(h.name)) { error = std::string("Grim guest hook count/binding mismatch: ") + h.name; return false; }
            h.slot = base + rows[i].r_offset;
        }
    }
    for (const auto& h : hooks) if (!h.slot) { error = std::string("Grim guest hook absent: ") + h.name; return false; }
    return true;
}
} // namespace

void GrimHooksCancelBackSample() { back_cancel(); }
bool GrimHooksBeginQuit() {
    QuitRequest expected = QuitRequest::Idle;
    const bool admitted = quit_request.compare_exchange_strong(expected, QuitRequest::Submitting,
        std::memory_order_acq_rel, std::memory_order_acquire);
    if (admitted)
        __android_log_print(ANDROID_LOG_INFO, "GrimCache",
            "guest quit latch: phase=submitting ready=%u done=%u self=%llx",
            unsigned(byte(base + 0x2f59458)), word(base + 0x2f59454),
            static_cast<unsigned long long>(pthread_self()));
    return admitted;
}
void GrimHooksCommitQuit() {
    QuitRequest expected = QuitRequest::Submitting;
    quit_request.compare_exchange_strong(expected, QuitRequest::Pending,
        std::memory_order_release, std::memory_order_relaxed);
}
int GrimGuestLanguage() {
    Host* host = GetGrimHost();
    if (!host) return 0;
    uint32_t target = host->FindLibrarySymbol("libGrimFandango.so", "zg_GetLanguage");
    return target ? int(host->CallGuestNested(target)) : 0;
}
std::string GrimGuestExternalRoot() {
    Host* host = GetGrimHost();
    if (!host) return {};
    uint32_t address = host->FindLibrarySymbol("libGrimFandango.so", "_externalFileDir");
    ElfLoader* module = host->FindModule("libGrimFandango.so");
    if (!module || address != module->GetBaseAddress() + 0x2f76fc4 || uint64_t(address) + 260 > host->GetGuestMemorySize()) return {};
    const char* text = reinterpret_cast<const char*>(host->GetGuestMemoryBase() + address);
    size_t size = strnlen(text, 260);
    return size < 260 ? std::string(text, size) : std::string();
}
void GrimSelectVideoEntry(const GrimCacheEntry* entry) {
    std::lock_guard lock(video_lock);
    video_valid = entry != nullptr;
    selected_video = entry ? *entry : GrimCacheEntry{};
}
bool InstallGrimHooks(Host& host, std::string& error) {
    std::lock_guard lock(bind_lock);
    if (installed) { if (engine == &host) return true; error = "Grim hooks already bound to another guest"; return false; }
    image = host.FindModule("libGrimFandango.so");
    if (!image) { error = "Grim engine guest module absent"; return false; }
    engine = &host; base = image->GetBaseAddress();
    if (!validate_native(error) || !timer_retirement_validate(error) || !save_compression_validate(error)) return false;
    std::vector<Hook> hooks = {
        {"compress",save_compression_hook},
        {"fopen",fopen_hook},{"stat",stat_hook},{"opendir",opendir_hook},{"readdir",readdir_hook},{"closedir",closedir_hook},
        {"zg_GetLanguageAlpha2",voice_hook},{"zg_SetLanguage",language_hook},{"zg_Input_GetMousePosition",mouse_position_hook},{"zg_Input_GetMouseButton",mouse_button_hook},
        {"UpdateKey",update_key_hook},{"stdControl_ReadControls",read_controls_hook},{"stdDisplay_TextOut",overlay_hook},{"Main_Service",service_hook},{"grimlib_UpdateManual",update_hook},{"Main_Shutdown",shutdown_hook},
        {"lua_pushstring",save_title_hook},{"zg_Thread_DestroyAndWait",dsn_join_hook},{"zg_Audio_Shutdown",shared_shutdown_hook},{"stdPlatform_InitServices",services_hook},
        {"_Z27zg_Video_GetVideoDurationMSPKc",duration_hook},{"glBufferSubData",orphan_hook},{"_Z13uploadTextureP9zgSurfacePvjjjS1_jjj",texture_hook},{"__aeabi_memclr",zero_hook}
    };
    // Resolve every exact slot before modifying a single guest binding.
    if (!locate_hooks(hooks, error)) return false;
    english = host.GuestAlloc(3); if (!english) { error = "Grim voice fallback allocation failed"; return false; }
    memcpy(span(english, 3), "en", 3);
    ms_init(&mouse); tp_init(&pointers);
    { std::lock_guard lock(back_lock); ms_init(&back_edges); back_seeded = back_owned = false; ++back_input_generation; }
    qa_game.api = {qb_begin,qb_end,qb_global,qb_function,qb_string,qb_getstring,qb_call,qb_execute,
        static_cast<uint32_t*>(span(originals.at("L"),4)),static_cast<uint32_t*>(span(originals.at("L_Main"),4)),
        static_cast<int*>(span(originals.at("g_ZG_ANDROID_HAX_LUA_REQ_EXIT"),4)),static_cast<int*>(span(originals.at("bDrawFrameRate"),4)),static_cast<int*>(span(originals.at("bDrawPerfData"),4))};
    if (qa_slot_init(&qa_commands)) { host.GuestFree(english); english = 0; error = "Grim QA command mutex unavailable"; return false; }
    auto& manager = host.GetThunkManager();
    scratch_thunk = manager.RegisterThunk("grim_vima_scratch_realloc", scratch_hook);
    const uint32_t timer_retire_thunk = manager.RegisterThunk("grim_timer_retirement", timer_retirement_hook);
    for (auto& h : hooks) h.thunk = manager.RegisterThunk(std::string("grim_") + h.name, h.callback);
    for (const auto& h : hooks) host.MemoryWrite32(h.slot, h.thunk);
    put(base + timer_retire_slot_va, timer_retire_thunk);
    // The measured scene already holds about 30 MiB; retain reusable resources
    // within the existing bounded LRU policy instead of its original 24 MiB.
    put(base + 0x2a7b80, 64u * 1024 * 1024);
    installed = true;
    __android_log_print(ANDROID_LOG_INFO,"GrimCache","host hooks ready: engine=%08x hooks=%zu VIMA=1 timer_retire=1 save_compress=1 DSN=1 shared_audio=1 QA=1 orphan=1 bulk=1 whole_zero=1 probes=0",base,hooks.size());
    return true;
}
void GrimHooksTouch(JNIEnv* env, jint device, jint pointer, jint action, jfloat x, jfloat y, jfloat pressure) {
    if (!installed) return;
    auto& jni = FakeJniEnv::Instance();
    if (!jni.BeginNativeCall(env)) return;
    {
        std::lock_guard lock(mouse_lock);
        uint32_t guest_env = jni.EnvTableGuestAddr();
        if (action == 3) release_mouse(guest_env);
        else if (word(base + 0x2f71c20)) {
            tp_result selected{};
            if (tp_action(&pointers, device, pointer, action, x, y, pressure, &selected) < 0) release_mouse(guest_env);
            else {
                touch_original(guest_env, device, pointer, action, x, y, pressure);
                if (selected.selected) {
                    GuestBytes output(8);
                    call("SDL_GetWindowSize", {word(base + 0x2f71c20), output.address, output.address + 4});
                    int width = int(word(output.address)), height = int(word(output.address + 4));
                    call("SDL_SendMouseMotion", {0, UINT32_MAX, 0, uint32_t(int(x * float(width))), uint32_t(int(y * float(height)))});
                    if (selected.kind == MS_DOWN || selected.kind == MS_UP) {
                        call("SDL_SendMouseButton", {0, UINT32_MAX, uint32_t(selected.kind == MS_DOWN), 1});
                        if (selected.kind == MS_UP) engine->MemoryWrite64(base + 0x2f71c18, 0);
                    }
                    call("SDL_GetMouseState", {output.address, output.address + 4});
                    if (ms_submit(&mouse, static_cast<ms_kind>(selected.kind), int(word(output.address)), int(word(output.address + 4))) < 0) release_mouse(guest_env);
                }
            }
        }
    }
    jni.EndNativeCall();
}
void GrimHooksResetInput() {
    GrimHooksCancelBackSample();
    if (!installed) return;
    auto& jni = FakeJniEnv::Instance();
    JNIEnv* env = jni.GetEnv();
    if (!env || !jni.BeginNativeCall(env)) return;
    { std::lock_guard lock(mouse_lock); release_mouse(jni.EnvTableGuestAddr()); }
    jni.EndNativeCall();
}
void GrimHooksPauseQa() { GrimHooksCancelBackSample(); if (installed) { qa_slot_request_reset(&qa_commands); clear_reply(false); } }
jlong GrimHooksQaCommand(JNIEnv* env, jint command, jlong epoch, jstring key) {
    if (!installed || !key || epoch < 1 || env->ExceptionCheck()) return QA_UNAVAILABLE;
    const char* pending = env->GetStringUTFChars(key,nullptr); if (!pending) return QA_UNAVAILABLE;
    uint64_t ticket = 0;
    int result = qa_slot_offer(&qa_commands,static_cast<qa_command>(command),uint64_t(epoch),pending,now_ms(),&ticket);
    env->ReleaseStringUTFChars(key,pending);
    return result == QA_OK ? jlong(ticket) : result;
}
jobjectArray GrimHooksQaState(JNIEnv* env) {
    if (env->ExceptionCheck()) return nullptr;
    char values[13][260]{};
    snprintf(values[0],sizeof(values[0]),"%llu",static_cast<unsigned long long>(installed ? qa_slot_epoch(&qa_commands) : 1));
    {
        std::lock_guard lock(qa_reply_lock);
        snprintf(values[1],sizeof(values[1]),"%llu",static_cast<unsigned long long>(qa_reply.ticket));
        snprintf(values[2],sizeof(values[2]),"%d",qa_reply.result);
        memcpy(values[3],qa_reply.status,sizeof(values[3])); memcpy(values[4],qa_reply.key,sizeof(values[4])); memcpy(values[5],qa_reply.room,sizeof(values[5]));
        snprintf(values[6],sizeof(values[6]),"%d",qa_reply.fps); snprintf(values[7],sizeof(values[7]),"%d",qa_reply.perf);
        snprintf(values[9],sizeof(values[9]),"%llu",static_cast<unsigned long long>(qa_menu_sequence));
        snprintf(values[10],sizeof(values[10]),"%llu",static_cast<unsigned long long>(qa_menu_epoch));
        snprintf(values[11],sizeof(values[11]),"%llu",static_cast<unsigned long long>(language_sequence));
        snprintf(values[12],sizeof(values[12]),"%d",language_requested);
    }
    std::string hud;
    {
        std::lock_guard lock(overlay_lock);
        if (values[6][0] == '1' && overlay.fps_valid) { hud += overlay.fps; hud += '\n'; }
        if (values[7][0] == '1' && overlay.perf_valid) for (const auto& line : overlay.perf) { hud += line; hud += '\n'; }
    }
    jclass string = env->FindClass("java/lang/String"); if (!string) return nullptr;
    jobjectArray result = env->NewObjectArray(13,string,nullptr);
    if (result) for (unsigned i = 0; i < 13 && !env->ExceptionCheck(); ++i) {
        jstring value = env->NewStringUTF(i == 8 ? hud.c_str() : values[i]);
        if (!value) break;
        env->SetObjectArrayElement(result,i,value); env->DeleteLocalRef(value);
    }
    env->DeleteLocalRef(string); return result;
}

void GrimHooksLanguageSaved(jlong sequence, bool saved) {
    std::lock_guard lock(qa_reply_lock);
    if (sequence < 1 || uint64_t(sequence) != language_sequence) return;
    if (saved) language_accepted = language_requested;
    else language_rollback = language_accepted;
    __android_log_print(ANDROID_LOG_INFO,"GrimCache","language selection=%d saved=%d next_launch=1",language_requested,int(saved));
}
