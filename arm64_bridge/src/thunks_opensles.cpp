#include "thunks_opensles.h"
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"

#include <SLES/OpenSLES.h>
#include <SLES/OpenSLES_Android.h>
#include <android/log.h>
#include <array>
#include <cstring>
#include <vector>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <algorithm>

#if defined(__ANDROID__)
#include <sys/resource.h>
#include <sys/prctl.h>
#endif

#define LOG_TAG "Arm32Bridge_Audio"
#include "bridge_log.h"

namespace {

// Host OpenSL ES global state
SLObjectItf g_hostEngineObject = nullptr;
SLEngineItf g_hostEngineEngine = nullptr;
SLObjectItf g_hostOutputMixObject = nullptr;

// Guest addresses for objects & vtables
uint32_t g_guestEngineObjectAddr = 0;
uint32_t g_guestEngineVtblAddr = 0;
uint32_t g_guestEngineInterfaceAddr = 0;
uint32_t g_guestEngineInterfaceVtblAddr = 0;

uint32_t g_guestOutputMixObjectAddr = 0;
uint32_t g_guestOutputMixVtblAddr = 0;

// Each guest audio player needs its own host player, callback and lifetime-stable
// queue storage. Unity and CRIWARE use different sample rates concurrently.
static constexpr size_t BUFFER_QUEUE_COUNT = 128;
static constexpr size_t MAX_REASONABLE_BUFFER_SIZE = 16 * 1024 * 1024;
static constexpr size_t MAX_TRACKED_AUDIO_PLAYERS = 64;

struct AudioPlayerState {
    uint64_t id = 0;
    SLObjectItf object = nullptr;
    SLPlayItf play = nullptr;
    SLAndroidSimpleBufferQueueItf queue = nullptr;
    SLVolumeItf volume = nullptr;
    SLAndroidConfigurationItf configuration = nullptr;

    uint32_t guest_object = 0;
    uint32_t guest_play = 0;
    uint32_t guest_queue = 0;
    uint32_t guest_volume = 0;
    uint32_t guest_configuration = 0;

    SLuint32 channels = 0;
    SLuint32 sample_rate = 0;
    std::array<std::vector<uint8_t>, BUFFER_QUEUE_COUNT> buffers;
    size_t next_buffer = 0;
    size_t outstanding_buffers = 0;
    std::mutex queue_mutex;
    std::recursive_mutex delivery_mutex;
    std::atomic<size_t> completed_buffers{0};
    std::atomic<uint32_t> guest_callback{0};
    std::atomic<uint32_t> guest_callback_context{0};
    std::atomic<int> pending_callbacks{0};
    std::atomic<bool> destroyed{false};
    std::atomic<bool> resume_after_pause{false};
};

static std::recursive_mutex g_audioApiMutex;
static std::mutex g_playersMutex;
static std::vector<std::shared_ptr<AudioPlayerState>> g_players;
static std::unordered_map<uint32_t, std::shared_ptr<AudioPlayerState>> g_playerByGuestHandle;
static std::atomic<uint64_t> g_nextPlayerId{1};

static std::unordered_map<std::string, uint32_t> g_iid_pointer_map;
static std::atomic<int> g_bqCallbackPending{0};

// Background Audio Thread synchronization
static std::atomic<bool> g_audioThreadRunning{false};
static std::atomic<bool> g_audioPaused{false};
static std::mutex g_audioCvMutex;
static std::condition_variable g_audioCv;
static std::unique_ptr<std::thread> g_audioThread;

static void HostBqPlayerCallback(SLAndroidSimpleBufferQueueItf bq, void *context) {
    (void)bq;
    auto* player = static_cast<AudioPlayerState*>(context);
    if (!player || player->destroyed.load(std::memory_order_acquire)) return;
    player->completed_buffers.fetch_add(1, std::memory_order_release);
    // Increment the aggregate first. If the worker observes it between these two
    // operations, it simply scans again; the counter can never underflow.
    g_bqCallbackPending.fetch_add(1, std::memory_order_release);
    player->pending_callbacks.fetch_add(1, std::memory_order_release);
    g_audioCv.notify_one();
}

static std::shared_ptr<AudioPlayerState> FindPlayer(uint32_t guest_handle) {
    std::lock_guard<std::mutex> lock(g_playersMutex);
    const auto it = g_playerByGuestHandle.find(guest_handle);
    return it == g_playerByGuestHandle.end() ? nullptr : it->second;
}

struct PlayerSnapshot {
    std::array<std::shared_ptr<AudioPlayerState>, MAX_TRACKED_AUDIO_PLAYERS> values{};
    size_t count = 0;
};

static PlayerSnapshot SnapshotPlayers() {
    std::lock_guard<std::mutex> lock(g_playersMutex);
    PlayerSnapshot result;
    result.count = std::min(g_players.size(), result.values.size());
    for (size_t i = 0; i < result.count; ++i) result.values[i] = g_players[i];
    return result;
}

static uint32_t AllocateGuestInterface(
        DynarmicHost& host,
        std::initializer_list<std::pair<size_t, const char*>> methods) {
    const uint32_t vtable = host.GuestAlloc(64 * sizeof(uint32_t), 8);
    const uint32_t interface_address = host.GuestAlloc(16, 8);
    if (!vtable || !interface_address) { host.GuestFree(vtable);host.GuestFree(interface_address);return 0; }
    for (uint32_t i=0;i<64;++i) host.MemoryWrite32(vtable+i*4, host.GetThunkManager().FindRegisteredSymbol("SLUnsupported"));
    memset(host.GetGuestMemoryBase() + interface_address, 0, 16);
    host.MemoryWrite32(interface_address, vtable);
    for (const auto& method : methods) {
        host.MemoryWrite32(
            vtable + static_cast<uint32_t>(method.first * sizeof(uint32_t)),
            host.GetThunkManager().GetOrCreateThunkAddress(method.second));
    }
    return interface_address;
}

static void RegisterPlayerHandles(const std::shared_ptr<AudioPlayerState>& player) {
    g_playerByGuestHandle[player->guest_object] = player;
    g_playerByGuestHandle[player->guest_play] = player;
    g_playerByGuestHandle[player->guest_queue] = player;
    g_playerByGuestHandle[player->guest_volume] = player;
    g_playerByGuestHandle[player->guest_configuration] = player;
}

bool IID_Matches(DynarmicHost& host, uint32_t iid_ptr, const SLInterfaceID host_iid) {
    if (iid_ptr == 0 || !host_iid) return false;
    const void* pStruct = host_iid;

    if (GuestRangeValid(host.GetGuestMemorySize(), iid_ptr, sizeof(struct SLInterfaceID_))) {
        const void* guest1 = host.GetGuestMemoryBase() + iid_ptr;
        if (memcmp(guest1, pStruct, sizeof(struct SLInterfaceID_)) == 0) return true;
    }

    if (iid_ptr + 4 <= host.GetGuestMemorySize()) {
        uint32_t deref = host.MemoryRead32(iid_ptr);
        if (GuestRangeValid(host.GetGuestMemorySize(), deref, sizeof(struct SLInterfaceID_))) {
            const void* guest2 = host.GetGuestMemoryBase() + deref;
            if (memcmp(guest2, pStruct, sizeof(struct SLInterfaceID_)) == 0) return true;
        }
    }
    return false;
}

static uint32_t AllocAndRegisterIID(ThunkManager& manager, DynarmicHost& host, const std::string& name, const SLInterfaceID host_iid) {
    // 1. Allocate 16 bytes for struct SLInterfaceID_
    uint32_t struct_addr = host.GuestAlloc(sizeof(struct SLInterfaceID_), 4);
    if (host_iid) {
        memcpy(host.GetGuestMemoryBase() + struct_addr, host_iid, sizeof(struct SLInterfaceID_));
    }

    // 2. Allocate 4 bytes for pointer to struct
    uint32_t ptr_addr = host.GuestAlloc(4, 4);
    host.MemoryWrite32(ptr_addr, struct_addr);

    // 3. Register in ThunkManager and map
    manager.RegisterSymbol(name, ptr_addr);
    g_iid_pointer_map[name] = ptr_addr;

    LOGI("Registered OpenSL ES IID %s: ptr=0x%08X -> struct=0x%08X", name.c_str(), ptr_addr, struct_addr);
    return ptr_addr;
}

} // namespace

bool HasPendingAudioCallbacks() {
    return g_bqCallbackPending.load(std::memory_order_relaxed) > 0;
}

void PumpOpenSLESCallbacks(DynarmicHost& host) {
    if (g_audioPaused.load(std::memory_order_relaxed)) return;
    if (host.IsJitRunning()) return;

    const PlayerSnapshot players = SnapshotPlayers();
    for (size_t player_index = 0; player_index < players.count; ++player_index) {
        auto player = players.values[player_index];
        std::lock_guard delivery_lock(player->delivery_mutex);
        const int pending = player->pending_callbacks.exchange(0, std::memory_order_acq_rel);
        if (pending <= 0) continue;
        g_bqCallbackPending.fetch_sub(pending, std::memory_order_acq_rel);

        if (player->destroyed.load(std::memory_order_acquire)) continue;
        const uint32_t callback = player->guest_callback.load(std::memory_order_acquire);
        const uint32_t context = player->guest_callback_context.load(std::memory_order_acquire);
        if (!callback) continue;
        for (int i = 0; i < pending; ++i) {
            if(player->destroyed.load(std::memory_order_acquire))break;
            host.RunFunction(callback, {player->guest_queue, context});
        }
    }
}

void PumpAudioWorkers(DynarmicHost&) { /* Guest pthreads now execute their own workers. */ }

static void AudioThreadLoop(DynarmicHost* host) {
    LOGI("Dedicated audio thread started with high priority!");
#if defined(__ANDROID__)
    prctl(PR_SET_NAME, "BridgeAudio", 0, 0, 0);
    setpriority(PRIO_PROCESS, 0, -16); // High priority audio thread
#endif

    while (g_audioThreadRunning.load(std::memory_order_relaxed)) {
        {
            std::unique_lock<std::mutex> lock(g_audioCvMutex);
            g_audioCv.wait_for(lock, std::chrono::milliseconds(5), []() {
                return !g_audioThreadRunning.load(std::memory_order_relaxed) ||
                       g_bqCallbackPending.load(std::memory_order_relaxed) > 0;
            });
        }

        if (!g_audioThreadRunning.load(std::memory_order_relaxed)) break;
        if (!host || g_audioPaused.load(std::memory_order_relaxed)) continue;

        if (g_bqCallbackPending.load(std::memory_order_relaxed) > 0) {
            PumpOpenSLESCallbacks(*host);
        }

    }

    if (host) host->ReleaseCurrentThread();

    LOGI("Dedicated audio thread stopped.");
}

void StartAudioThread(DynarmicHost* host) {
    if (g_audioThreadRunning.load(std::memory_order_relaxed)) return;
    if (!host) return;
    g_audioThreadRunning.store(true, std::memory_order_relaxed);
    g_audioPaused.store(false, std::memory_order_relaxed);
    g_audioThread = std::make_unique<std::thread>(AudioThreadLoop, host);
    LOGI("Audio thread launched successfully!");
}

void StopAudioThread() {
    if (!g_audioThreadRunning.load(std::memory_order_relaxed)) return;
    g_audioThreadRunning.store(false, std::memory_order_relaxed);
    g_audioCv.notify_all();
    if (g_audioThread && g_audioThread->joinable()) {
        g_audioThread->join();
    }
    g_audioThread.reset();
}

void PauseAudioPlayback() {
    std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
    LOGI("PauseAudioPlayback requested");
    g_audioPaused.store(true, std::memory_order_release);
    const PlayerSnapshot players = SnapshotPlayers();
    for (size_t player_index = 0; player_index < players.count; ++player_index) {
        auto player = players.values[player_index];
        if (!player->play || player->destroyed.load(std::memory_order_acquire)) continue;
        SLuint32 state = SL_PLAYSTATE_STOPPED;
        const bool was_playing =
            (*player->play)->GetPlayState(player->play, &state) == SL_RESULT_SUCCESS &&
            state == SL_PLAYSTATE_PLAYING;
        player->resume_after_pause.store(was_playing, std::memory_order_release);
        if (was_playing) {
            (*player->play)->SetPlayState(player->play, SL_PLAYSTATE_PAUSED);
        }
    }
}

void ResumeAudioPlayback() {
    std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
    LOGI("ResumeAudioPlayback requested");
    g_audioPaused.store(false, std::memory_order_release);
    const PlayerSnapshot players = SnapshotPlayers();
    for (size_t player_index = 0; player_index < players.count; ++player_index) {
        auto player = players.values[player_index];
        if (!player->play || player->destroyed.load(std::memory_order_acquire)) continue;
        if (player->resume_after_pause.exchange(false, std::memory_order_acq_rel)) {
            (*player->play)->SetPlayState(player->play, SL_PLAYSTATE_PLAYING);
        }
    }
    g_audioCv.notify_one();
}

uint32_t GetOpenSLESInterfacePointer(const std::string& name) {
    auto it = g_iid_pointer_map.find(name);
    if (it != g_iid_pointer_map.end()) {
        return it->second;
    }
    return 0;
}

void RegisterOpenSLESThunks(ThunkManager& manager, DynarmicHost& host) {
    manager.RegisterThunk("SLUnsupported", [](Dynarmic::A32::Jit& j, DynarmicHost&) { j.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED; });
    LOGI("Registering OpenSL ES guest bridge thunks...");

    // Register all standard OpenSL ES interface IDs
    AllocAndRegisterIID(manager, host, "SL_IID_ENGINE", SL_IID_ENGINE);
    AllocAndRegisterIID(manager, host, "SL_IID_ANDROIDSIMPLEBUFFERQUEUE", SL_IID_ANDROIDSIMPLEBUFFERQUEUE);
    AllocAndRegisterIID(manager, host, "SL_IID_ANDROIDCONFIGURATION", SL_IID_ANDROIDCONFIGURATION);
    AllocAndRegisterIID(manager, host, "SL_IID_PLAY", SL_IID_PLAY);
    AllocAndRegisterIID(manager, host, "SL_IID_VOLUME", SL_IID_VOLUME);
    AllocAndRegisterIID(manager, host, "SL_IID_OUTPUTMIX", SL_IID_OUTPUTMIX);
    AllocAndRegisterIID(manager, host, "SL_IID_BUFFERQUEUE", SL_IID_BUFFERQUEUE);
    AllocAndRegisterIID(manager, host, "SL_IID_RECORD", SL_IID_RECORD);

    // 1. slCreateEngine
    manager.RegisterThunk("slCreateEngine", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        uint32_t pEngine = jit.Regs()[0];
        LOGI("slCreateEngine called! pEngine=0x%08X", pEngine);

        // Initialize Host OpenSL ES
        if (!g_hostEngineObject) {
            SLresult result = slCreateEngine(&g_hostEngineObject, 0, nullptr, 0, nullptr, nullptr);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host slCreateEngine failed: %u", result);
                jit.Regs()[0] = result;
                return;
            }

            result = (*g_hostEngineObject)->Realize(g_hostEngineObject, SL_BOOLEAN_FALSE);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host Engine Realize failed: %u", result);
                jit.Regs()[0] = result;
                return;
            }

            result = (*g_hostEngineObject)->GetInterface(g_hostEngineObject, SL_IID_ENGINE, &g_hostEngineEngine);
            if (result != SL_RESULT_SUCCESS) {
                LOGE("Host Engine GetInterface failed: %u", result);
                jit.Regs()[0] = result;
                return;
            }

            // Create Host OutputMix
            result = (*g_hostEngineEngine)->CreateOutputMix(g_hostEngineEngine, &g_hostOutputMixObject, 0, nullptr, nullptr);
            if (result == SL_RESULT_SUCCESS) {
                (*g_hostOutputMixObject)->Realize(g_hostOutputMixObject, SL_BOOLEAN_FALSE);
            }
        }

        // Allocate Guest Engine Object structure
        if (g_guestEngineObjectAddr == 0) {
            g_guestEngineVtblAddr = host.GuestAlloc(64 * 4, 8);
            g_guestEngineObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestEngineObjectAddr, g_guestEngineVtblAddr);

            // Populate VTable with thunk addresses
            host.MemoryWrite32(g_guestEngineVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 1 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Resume"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_GetState"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 3 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_GetInterface"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 4 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_RegisterCallback"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 5 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_AbortAsyncOperation"));
            host.MemoryWrite32(g_guestEngineVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pEngine) {
            host.MemoryWrite32(pEngine, g_guestEngineObjectAddr);
        }

        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 2. Generic SLObject Thunks
    manager.RegisterThunk("SLObject_Realize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        LOGI("SLObject_Realize called");
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_Resume", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        uint32_t pState = jit.Regs()[1];
        if (pState) host.MemoryWrite32(pState, SL_OBJECT_STATE_REALIZED);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLObject_AbortAsyncOperation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
    });

    manager.RegisterThunk("SLObject_Destroy", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        auto player = FindPlayer(jit.Regs()[0]);
        if (!player) {
            LOGI("SLObject_Destroy called for shared engine/output object");
            return;
        }
        // Never wait for a guest callback while holding the native API mutex:
        // that callback can itself enqueue, clear or destroy this player.
        std::lock_guard delivery_lock(player->delivery_mutex);
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        if (player->destroyed.exchange(true, std::memory_order_acq_rel)) return;
        player->guest_callback.store(0,std::memory_order_release);

        LOGI("Destroying host Audio Player #%llu", static_cast<unsigned long long>(player->id));
        if (player->play) {
            (*player->play)->SetPlayState(player->play, SL_PLAYSTATE_STOPPED);
        }
        if (player->queue) {
            (*player->queue)->Clear(player->queue);
        }
        if (player->object) {
            (*player->object)->Destroy(player->object);
        }
        player->object = nullptr;
        player->play = nullptr;
        player->queue = nullptr;
        player->volume = nullptr;
        player->configuration = nullptr;
        const int pending=player->pending_callbacks.exchange(0,std::memory_order_acq_rel);
        g_bqCallbackPending.fetch_sub(pending,std::memory_order_acq_rel);
        {
            std::lock_guard lock(g_playersMutex);
            for(uint32_t address:{player->guest_object,player->guest_play,player->guest_queue,player->guest_volume,player->guest_configuration}) {
                g_playerByGuestHandle.erase(address);
                host.GuestFree(host.MemoryRead32(address));host.GuestFree(address);
            }
            std::erase(g_players,player);
        }
    });

    // 3. SLEngine_GetInterface
    manager.RegisterThunk("SLEngine_GetInterface", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        uint32_t self = jit.Regs()[0];
        uint32_t iid_ptr = jit.Regs()[1];
        uint32_t pInterface = jit.Regs()[2];

        LOGI("SLEngine_GetInterface self=0x%08X, iid=0x%08X, pInterface=0x%08X", self, iid_ptr, pInterface);

        if (IID_Matches(host, iid_ptr, SL_IID_ENGINE)) {
            if (g_guestEngineInterfaceAddr == 0) {
                g_guestEngineInterfaceVtblAddr = host.GuestAlloc(64 * 4, 8);
                g_guestEngineInterfaceAddr = host.GuestAlloc(16, 8);
                host.MemoryWrite32(g_guestEngineInterfaceAddr, g_guestEngineInterfaceVtblAddr);

                // Populate SLEngineItf VTable
                host.MemoryWrite32(g_guestEngineInterfaceVtblAddr + 2 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_CreateAudioPlayer"));
                host.MemoryWrite32(g_guestEngineInterfaceVtblAddr + 7 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLEngine_CreateOutputMix"));
            }

            if (pInterface) {
                host.MemoryWrite32(pInterface, g_guestEngineInterfaceAddr);
            }
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        LOGI("SLEngine_GetInterface: unsupported IID 0x%08X", iid_ptr);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    // 4. SLEngine_CreateOutputMix
    manager.RegisterThunk("SLEngine_CreateOutputMix", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        uint32_t pMix = jit.Regs()[1];
        LOGI("SLEngine_CreateOutputMix called! pMix=0x%08X", pMix);

        if (g_guestOutputMixObjectAddr == 0) {
            g_guestOutputMixVtblAddr = host.GuestAlloc(64 * 4, 8);
            g_guestOutputMixObjectAddr = host.GuestAlloc(16, 8);
            host.MemoryWrite32(g_guestOutputMixObjectAddr, g_guestOutputMixVtblAddr);

            host.MemoryWrite32(g_guestOutputMixVtblAddr + 0 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Realize"));
            host.MemoryWrite32(g_guestOutputMixVtblAddr + 6 * 4, host.GetThunkManager().GetOrCreateThunkAddress("SLObject_Destroy"));
        }

        if (pMix) {
            host.MemoryWrite32(pMix, g_guestOutputMixObjectAddr);
        }
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 5. SLEngine_CreateAudioPlayer
    manager.RegisterThunk("SLEngine_CreateAudioPlayer", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        Arm32CallArgs args(jit, host);
        const uint32_t self = args.U32();
        const uint32_t pPlayer = args.Ptr();
        const uint32_t pAudioSrc = args.Ptr();
        const uint32_t pAudioSnk = args.Ptr();
        const uint32_t numInterfaces = args.U32();
        const uint32_t interfaceIds = args.Ptr();
        const uint32_t interfaceRequired = args.Ptr();
        (void)self;
        (void)pAudioSnk;
        (void)interfaceIds;
        (void)interfaceRequired;

        LOGI("SLEngine_CreateAudioPlayer pPlayer=0x%08X src=0x%08X interfaces=%u",
             pPlayer, pAudioSrc, numInterfaces);
        if (!g_hostEngineEngine || !g_hostOutputMixObject ||
            !GuestRangeValid(host.GetGuestMemorySize(), pPlayer, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }

        {
            std::lock_guard lock(g_playersMutex);
            if(g_players.size() >= MAX_TRACKED_AUDIO_PLAYERS) { jit.Regs()[0]=SL_RESULT_RESOURCE_ERROR;return; }
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pAudioSrc, 8) ||
            !GuestRangeValid(host.GetGuestMemorySize(), pAudioSnk, 8) || numInterfaces > 64 ||
            (numInterfaces && (!GuestRangeValid(host.GetGuestMemorySize(), interfaceIds, numInterfaces*4) ||
                               !GuestRangeValid(host.GetGuestMemorySize(), interfaceRequired, numInterfaces*4)))) {
            jit.Regs()[0]=SL_RESULT_PARAMETER_INVALID;return;
        }
        const uint32_t locator=host.MemoryRead32(pAudioSrc), format_addr=host.MemoryRead32(pAudioSrc+4);
        const uint32_t sink=host.MemoryRead32(pAudioSnk);
        if (!GuestRangeValid(host.GetGuestMemorySize(),locator,8) ||
            !GuestRangeValid(host.GetGuestMemorySize(),format_addr,28) ||
            !GuestRangeValid(host.GetGuestMemorySize(),sink,8)) { jit.Regs()[0]=SL_RESULT_PARAMETER_INVALID;return; }
        const uint32_t locator_type=host.MemoryRead32(locator);
        if ((locator_type!=SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE && locator_type!=SL_DATALOCATOR_BUFFERQUEUE) ||
            host.MemoryRead32(format_addr)!=SL_DATAFORMAT_PCM || host.MemoryRead32(sink)!=SL_DATALOCATOR_OUTPUTMIX) {
            jit.Regs()[0]=SL_RESULT_CONTENT_UNSUPPORTED;return;
        }
        for(uint32_t i=0;i<numInterfaces;++i) {
            uint32_t iid=host.MemoryRead32(interfaceIds+i*4);
            if(host.MemoryRead32(interfaceRequired+i*4) && !IID_Matches(host,iid,SL_IID_PLAY) &&
               !IID_Matches(host,iid,SL_IID_VOLUME) && !IID_Matches(host,iid,SL_IID_BUFFERQUEUE) &&
               !IID_Matches(host,iid,SL_IID_ANDROIDSIMPLEBUFFERQUEUE) && !IID_Matches(host,iid,SL_IID_ANDROIDCONFIGURATION)) {
                jit.Regs()[0]=SL_RESULT_FEATURE_UNSUPPORTED;return;
            }
        }

        SLuint32 numChannels = 2;
        SLuint32 sampleRate = SL_SAMPLINGRATE_44_1;
        SLuint32 bitsPerSample = SL_PCMSAMPLEFORMAT_FIXED_16;
        SLuint32 containerSize = SL_PCMSAMPLEFORMAT_FIXED_16;
        SLuint32 channelMask = SL_SPEAKER_FRONT_LEFT | SL_SPEAKER_FRONT_RIGHT;
        SLuint32 endianness = SL_BYTEORDER_LITTLEENDIAN;
        if (GuestRangeValid(host.GetGuestMemorySize(), pAudioSrc, 2 * sizeof(uint32_t))) {
            const uint32_t pFormat = host.MemoryRead32(pAudioSrc + sizeof(uint32_t));
            if (GuestRangeValid(host.GetGuestMemorySize(), pFormat, 7 * sizeof(uint32_t)) &&
                host.MemoryRead32(pFormat) == SL_DATAFORMAT_PCM) {
                numChannels = host.MemoryRead32(pFormat + 4);
                sampleRate = host.MemoryRead32(pFormat + 8);
                bitsPerSample = host.MemoryRead32(pFormat + 12);
                containerSize = host.MemoryRead32(pFormat + 16);
                channelMask = host.MemoryRead32(pFormat + 20);
                endianness = host.MemoryRead32(pFormat + 24);
            }
        }
        if (!numChannels || !sampleRate || !bitsPerSample || !containerSize) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        if (!channelMask) {
            channelMask = numChannels == 1
                ? SL_SPEAKER_FRONT_CENTER
                : (SL_SPEAKER_FRONT_LEFT | SL_SPEAKER_FRONT_RIGHT);
        }

        auto player = std::make_shared<AudioPlayerState>();
        player->id = g_nextPlayerId.fetch_add(1, std::memory_order_relaxed);
        player->channels = numChannels;
        player->sample_rate = sampleRate;

        SLDataLocator_AndroidSimpleBufferQueue loc_bufq = {
            SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE,
            static_cast<SLuint32>(BUFFER_QUEUE_COUNT)
        };
        SLDataFormat_PCM format_pcm = {
            SL_DATAFORMAT_PCM,
            numChannels,
            sampleRate,
            bitsPerSample,
            containerSize,
            channelMask,
            endianness
        };
        SLDataSource audioSrc = {&loc_bufq, &format_pcm};
        SLDataLocator_OutputMix loc_outmix = {
            SL_DATALOCATOR_OUTPUTMIX,
            g_hostOutputMixObject
        };
        SLDataSink audioSnk = {&loc_outmix, nullptr};
        const SLInterfaceID ids[] = {
            SL_IID_ANDROIDSIMPLEBUFFERQUEUE,
            SL_IID_PLAY,
            SL_IID_VOLUME,
            SL_IID_ANDROIDCONFIGURATION
        };
        const SLboolean required[] = {
            SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE
        };

        SLresult result = (*g_hostEngineEngine)->CreateAudioPlayer(
            g_hostEngineEngine, &player->object, &audioSrc, &audioSnk,
            static_cast<SLuint32>(std::size(ids)), ids, required);
        if (result != SL_RESULT_SUCCESS) {
            LOGE("Host CreateAudioPlayer #%llu failed: %u",
                 static_cast<unsigned long long>(player->id), result);
            jit.Regs()[0] = result;
            return;
        }

        result = (*player->object)->GetInterface(
            player->object, SL_IID_ANDROIDCONFIGURATION, &player->configuration);
        if (result == SL_RESULT_SUCCESS && player->configuration) {
            SLint32 streamType = SL_ANDROID_STREAM_MEDIA;
            result = (*player->configuration)->SetConfiguration(
                player->configuration, SL_ANDROID_KEY_STREAM_TYPE,
                &streamType, sizeof(streamType));
        }
        if (result == SL_RESULT_SUCCESS) {
            result = (*player->object)->Realize(player->object, SL_BOOLEAN_FALSE);
        }
        if (result == SL_RESULT_SUCCESS) {
            result = (*player->object)->GetInterface(player->object, SL_IID_PLAY, &player->play);
        }
        if (result == SL_RESULT_SUCCESS) {
            result = (*player->object)->GetInterface(
                player->object, SL_IID_ANDROIDSIMPLEBUFFERQUEUE, &player->queue);
        }
        if (result == SL_RESULT_SUCCESS) {
            result = (*player->object)->GetInterface(player->object, SL_IID_VOLUME, &player->volume);
        }
        if (result != SL_RESULT_SUCCESS || !player->play || !player->queue || !player->volume) {
            LOGE("Host Audio Player #%llu setup failed: %u",
                 static_cast<unsigned long long>(player->id), result);
            (*player->object)->Destroy(player->object);
            jit.Regs()[0] = result == SL_RESULT_SUCCESS ? SL_RESULT_FEATURE_UNSUPPORTED : result;
            return;
        }

        (*player->volume)->SetVolumeLevel(player->volume, 0);

        player->guest_object = AllocateGuestInterface(host, {
            {0, "SLObject_Realize"},
            {1, "SLObject_Resume"},
            {2, "SLObject_GetState"},
            {3, "SLPlayer_GetInterface"},
            {4, "SLObject_RegisterCallback"},
            {5, "SLObject_AbortAsyncOperation"},
            {6, "SLObject_Destroy"}
        });
        player->guest_play = AllocateGuestInterface(host, {
            {0, "SLPlay_SetPlayState"},
            {1, "SLPlay_GetPlayState"},
            {2, "SLPlay_GetDuration"},
            {3, "SLPlay_GetPosition"}
        });
        player->guest_queue = AllocateGuestInterface(host, {
            {0, "SLBufferQueue_Enqueue"},
            {1, "SLBufferQueue_Clear"},
            {2, "SLBufferQueue_GetState"},
            {3, "SLBufferQueue_RegisterCallback"}
        });
        player->guest_volume = AllocateGuestInterface(host, {
            {0, "SLVolume_SetVolumeLevel"},
            {1, "SLVolume_GetVolumeLevel"},
            {2, "SLVolume_GetMaxVolumeLevel"}
        });
        player->guest_configuration = AllocateGuestInterface(host, {
            {0, "SLConfig_SetConfiguration"},
            {1, "SLConfig_GetConfiguration"}
        });
        if (!player->guest_object || !player->guest_play || !player->guest_queue ||
            !player->guest_volume || !player->guest_configuration) {
            (*player->object)->Destroy(player->object);
            jit.Regs()[0] = SL_RESULT_MEMORY_FAILURE;
            return;
        }

        result = (*player->queue)->RegisterCallback(
            player->queue, HostBqPlayerCallback, player.get());
        if (result != SL_RESULT_SUCCESS) {
            (*player->object)->Destroy(player->object);
            jit.Regs()[0] = result;
            return;
        }

        auto player_ptr = player;
        {
            std::lock_guard<std::mutex> lock(g_playersMutex);
            RegisterPlayerHandles(player_ptr);
            g_players.emplace_back(std::move(player));
        }
        host.MemoryWrite32(pPlayer, player_ptr->guest_object);
        LOGI("Host Audio Player #%llu created: %u channels, %u mHz, object=0x%08X queue=0x%08X",
             static_cast<unsigned long long>(player_ptr->id), numChannels, sampleRate,
             player_ptr->guest_object, player_ptr->guest_queue);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    // 6. SLPlayer_GetInterface
    manager.RegisterThunk("SLPlayer_GetInterface", [&host](Dynarmic::A32::Jit& jit, DynarmicHost& h) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        const uint32_t self = jit.Regs()[0];
        const uint32_t iid_ptr = jit.Regs()[1];
        const uint32_t pInterface = jit.Regs()[2];
        auto player = FindPlayer(self);

        LOGI("SLPlayer_GetInterface self=0x%08X, iid=0x%08X, pInterface=0x%08X", self, iid_ptr, pInterface);
        if (!player || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pInterface, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_PLAY)) {
            host.MemoryWrite32(pInterface, player->guest_play);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_ANDROIDSIMPLEBUFFERQUEUE) || IID_Matches(host, iid_ptr, SL_IID_BUFFERQUEUE)) {
            host.MemoryWrite32(pInterface, player->guest_queue);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_VOLUME)) {
            host.MemoryWrite32(pInterface, player->guest_volume);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        if (IID_Matches(host, iid_ptr, SL_IID_ANDROIDCONFIGURATION)) {
            host.MemoryWrite32(pInterface, player->guest_configuration);
            jit.Regs()[0] = SL_RESULT_SUCCESS;
            return;
        }

        LOGI("SLPlayer_GetInterface: unsupported IID 0x%08X (returning FEATURE_UNSUPPORTED)", iid_ptr);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    manager.RegisterThunk("SLConfig_SetConfiguration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    manager.RegisterThunk("SLConfig_GetConfiguration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        jit.Regs()[0] = SL_RESULT_FEATURE_UNSUPPORTED;
    });

    // 7. SLPlay Thunks
    manager.RegisterThunk("SLPlay_SetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const SLuint32 state = jit.Regs()[1];
        if (!player || !player->play || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        LOGI("Audio Player #%llu SetPlayState=%u",
             static_cast<unsigned long long>(player->id), state);
        jit.Regs()[0] = (*player->play)->SetPlayState(player->play, state);
    });

    manager.RegisterThunk("SLPlay_GetPlayState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pState = jit.Regs()[1];
        if (!player || !player->play || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pState, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLuint32 state = SL_PLAYSTATE_STOPPED;
        const SLresult result = (*player->play)->GetPlayState(player->play, &state);
        if (result == SL_RESULT_SUCCESS) host.MemoryWrite32(pState, state);
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLPlay_GetDuration", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pMsec = jit.Regs()[1];
        if (!player || !player->play || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pMsec, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLmillisecond value = SL_TIME_UNKNOWN;
        const SLresult result = (*player->play)->GetDuration(player->play, &value);
        if (result == SL_RESULT_SUCCESS) host.MemoryWrite32(pMsec, value);
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLPlay_GetPosition", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pMsec = jit.Regs()[1];
        if (!player || !player->play || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pMsec, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLmillisecond value = 0;
        const SLresult result = (*player->play)->GetPosition(player->play, &value);
        if (result == SL_RESULT_SUCCESS) host.MemoryWrite32(pMsec, value);
        jit.Regs()[0] = result;
    });

    // 8. SLBufferQueue Thunks
    manager.RegisterThunk("SLBufferQueue_RegisterCallback", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        if (!player || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        player->guest_callback_context.store(jit.Regs()[2], std::memory_order_release);
        player->guest_callback.store(jit.Regs()[1], std::memory_order_release);
        if(jit.Regs()[1]) StartAudioThread(&host);
        LOGI("Audio Player #%llu RegisterCallback callback=0x%08X context=0x%08X",
             static_cast<unsigned long long>(player->id), jit.Regs()[1], jit.Regs()[2]);
        jit.Regs()[0] = SL_RESULT_SUCCESS;
    });

    manager.RegisterThunk("SLBufferQueue_Clear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        if (!player || !player->queue || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        std::lock_guard<std::mutex> lock(player->queue_mutex);
        const SLresult result = (*player->queue)->Clear(player->queue);
        if (result == SL_RESULT_SUCCESS) {
            const int pending=player->pending_callbacks.exchange(0,std::memory_order_acq_rel);
            g_bqCallbackPending.fetch_sub(pending,std::memory_order_acq_rel);
            player->completed_buffers.store(0, std::memory_order_release);
            player->outstanding_buffers = 0;
            player->next_buffer = 0;
        }
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLBufferQueue_GetState", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pState = jit.Regs()[1];
        if (!player || !player->queue || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pState, 2 * sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLAndroidSimpleBufferQueueState state = {0, 0};
        const SLresult result = (*player->queue)->GetState(player->queue, &state);
        if (result == SL_RESULT_SUCCESS) {
            host.MemoryWrite32(pState, state.count);
            host.MemoryWrite32(pState + sizeof(uint32_t), state.index);
        }
        jit.Regs()[0] = result;
    });

        manager.RegisterThunk("SLBufferQueue_Enqueue", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pBuffer = jit.Regs()[1];
        const uint32_t size = jit.Regs()[2];
        if (!player || !player->queue || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!size || static_cast<size_t>(size) > MAX_REASONABLE_BUFFER_SIZE ||
            !GuestRangeValid(host.GetGuestMemorySize(), pBuffer, static_cast<size_t>(size))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }

        std::lock_guard<std::mutex> lock(player->queue_mutex);
        const size_t completed = player->completed_buffers.exchange(0, std::memory_order_acq_rel);
        player->outstanding_buffers -= std::min(completed, player->outstanding_buffers);
        if (player->outstanding_buffers >= BUFFER_QUEUE_COUNT) {
            jit.Regs()[0] = SL_RESULT_BUFFER_INSUFFICIENT;
            return;
        }

        std::vector<uint8_t>& storage = player->buffers[player->next_buffer];
        storage.resize(size);
        memcpy(storage.data(), host.GetGuestMemoryBase() + pBuffer, size);

        const SLresult result = (*player->queue)->Enqueue(
            player->queue, storage.data(), static_cast<SLuint32>(storage.size()));
        if (result == SL_RESULT_SUCCESS) {
            player->next_buffer = (player->next_buffer + 1) % BUFFER_QUEUE_COUNT;
            ++player->outstanding_buffers;
        }
        jit.Regs()[0] = result;
    });

    // 9. SLVolume Thunk
    manager.RegisterThunk("SLVolume_SetVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        if (!player || !player->volume || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        jit.Regs()[0] = (*player->volume)->SetVolumeLevel(
            player->volume, static_cast<SLmillibel>(jit.Regs()[1]));
    });

    manager.RegisterThunk("SLVolume_GetVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pLevel = jit.Regs()[1];
        if (!player || !player->volume || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pLevel, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLmillibel level = 0;
        const SLresult result = (*player->volume)->GetVolumeLevel(player->volume, &level);
        if (result == SL_RESULT_SUCCESS) host.MemoryWrite32(pLevel, static_cast<uint32_t>(level));
        jit.Regs()[0] = result;
    });

    manager.RegisterThunk("SLVolume_GetMaxVolumeLevel", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        std::lock_guard<std::recursive_mutex> api_lock(g_audioApiMutex);
        auto player = FindPlayer(jit.Regs()[0]);
        const uint32_t pLevel = jit.Regs()[1];
        if (!player || !player->volume || player->destroyed.load(std::memory_order_acquire)) {
            jit.Regs()[0] = SL_RESULT_PRECONDITIONS_VIOLATED;
            return;
        }
        if (!GuestRangeValid(host.GetGuestMemorySize(), pLevel, sizeof(uint32_t))) {
            jit.Regs()[0] = SL_RESULT_PARAMETER_INVALID;
            return;
        }
        SLmillibel level = 0;
        const SLresult result = (*player->volume)->GetMaxVolumeLevel(player->volume, &level);
        if (result == SL_RESULT_SUCCESS) host.MemoryWrite32(pLevel, static_cast<uint32_t>(level));
        jit.Regs()[0] = result;
    });
}
