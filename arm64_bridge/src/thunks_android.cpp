#include "thunks_android.h"
#include "frame_pacing.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "dynarmic_host.h"
#include "jni_fake_env.h"

#include <EGL/egl.h>
#include <elf.h>
#include <cerrno>
#include <unistd.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <android/configuration.h>
#include <android/log.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

#define LOG_TAG "Arm32Bridge_Android"
#include "bridge_log.h"

namespace {
template <typename T>
class HandleTable {
public:
    uint32_t Add(T value, bool retain = false) {
        if (!value) return 0;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [handle, existing] : values_) if (existing == value) { if (retain) ++refs_[handle]; return handle; }
        const uint32_t handle = next_++;
        values_[handle] = value; refs_[handle] = 1;
        return handle;
    }
    T Get(uint32_t handle) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = values_.find(handle);
        return it == values_.end() ? T{} : it->second;
    }
    void Remove(uint32_t handle) {
        std::lock_guard<std::mutex> lock(mutex_);
        values_.erase(handle); refs_.erase(handle);
    }
    T Retain(uint32_t handle) {
        std::lock_guard lock(mutex_); auto it=values_.find(handle);
        if(it==values_.end())return T{}; ++refs_[handle];return it->second;
    }
    T Release(uint32_t handle) {
        std::lock_guard lock(mutex_); auto it=values_.find(handle);
        if(it==values_.end())return T{}; T value=it->second;
        if(--refs_[handle]==0) { values_.erase(it);refs_.erase(handle); }return value;
    }
private:
    mutable std::mutex mutex_;
    uint32_t next_ = 0x60000000;
    std::unordered_map<uint32_t, T> values_;
    std::unordered_map<uint32_t, size_t> refs_;
};

HandleTable<EGLDisplay> displays;
HandleTable<EGLConfig> configs;
HandleTable<EGLContext> contexts;
HandleTable<EGLSurface> surfaces;
// Only real window surfaces created by this existing guest boundary are paced.
std::mutex window_surface_lock;
std::unordered_map<EGLSurface, ANativeWindow*> window_surfaces;
thread_local EGLDisplay current_display = EGL_NO_DISPLAY;
thread_local EGLSurface current_draw = EGL_NO_SURFACE;
thread_local EGLContext current_context = EGL_NO_CONTEXT;
thread_local EGLint current_swap_interval = 0;
HandleTable<ANativeWindow*> windows;
HandleTable<AAssetManager*> asset_managers;
HandleTable<AAsset*> assets;
HandleTable<AAssetDir*> asset_dirs;
HandleTable<AConfiguration*> configurations;

const char* GuestString(DynarmicHost& host, uint32_t address) {
    if (!GuestRangeValid(host.GetGuestMemorySize(), address, 1)) return nullptr;
    const char* value = reinterpret_cast<const char*>(host.GetGuestMemoryBase() + address);
    return memchr(value, 0, std::min<size_t>(1024 * 1024, host.GetGuestMemorySize() - address)) ? value : nullptr;
}

const EGLint* GuestEglInts(DynarmicHost& host, uint32_t address) {
    if (!address || address % alignof(EGLint)) return nullptr;
    const size_t size = host.GetGuestMemorySize();
    for (uint64_t cursor = address; cursor + sizeof(EGLint) <= size && cursor - address < 2048; cursor += 2 * sizeof(EGLint)) {
        if (host.MemoryRead32(static_cast<uint32_t>(cursor)) == EGL_NONE)
            return reinterpret_cast<const EGLint*>(host.GetGuestMemoryBase() + address);
        if (cursor + 2 * sizeof(EGLint) > size) break;
    }
    LOGE("EGL rejected unterminated guest attributes at 0x%08X", address);
    return nullptr;
}

uint32_t CopyHostString(DynarmicHost& host, const char* value) {
    if (!value) return 0;
    const size_t size = strlen(value) + 1;
    const uint32_t guest = host.GuestAlloc(size, 4);
    if (guest) memcpy(host.GetGuestMemoryBase() + guest, value, size);
    return guest;
}
}

struct AndroidStrings {
    std::mutex mutex;
    std::unordered_map<std::string, uint32_t> egl;
    std::unordered_map<uint32_t, uint32_t> dirs;
    std::unordered_map<uint32_t, uint32_t> buffers;
};

static void RegisterAndroidExtraThunks(ThunkManager& manager);

void RegisterAndroidThunks(ThunkManager& manager, DynarmicHost& host) {
    auto strings = std::make_shared<AndroidStrings>();
    manager.RegisterThunk("ANativeWindow_fromSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        JNIEnv* env = FakeJniEnv::Instance().GetEnv();
        jobject surface = FakeJniEnv::Instance().ResolveObject(jit.Regs()[1]);
        jit.Regs()[0] = (env && surface) ? windows.Add(ANativeWindow_fromSurface(env, surface), true) : 0;
        if (env && surface) env->DeleteLocalRef(surface);
    });
    manager.RegisterThunk("ANativeWindow_release", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        ANativeWindow* window = windows.Release(jit.Regs()[0]);
        if (window) ANativeWindow_release(window);
    });

    manager.RegisterThunk("AAssetManager_fromJava", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        JNIEnv* env = FakeJniEnv::Instance().GetEnv();
        jobject object = FakeJniEnv::Instance().ResolveObject(jit.Regs()[1]);
        jit.Regs()[0] = (env && object) ? asset_managers.Add(AAssetManager_fromJava(env, object)) : 0;
        if (env && object) env->DeleteLocalRef(object);
    });
    manager.RegisterThunk("AAssetManager_open", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetManager* manager_ptr = asset_managers.Get(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        AAsset* asset = (manager_ptr && name) ? AAssetManager_open(manager_ptr, name, jit.Regs()[2]) : nullptr;
        jit.Regs()[0] = assets.Add(asset);
        LOGI("AAssetManager_open '%s' -> 0x%08X", name ? name : "(null)", jit.Regs()[0]);
    });
    manager.RegisterThunk("AAssetManager_openDir", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetManager* manager_ptr = asset_managers.Get(jit.Regs()[0]);
        const char* name = GuestString(host, jit.Regs()[1]);
        AAssetDir* dir = (manager_ptr && name) ? AAssetManager_openDir(manager_ptr, name) : nullptr;
        jit.Regs()[0] = asset_dirs.Add(dir);
        LOGI("AAssetManager_openDir '%s' -> 0x%08X", name ? name : "(null)", jit.Regs()[0]);
    });
    manager.RegisterThunk("AAsset_read", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        void* buffer = GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], jit.Regs()[2]);
        jit.Regs()[0] = (asset && buffer) ? static_cast<uint32_t>(AAsset_read(asset, buffer, jit.Regs()[2])) : static_cast<uint32_t>(-1);
    });
    manager.RegisterThunk("AAsset_seek", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        jit.Regs()[0] = asset ? static_cast<uint32_t>(AAsset_seek(asset, static_cast<off_t>(static_cast<int32_t>(jit.Regs()[1])), jit.Regs()[2])) : static_cast<uint32_t>(-1);
    });
    manager.RegisterThunk("AAsset_close", [strings](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        if (asset) AAsset_close(asset);
        assets.Remove(jit.Regs()[0]);
        std::lock_guard lock(strings->mutex);
        auto found=strings->buffers.find(jit.Regs()[0]);
        if(found!=strings->buffers.end()) { host.GuestFree(found->second);strings->buffers.erase(found); }
    });
    manager.RegisterThunk("AAsset_getBuffer", [strings](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const uint32_t handle=jit.Regs()[0];AAsset* asset=assets.Get(handle);
        if(!asset) { jit.Regs()[0]=0;return; }
        std::lock_guard lock(strings->mutex);
        auto found=strings->buffers.find(handle);
        if(found!=strings->buffers.end()) { jit.Regs()[0]=found->second;return; }
        const int64_t length=AAsset_getLength64(asset);const void* buffer=AAsset_getBuffer(asset);
        uint32_t guest=buffer&&length>=0&&uint64_t(length)<=UINT32_MAX?host.GuestAlloc(std::max<int64_t>(length,1)):0;
        if(guest) { memcpy(host.GetGuestMemoryBase()+guest,buffer,length);strings->buffers.emplace(handle,guest); }
        jit.Regs()[0]=guest;
    });
    manager.RegisterThunk("AAsset_isAllocated", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAsset* asset=assets.Get(jit.Regs()[0]);jit.Regs()[0]=asset?AAsset_isAllocated(asset):0;
    });
    manager.RegisterThunk("AAsset_getLength", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        jit.Regs()[0] = asset ? static_cast<uint32_t>(AAsset_getLength(asset)) : 0;
    });
    manager.RegisterThunk("AAsset_openFileDescriptor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAsset* asset = assets.Get(jit.Regs()[0]);
        if ((jit.Regs()[1] && !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[1], sizeof(uint32_t))) ||
            (jit.Regs()[2] && !GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[2], sizeof(uint32_t)))) {
            jit.Regs()[0] = static_cast<uint32_t>(-1);
            return;
        }
        off_t start = 0, length = 0;
        int fd = asset ? AAsset_openFileDescriptor(asset, &start, &length) : -1;
        if (fd >= 0 && (start > INT32_MAX || length > INT32_MAX)) {
            close(fd); host.MemoryWrite32(host.GuestErrnoAddress(), EOVERFLOW); jit.Regs()[0] = -1; return;
        }
        if (jit.Regs()[1]) host.MemoryWrite32(jit.Regs()[1], static_cast<uint32_t>(start));
        if (jit.Regs()[2]) host.MemoryWrite32(jit.Regs()[2], static_cast<uint32_t>(length));
        jit.Regs()[0] = static_cast<uint32_t>(fd);
    });
    manager.RegisterThunk("AAssetDir_getNextFileName", [strings](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetDir* dir = asset_dirs.Get(jit.Regs()[0]);
        std::lock_guard lock(strings->mutex);
        uint32_t& previous = strings->dirs[jit.Regs()[0]];
        if (previous) host.GuestFree(previous);
        previous = dir ? CopyHostString(host, AAssetDir_getNextFileName(dir)) : 0;
        jit.Regs()[0] = previous;
    });
    manager.RegisterThunk("AAssetDir_rewind", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        AAssetDir* dir = asset_dirs.Get(jit.Regs()[0]);
        if (dir) AAssetDir_rewind(dir);
    });
    manager.RegisterThunk("AAssetDir_close", [strings](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        AAssetDir* dir = asset_dirs.Get(jit.Regs()[0]);
        if (dir) AAssetDir_close(dir);
        asset_dirs.Remove(jit.Regs()[0]);
        std::lock_guard lock(strings->mutex);
        auto found = strings->dirs.find(jit.Regs()[0]);
        if(found != strings->dirs.end()) { host.GuestFree(found->second);strings->dirs.erase(found); }
    });

    manager.RegisterThunk("eglBindAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglBindAPI(jit.Regs()[0]); });
    manager.RegisterThunk("eglQueryAPI", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglQueryAPI(); });
    manager.RegisterThunk("eglGetDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = displays.Add(eglGetDisplay(EGL_DEFAULT_DISPLAY));
    });
    manager.RegisterThunk("eglInitialize", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        EGLint* major = jit.Regs()[1] ? static_cast<EGLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[1], sizeof(EGLint))) : nullptr;
        EGLint* minor = jit.Regs()[2] ? static_cast<EGLint*>(GuestSpan(host.GetGuestMemoryBase(), host.GetGuestMemorySize(), jit.Regs()[2], sizeof(EGLint))) : nullptr;
        if ((jit.Regs()[1] && !major) || (jit.Regs()[2] && !minor)) { jit.Regs()[0] = EGL_FALSE; return; }
        jit.Regs()[0] = eglInitialize(display, major, minor);
    });
    manager.RegisterThunk("eglChooseConfig", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[1]);
        const uint32_t out = jit.Regs()[2];
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[3]);
        const uint32_t count_out = host.ReadStackWord(jit, 0);
        if ((jit.Regs()[1] && !attributes) || capacity < 0 ||
            !GuestRangeValid(host.GetGuestMemorySize(), count_out, sizeof(EGLint)) ||
            (out && !GuestRangeValid(host.GetGuestMemorySize(), out, static_cast<size_t>(capacity) * sizeof(uint32_t)))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        EGLBoolean ok = eglChooseConfig(display, attributes, nullptr, 0, &count);
        if (ok && out && capacity > 0 && count > 0) {
            const EGLint limit = std::min(count, capacity);
            std::vector<EGLConfig> found(limit);
            ok = eglChooseConfig(display, attributes, found.data(), limit, &count);
            if (ok) for (EGLint i = 0; i < std::min(count, limit); ++i) host.MemoryWrite32(out + i * 4, configs.Add(found[i]));
        } else if (out && capacity == 0) {
            count = 0;
        }
        host.MemoryWrite32(count_out, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigs", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        const uint32_t out = jit.Regs()[1];
        const EGLint capacity = static_cast<EGLint>(jit.Regs()[2]);
        const uint32_t count_out = jit.Regs()[3];
        if (capacity < 0 || !GuestRangeValid(host.GetGuestMemorySize(), count_out, sizeof(EGLint)) ||
            (out && !GuestRangeValid(host.GetGuestMemorySize(), out, static_cast<size_t>(capacity) * sizeof(uint32_t)))) {
            jit.Regs()[0] = EGL_FALSE;
            return;
        }
        EGLint count = 0;
        EGLBoolean ok = eglGetConfigs(display, nullptr, 0, &count);
        if (ok && out && capacity > 0 && count > 0) {
            const EGLint limit = std::min(count, capacity);
            std::vector<EGLConfig> found(limit);
            ok = eglGetConfigs(display, found.data(), limit, &count);
            if (ok) for (EGLint i = 0; i < std::min(count, limit); ++i) host.MemoryWrite32(out + i * 4, configs.Add(found[i]));
        } else if (out && capacity == 0) {
            count = 0;
        }
        host.MemoryWrite32(count_out, static_cast<uint32_t>(count));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglGetConfigAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (!GuestRangeValid(host.GetGuestMemorySize(), jit.Regs()[3], sizeof(EGLint))) { jit.Regs()[0] = EGL_FALSE; return; }
        EGLint value = 0;
        const EGLBoolean ok = eglGetConfigAttrib(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]), jit.Regs()[2], &value);
        if (ok) host.MemoryWrite32(jit.Regs()[3], static_cast<uint32_t>(value));
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglCreateWindowSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[3]);
        if (jit.Regs()[3] && !attributes) { jit.Regs()[0] = 0; return; }
        ANativeWindow* window = windows.Get(jit.Regs()[2]);
        EGLSurface surface = eglCreateWindowSurface(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]),
            window, attributes);
        jit.Regs()[0] = surfaces.Add(surface);
        const int outgoing_errno = errno;
        if (surface != EGL_NO_SURFACE) {
            std::lock_guard lock(window_surface_lock);
            window_surfaces[surface] = window;
        }
        errno = outgoing_errno;
    });
    manager.RegisterThunk("eglCreateContext", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const EGLint* attributes = GuestEglInts(host, jit.Regs()[3]);
        if (jit.Regs()[3] && !attributes) { jit.Regs()[0] = 0; return; }
        EGLContext context = eglCreateContext(displays.Get(jit.Regs()[0]), configs.Get(jit.Regs()[1]),
            contexts.Get(jit.Regs()[2]), attributes);
        jit.Regs()[0] = contexts.Add(context);
    });
    manager.RegisterThunk("eglMakeCurrent", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        EGLSurface draw = surfaces.Get(jit.Regs()[1]);
        EGLContext context = contexts.Get(jit.Regs()[3]);
        jit.Regs()[0] = eglMakeCurrent(display, draw, surfaces.Get(jit.Regs()[2]), context);
        extern void RefreshGlBindings();
        if (jit.Regs()[0]) {
            // Track successful existing bindings; no extra EGL getter/error call.
            const int outgoing_errno = errno;
            if (current_display != display || current_draw != draw || current_context != context) {
                current_swap_interval = 0;
                GrimFramePacing::Reset();
            }
            current_display = display; current_draw = draw; current_context = context;
            errno = outgoing_errno;
            RefreshGlBindings();
        }
    });
    manager.RegisterThunk("eglSwapBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        EGLDisplay display = displays.Get(jit.Regs()[0]);
        EGLSurface surface = surfaces.Get(jit.Regs()[1]);
        const int incoming_errno = errno;
        ANativeWindow* window = nullptr;
        if (display == current_display && surface == current_draw && current_context != EGL_NO_CONTEXT) {
            std::lock_guard lock(window_surface_lock);
            const auto found = window_surfaces.find(surface);
            if (found != window_surfaces.end()) window = found->second;
        }
        // No handle/QA/registry/JIT lock survives into this cancellable wait.
        GrimFramePacing::BeforeSwap(reinterpret_cast<uintptr_t>(surface), window, current_swap_interval == 1);
        errno = incoming_errno;
        const EGLBoolean result = eglSwapBuffers(display, surface);
        const int outgoing_errno = errno;
        if (!result) GrimFramePacing::Reset();
        errno = outgoing_errno;
        jit.Regs()[0] = result;
    });
    manager.RegisterThunk("eglSwapInterval", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLDisplay display = displays.Get(jit.Regs()[0]);
        const EGLint interval = static_cast<EGLint>(jit.Regs()[1]);
        jit.Regs()[0] = eglSwapInterval(display, interval);
        if (jit.Regs()[0] && display == current_display) current_swap_interval = interval;
    });
    manager.RegisterThunk("eglDestroySurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLSurface surface = surfaces.Get(jit.Regs()[1]);
        const EGLBoolean ok = eglDestroySurface(displays.Get(jit.Regs()[0]), surface);
        const int outgoing_errno = errno;
        if (ok) {
            surfaces.Remove(jit.Regs()[1]);
            { std::lock_guard lock(window_surface_lock); window_surfaces.erase(surface); }
            GrimFramePacing::Reset();
        }
        errno = outgoing_errno;
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglDestroyContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        const EGLBoolean ok = eglDestroyContext(displays.Get(jit.Regs()[0]), contexts.Get(jit.Regs()[1]));
        const int outgoing_errno = errno;
        if (ok) { contexts.Remove(jit.Regs()[1]); GrimFramePacing::Reset(); }
        errno = outgoing_errno;
        jit.Regs()[0] = ok;
    });
    manager.RegisterThunk("eglTerminate", [](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        jit.Regs()[0] = eglTerminate(displays.Get(jit.Regs()[0]));
        if (jit.Regs()[0]) GrimFramePacing::Reset();
    });
    manager.RegisterThunk("eglWaitNative", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglWaitNative(jit.Regs()[0]); });
    manager.RegisterThunk("eglWaitGL", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglWaitGL(); });
    manager.RegisterThunk("eglReleaseThread", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglReleaseThread(); });
    manager.RegisterThunk("eglGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = eglGetError(); });
    manager.RegisterThunk("eglQueryString", [strings](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* value = eglQueryString(displays.Get(jit.Regs()[0]), jit.Regs()[1]);
        if (!value) { jit.Regs()[0] = 0; return; }
        std::lock_guard lock(strings->mutex);
        auto [it, inserted] = strings->egl.try_emplace(value, 0);
        if (inserted) it->second = CopyHostString(host, value);
        jit.Regs()[0] = it->second;
    });
    manager.RegisterThunk("eglGetCurrentDisplay", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = displays.Add(eglGetCurrentDisplay()); });
    manager.RegisterThunk("eglGetCurrentContext", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = contexts.Add(eglGetCurrentContext()); });
    manager.RegisterThunk("eglGetCurrentSurface", [](Dynarmic::A32::Jit& jit, DynarmicHost&) { jit.Regs()[0] = surfaces.Add(eglGetCurrentSurface(jit.Regs()[0])); });
    manager.RegisterThunk("eglGetProcAddress", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = GuestString(host, jit.Regs()[0]);
        jit.Regs()[0] = name ? host.GetThunkManager().ResolveSymbol(name, STT_FUNC) : 0;
    });

    RegisterAndroidExtraThunks(manager);
    LOGI("Registered Android asset/window/EGL thunks");
}

static void RegisterAndroidExtraThunks(ThunkManager& manager) {
    using Jit=Dynarmic::A32::Jit;
    using Host=DynarmicHost;
    manager.RegisterThunk("ANativeWindow_acquire",[](Jit& j,Host&) { if(auto* w=windows.Retain(j.Regs()[0]))ANativeWindow_acquire(w); });
    manager.RegisterThunk("ANativeWindow_getWidth",[](Jit& j,Host&) { auto* w=windows.Get(j.Regs()[0]);j.Regs()[0]=w?ANativeWindow_getWidth(w):0; });
    manager.RegisterThunk("ANativeWindow_getHeight",[](Jit& j,Host&) { auto* w=windows.Get(j.Regs()[0]);j.Regs()[0]=w?ANativeWindow_getHeight(w):0; });
    manager.RegisterThunk("ANativeWindow_getFormat",[](Jit& j,Host&) { auto* w=windows.Get(j.Regs()[0]);j.Regs()[0]=w?ANativeWindow_getFormat(w):0; });
    manager.RegisterThunk("ANativeWindow_setBuffersGeometry",[](Jit& j,Host&) { auto* w=windows.Get(j.Regs()[0]);j.Regs()[0]=w?ANativeWindow_setBuffersGeometry(w,j.Regs()[1],j.Regs()[2],j.Regs()[3]):-EINVAL; });
    manager.RegisterThunk("AAsset_getLength64",[](Jit& j,Host&) { auto* a=assets.Get(j.Regs()[0]);uint64_t n=a?AAsset_getLength64(a):0;j.Regs()[0]=n;j.Regs()[1]=n>>32; });
    manager.RegisterThunk("AAsset_getRemainingLength",[](Jit& j,Host&) { auto* a=assets.Get(j.Regs()[0]);j.Regs()[0]=a?AAsset_getRemainingLength(a):0; });
    manager.RegisterThunk("AAsset_getRemainingLength64",[](Jit& j,Host&) { auto* a=assets.Get(j.Regs()[0]);uint64_t n=a?AAsset_getRemainingLength64(a):0;j.Regs()[0]=n;j.Regs()[1]=n>>32; });
    manager.RegisterThunk("AAsset_seek64",[](Jit& j,Host& h) {
        Arm32CallArgs args(j,h);auto* a=assets.Get(args.Ptr());int64_t offset=args.I64();int whence=args.I32();
        uint64_t result=a?AAsset_seek64(a,offset,whence):-1;j.Regs()[0]=result;j.Regs()[1]=result>>32;
    });
    manager.RegisterThunk("AAsset_openFileDescriptor64",[](Jit& j,Host& h) {
        const uint32_t start=j.Regs()[1],length=j.Regs()[2];
        if(!GuestRangeValid(h.GetGuestMemorySize(),start,8)||!GuestRangeValid(h.GetGuestMemorySize(),length,8)) { j.Regs()[0]=-1;return; }
        auto* a=assets.Get(j.Regs()[0]);off64_t begin=0,size=0;int fd=a?AAsset_openFileDescriptor64(a,&begin,&size):-1;
        if(fd>=0) { h.MemoryWrite64(start,begin);h.MemoryWrite64(length,size); }j.Regs()[0]=fd;
    });
    manager.RegisterThunk("AConfiguration_new",[](Jit& j,Host&) { j.Regs()[0]=configurations.Add(AConfiguration_new()); });
    manager.RegisterThunk("AConfiguration_delete",[](Jit& j,Host&) { auto* c=configurations.Get(j.Regs()[0]);if(c)AConfiguration_delete(c);configurations.Remove(j.Regs()[0]); });
    manager.RegisterThunk("AConfiguration_fromAssetManager",[](Jit& j,Host&) { auto* c=configurations.Get(j.Regs()[0]);auto* a=asset_managers.Get(j.Regs()[1]);if(c&&a)AConfiguration_fromAssetManager(c,a); });
    auto getter=[&](const char* name,int32_t(*fn)(AConfiguration*)) { manager.RegisterThunk(name,[fn](Jit& j,Host&) { auto* c=configurations.Get(j.Regs()[0]);j.Regs()[0]=c?fn(c):0; }); };
    getter("AConfiguration_getDensity",AConfiguration_getDensity);getter("AConfiguration_getOrientation",AConfiguration_getOrientation);
    getter("AConfiguration_getMcc",AConfiguration_getMcc);getter("AConfiguration_getMnc",AConfiguration_getMnc);
    getter("AConfiguration_getTouchscreen",AConfiguration_getTouchscreen);getter("AConfiguration_getKeyboard",AConfiguration_getKeyboard);
    getter("AConfiguration_getKeysHidden",AConfiguration_getKeysHidden);getter("AConfiguration_getNavigation",AConfiguration_getNavigation);
    getter("AConfiguration_getNavHidden",AConfiguration_getNavHidden);getter("AConfiguration_getSdkVersion",AConfiguration_getSdkVersion);
    getter("AConfiguration_getScreenSize",AConfiguration_getScreenSize);getter("AConfiguration_getScreenLong",AConfiguration_getScreenLong);
    getter("AConfiguration_getUiModeType",AConfiguration_getUiModeType);getter("AConfiguration_getUiModeNight",AConfiguration_getUiModeNight);
    manager.RegisterThunk("AConfiguration_getLanguage",[](Jit& j,Host& h) { auto* c=configurations.Get(j.Regs()[0]);auto* out=static_cast<char*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),j.Regs()[1],2));if(c&&out)AConfiguration_getLanguage(c,out); });
    manager.RegisterThunk("AConfiguration_getCountry",[](Jit& j,Host& h) { auto* c=configurations.Get(j.Regs()[0]);auto* out=static_cast<char*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),j.Regs()[1],2));if(c&&out)AConfiguration_getCountry(c,out); });
    manager.RegisterThunk("eglCreatePbufferSurface",[](Jit& j,Host& h) { const EGLint* a=GuestEglInts(h,j.Regs()[2]);if(j.Regs()[2]&&!a) { j.Regs()[0]=0;return; }j.Regs()[0]=surfaces.Add(eglCreatePbufferSurface(displays.Get(j.Regs()[0]),configs.Get(j.Regs()[1]),a)); });
    manager.RegisterThunk("eglQuerySurface",[](Jit& j,Host& h) { auto* out=static_cast<EGLint*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),j.Regs()[3],4));j.Regs()[0]=out?eglQuerySurface(displays.Get(j.Regs()[0]),surfaces.Get(j.Regs()[1]),j.Regs()[2],out):EGL_FALSE; });
    manager.RegisterThunk("eglQueryContext",[](Jit& j,Host& h) { auto* out=static_cast<EGLint*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),j.Regs()[3],4));j.Regs()[0]=out?eglQueryContext(displays.Get(j.Regs()[0]),contexts.Get(j.Regs()[1]),j.Regs()[2],out):EGL_FALSE; });
}
