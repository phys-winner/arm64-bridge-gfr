#include <jni.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <android/native_window_jni.h>
#include "frame_pacing.h"
#include <cinttypes>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>
#include "dynarmic_host.h"
#include "elf_loader.h"
#include "thunk_manager.h"
#include "jni_fake_env.h"
#include "grim_cache.h"
#include "grim_runtime.h"
#include "grim_hooks.h"

#define LOG_TAG "GrimBridge_JNI"
#include "bridge_log.h"

namespace {
constexpr const char* kGuestLibrary = "libGrimFandango.so";
constexpr const char* kGuestAsset = "guest_libs/libGrimFandango.so";
constexpr uint32_t kGuestBase = 0x40000000;
constexpr uint32_t kGuestLimit = 0x50000000;
constexpr const char* kRequiredNatives[] = {
    "Java_com_doublefine_grimfandangoremastered_GrimFandango_grimNativeInit",
    "Java_com_doublefine_grimfandangoremastered_GrimFandango_setExternalFileDir",
    "Java_com_doublefine_grimfandangoremastered_GrimFandango_setMountedPackage",
    "Java_org_libsdl_app_SDLActivity_nativeFlipBuffers",
    "Java_org_libsdl_app_SDLActivity_nativeInit",
    "Java_org_libsdl_app_SDLActivity_nativeLowMemory",
    "Java_org_libsdl_app_SDLActivity_nativePause",
    "Java_org_libsdl_app_SDLActivity_nativeQuit",
    "Java_org_libsdl_app_SDLActivity_nativeResume",
    "Java_org_libsdl_app_SDLActivity_nativeSetMaxScreenResolution",
    "Java_org_libsdl_app_SDLActivity_nativeUpdateScaledWindowBufferSize",
    "Java_org_libsdl_app_SDLActivity_onNativeAccel",
    "Java_org_libsdl_app_SDLActivity_onNativeAxis",
    "Java_org_libsdl_app_SDLActivity_onNativeButton",
    "Java_org_libsdl_app_SDLActivity_onNativeKeyDown",
    "Java_org_libsdl_app_SDLActivity_onNativeKeyUp",
    "Java_org_libsdl_app_SDLActivity_onNativeKeyboardFocusLost",
    "Java_org_libsdl_app_SDLActivity_onNativeResize",
    "Java_org_libsdl_app_SDLActivity_onNativeSurfaceChanged",
    "Java_org_libsdl_app_SDLActivity_onNativeSurfaceDestroyed",
    "Java_org_libsdl_app_SDLActivity_onNativeTouch",
    "Java_org_libsdl_app_SDLInputConnection_nativeCommitText",
    "Java_org_libsdl_app_SDLInputConnection_nativeSetComposingText",
    "Java_com_doublefine_grimfandangoremastered_VideoSurface_nativeSetVideoSize",
};
std::recursive_mutex g_load_mutex;
enum class LoadPhase { Empty, Loading, Ready, Failed };
LoadPhase g_phase = LoadPhase::Empty;
std::string g_load_error;
std::atomic<bool> g_ready{false};
}

// These names are used by the shared thunk infrastructure.
std::unique_ptr<DynarmicHost> g_host;
JavaVM* g_jvm = nullptr;
JavaVM* GetHostJavaVM() { return g_jvm; }
std::string g_saved_apk_path;
std::string g_saved_files_dir;
extern "C" int IndexApk(const char* apk_path);

namespace {
struct LocalRef {
    JNIEnv* env;
    jobject object;
    ~LocalRef() { if (object) env->DeleteLocalRef(object); }
    LocalRef(const LocalRef&) = delete;
    LocalRef& operator=(const LocalRef&) = delete;
    LocalRef(JNIEnv* e, jobject o) : env(e), object(o) {}
};

bool CopyString(JNIEnv* env, jstring text, std::string& result) {
    if (!text || env->ExceptionCheck()) return false;
    const char* utf = env->GetStringUTFChars(text, nullptr);
    if (!utf) return false;
    result.assign(utf);
    env->ReleaseStringUTFChars(text, utf);
    return !env->ExceptionCheck();
}

jobject ApplicationContext(JNIEnv* env) {
    // CacheReader.prepare assigns this public-Context receiver before initialize.
    LocalRef cache(env, env->FindClass("com/doublefine/grimfandangoremastered/CacheReader"));
    if (!cache.object) return nullptr;
    jfieldID context = env->GetStaticFieldID(static_cast<jclass>(cache.object), "context",
                                            "Landroid/content/Context;");
    if (!context) return nullptr;
    jobject application = env->GetStaticObjectField(static_cast<jclass>(cache.object), context);
    if (application || env->ExceptionCheck()) return application;
    // Also permit direct launch of the game Activity before CacheReader.prepare.
    LocalRef thread(env, env->FindClass("android/app/ActivityThread"));
    if (!thread.object) return nullptr;
    jmethodID current = env->GetStaticMethodID(static_cast<jclass>(thread.object),
                           "currentApplication", "()Landroid/app/Application;");
    return current ? env->CallStaticObjectMethod(static_cast<jclass>(thread.object), current) : nullptr;
}

bool CaptureApplication(JNIEnv* env, LocalRef& assets, std::string& error) {
    LocalRef context(env, ApplicationContext(env));
    if (!context.object || env->ExceptionCheck()) {
        error = "Application context unavailable before guest load";
        return false;
    }
    LocalRef type(env, env->GetObjectClass(context.object));
    if (!type.object) { error = "Application class unavailable"; return false; }
    jclass cls = static_cast<jclass>(type.object);
    jmethodID get_assets = env->GetMethodID(cls, "getAssets", "()Landroid/content/res/AssetManager;");
    if (!get_assets || env->ExceptionCheck()) { error = "Application AssetManager method unavailable"; return false; }
    jmethodID get_path = env->GetMethodID(cls, "getPackageCodePath", "()Ljava/lang/String;");
    if (!get_path || env->ExceptionCheck()) { error = "Application APK path method unavailable"; return false; }
    jmethodID get_files = env->GetMethodID(cls, "getFilesDir", "()Ljava/io/File;");
    if (!get_files || env->ExceptionCheck()) {
        error = "Application files directory method unavailable";
        return false;
    }
    assets.object = env->CallObjectMethod(context.object, get_assets);
    if (!assets.object || env->ExceptionCheck()) {
        error = "Application AssetManager unavailable";
        return false;
    }
    LocalRef apk(env, env->CallObjectMethod(context.object, get_path));
    if (!CopyString(env, static_cast<jstring>(apk.object), g_saved_apk_path) ||
        g_saved_apk_path.empty()) { error = "Application APK path unavailable"; return false; }
    LocalRef files(env, env->CallObjectMethod(context.object, get_files));
    if (!files.object || env->ExceptionCheck()) { error = "Application files directory unavailable"; return false; }
    LocalRef file_type(env, env->GetObjectClass(files.object));
    if (!file_type.object) { error = "File class unavailable"; return false; }
    jmethodID absolute = env->GetMethodID(static_cast<jclass>(file_type.object),
                                         "getAbsolutePath", "()Ljava/lang/String;");
    if (!absolute || env->ExceptionCheck()) { error = "File absolute path method unavailable"; return false; }
    LocalRef directory(env, env->CallObjectMethod(files.object, absolute));
    if (!CopyString(env, static_cast<jstring>(directory.object), g_saved_files_dir)) {
        error = "Application files path unavailable";
        return false;
    }
    return true;
}

struct GuestAssetMap {
    int fd = -1;
    void* mapping = MAP_FAILED;
    size_t map_bytes = 0;
    const uint8_t* data = nullptr;
    size_t bytes = 0;
    off64_t offset = 0;
    ~GuestAssetMap() {
        if (mapping != MAP_FAILED) {
            int result = munmap(mapping, map_bytes);
            __android_log_print(result ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG,
                "guest munmap: asset=%s bytes=%zu result=%d", kGuestAsset, map_bytes, result);
        }
        if (fd >= 0) close(fd);
    }
    bool Open(AAssetManager* manager, std::string& error) {
        AAsset* asset = AAssetManager_open(manager, kGuestAsset, AASSET_MODE_RANDOM);
        if (!asset) { error = "STORED guest ELF asset is missing"; return false; }
        off64_t length = 0;
        int asset_fd = AAsset_openFileDescriptor64(asset, &offset, &length);
        AAsset_close(asset);
        if (asset_fd < 0) { error = "Guest ELF requires a directly addressable STORED asset"; return false; }
        fd = dup(asset_fd);
        const int duplicate_errno = errno;
        close(asset_fd);
        if (fd < 0) { error = std::string("Cannot duplicate guest asset FD: ") + strerror(duplicate_errno); return false; }
        struct stat st{};
        if (fstat(fd, &st) || offset < 0 || length < 52 || st.st_size < 0 ||
            static_cast<uint64_t>(offset) > static_cast<uint64_t>(st.st_size) ||
            static_cast<uint64_t>(length) > static_cast<uint64_t>(st.st_size) - static_cast<uint64_t>(offset)) {
            error = "Guest asset FD/offset/length is invalid";
            return false;
        }
        long page = sysconf(_SC_PAGESIZE);
        if (page <= 0 || (page & (page - 1))) { error = "Host page size is invalid"; return false; }
        const off64_t aligned = offset - offset % page;
        const uint64_t delta = static_cast<uint64_t>(offset - aligned);
        const uint64_t extent = static_cast<uint64_t>(length) + delta;
        if (extent < delta || extent > std::numeric_limits<size_t>::max()) {
            error = "Guest asset mmap extent overflows";
            return false;
        }
        map_bytes = static_cast<size_t>(extent);
        mapping = mmap(nullptr, map_bytes, PROT_READ, MAP_PRIVATE, fd, static_cast<off_t>(aligned));
        if (mapping == MAP_FAILED) { error = std::string("Cannot mmap guest asset: ") + strerror(errno); return false; }
        data = static_cast<const uint8_t*>(mapping) + delta;
        bytes = static_cast<size_t>(length);
        // Required lifetime receipt, emitted once even when hot-path logging is off.
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
            "guest mmap: asset=%s fd=%d offset=%" PRId64 " size=%zu -> %p",
            kGuestAsset, fd, static_cast<int64_t>(offset), bytes, static_cast<const void*>(data));
        return true;
    }
};

struct NativeScope {
    FakeJniEnv& jni = FakeJniEnv::Instance();
    bool active;
    explicit NativeScope(JNIEnv* env) : active(jni.BeginNativeCall(env)) {}
    ~NativeScope() { if (active) jni.EndNativeCall(); }
    NativeScope(const NativeScope&) = delete;
    NativeScope& operator=(const NativeScope&) = delete;
};

void ThrowBridge(JNIEnv* env, const std::string& error) {
    LOGE("%s", error.c_str());
    if (env->ExceptionCheck()) return;
    LocalRef cls(env, env->FindClass("java/lang/UnsatisfiedLinkError"));
    if (cls.object) env->ThrowNew(static_cast<jclass>(cls.object), error.c_str());
}

uint32_t GuestWord(FakeJniEnv&, jint value) { return static_cast<uint32_t>(value); }
uint32_t GuestWord(FakeJniEnv&, jboolean value) { return value ? 1u : 0u; }
uint32_t GuestWord(FakeJniEnv&, jfloat value) {
    uint32_t bits;
    static_assert(sizeof(value) == sizeof(bits));
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}
uint32_t GuestWord(FakeJniEnv& jni, jobject value) { return jni.AddObjectRef(value); }

template<bool JniArguments = true, class... Arguments>
uint32_t Invoke(JNIEnv* env, jobject receiver, const char* symbol, Arguments... values) {
    std::string error;
    if (!EnsureGrimGuest(env, error)) { ThrowBridge(env, error); return 0; }
    NativeScope frame(env);
    if (!frame.active) { ThrowBridge(env, "Guest JNI frame unavailable"); return 0; }
    const uint32_t target = g_host->FindLibrarySymbol(kGuestLibrary, symbol);
    std::vector<uint32_t> arguments;
    if constexpr (JniArguments)
        arguments = {frame.jni.EnvTableGuestAddr(), frame.jni.AddObjectRef(receiver)};
    (arguments.push_back(GuestWord(frame.jni, values)), ...);
    if (!target || frame.jni.HasFailed() || env->ExceptionCheck()) {
        ThrowBridge(env, "Guest JNI target/argument unavailable");
        return 0;
    }
    // No load/registry/host execution mutex spans SDL_main, Java or guest waits.
    const uint32_t result = g_host->RunFunction(target, arguments);
    if (g_host->HasFailed() || frame.jni.HasFailed()) {
        ThrowBridge(env, std::string("Guest native call failed: ") + symbol +
            "; host=" + g_host->FailureReason() + "; JNI=" + frame.jni.FailureReason());
    }
    return result;
}
}

DynarmicHost* GetGrimHost() {
    return g_ready.load(std::memory_order_acquire) && g_host && !g_host->HasFailed()
        && !FakeJniEnv::Instance().HasFailed()
        ? g_host.get() : nullptr;
}

bool EnsureGrimGuest(JNIEnv* env, std::string& error) {
    if (GetGrimHost()) return true;
    std::lock_guard<std::recursive_mutex> lock(g_load_mutex);
    if (g_phase == LoadPhase::Ready) {
        error = std::string("Guest runtime has failed; host=") + g_host->FailureReason() +
            "; JNI=" + FakeJniEnv::Instance().FailureReason();
        return false;
    }
    if (g_phase == LoadPhase::Failed) { error = g_load_error; return false; }
    if (g_phase == LoadPhase::Loading) { error = "Recursive guest initialization"; return false; }
    g_phase = LoadPhase::Loading;
    auto fail = [&] {
        if (error.empty()) error = "Guest initialization failed";
        g_load_error = error;
        g_phase = LoadPhase::Failed;
        // Keep a failed host alive: a constructor may already have spawned a worker.
        LOGE("%s", error.c_str());
        return false;
    };
    LocalRef assets(env, nullptr);
    if (!CaptureApplication(env, assets, error)) return fail();
    AAssetManager* manager = AAssetManager_fromJava(env, assets.object);
    if (!manager) { error = "Host AssetManager conversion failed"; return fail(); }
    GuestAssetMap image;
    if (!image.Open(manager, error)) return fail();
    g_host = std::make_unique<DynarmicHost>();
    if (!g_host->Initialize()) { error = "Dynarmic host initialization failed"; return fail(); }
    if (!g_host->RunSelfChecks()) { error = "Initial guest heap/ELF/ABI checks failed"; return fail(); }
    FakeJniEnv& jni = FakeJniEnv::Instance();
    jni.SetJavaVM(g_jvm);
    if (!jni.Init(*g_host)) { error = "Guest JNI table initialization failed"; return fail(); }
    NativeScope frame(env);
    if (!frame.active) { error = "Initial guest JNI scope unavailable"; return fail(); }
    if (IndexApk(g_saved_apk_path.c_str()) != 0) { error = "Base APK asset indexing failed"; return fail(); }
    // Only module metadata is a vector; ELF payload is the FD-backed mmap span.
    if (!g_host->LoadModulesFromMemory({{kGuestLibrary, image.data, image.bytes, kGuestBase, kGuestLimit}})) {
        error = "Guest ELF load/relocation/constructors failed";
        return fail();
    }
    for (const char* symbol : kRequiredNatives) {
        if (!g_host->FindLibrarySymbol(kGuestLibrary, symbol)) {
            error = std::string("Required guest JNI symbol absent: ") + symbol;
            return fail();
        }
    }
    uint32_t on_load = g_host->FindLibrarySymbol(kGuestLibrary, "JNI_OnLoad");
    if (!on_load) { error = "Guest JNI_OnLoad absent"; return fail(); }
    const uint32_t version = g_host->RunFunction(on_load, {jni.VmTableGuestAddr(), 0});
    if (version != JNI_VERSION_1_4 || g_host->HasFailed() || jni.HasFailed() || env->ExceptionCheck()) {
        error = "Guest JNI_OnLoad did not complete with JNI_VERSION_1_4";
        return fail();
    }
    if (!BindGrimCacheGuest(*g_host, env, error)) return fail();
    g_phase = LoadPhase::Ready;
    g_ready.store(true, std::memory_order_release);
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "guest ready: library=%s base=%08x image_bytes=%u JNI=1.4 engine_natives=24 reader=host64",
        kGuestLibrary, g_host->GetElfLoader().GetBaseAddress(), g_host->GetElfLoader().GetImageSize());
    return true;
}

bool MountGrimCache(JNIEnv* env, unsigned index, const char* root, std::string& error) {
    if (index > 1 || !root) { error = "Invalid guest cache mount"; return false; }
    if (!EnsureGrimGuest(env, error)) return false;
    NativeScope frame(env);
    if (!frame.active) { error = "Mount guest JNI frame unavailable"; return false; }
    LocalRef name(env, env->NewStringUTF(root));
    if (!name.object || env->ExceptionCheck()) { error = "Mount path allocation failed"; return false; }
    const uint32_t path = frame.jni.AddObjectRef(name.object);
    const uint32_t target = g_host->FindLibrarySymbol(kGuestLibrary,
        "Java_com_doublefine_grimfandangoremastered_GrimFandango_setMountedPackage");
    if (!target || !path || frame.jni.HasFailed()) { error = "Mount guest JNI argument unavailable"; return false; }
    // Original accepted reader passes null jclass here; the engine does not use it.
    g_host->RunFunction(target, {frame.jni.EnvTableGuestAddr(), 0, index, path});
    if (g_host->HasFailed() || frame.jni.HasFailed() || env->ExceptionCheck()) {
        error = "Guest cache mount failed";
        return false;
    }
    return true;
}

static void Native_0_grimNativeInit(JNIEnv* env, jclass receiver) {
    Invoke(env, receiver, "Java_com_doublefine_grimfandangoremastered_GrimFandango_grimNativeInit");
}

static void Native_0_setExternalFileDir(JNIEnv* env, jclass receiver, jstring a0) {
    Invoke(env, receiver, "Java_com_doublefine_grimfandangoremastered_GrimFandango_setExternalFileDir", a0);
}

static void Native_0_setMountedPackage(JNIEnv* env, jclass receiver, jint a0, jstring a1) {
    Invoke(env, receiver, "Java_com_doublefine_grimfandangoremastered_GrimFandango_setMountedPackage", a0, a1);
}

static void Native_1_nativeFlipBuffers(JNIEnv* env, jclass receiver) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativeFlipBuffers");
}

static void Native_1_nativeInit(JNIEnv* env, jclass receiver) {
    GrimFramePacing::BeginSession();
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativeInit");
    if (!env->ExceptionCheck())
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "guest SDL main returned");
}

static void Native_1_nativeLowMemory(JNIEnv* env, jclass receiver) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativeLowMemory");
}

void GrimHooksCancelBackSample();

static void Native_1_nativePause(JNIEnv* env, jclass receiver) {
    GrimFramePacing::Suspend(true);
    GrimHooksCancelBackSample();
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativePause");
}

static void Native_1_nativeQuit(JNIEnv* env, jclass receiver) {
    GrimFramePacing::Quit();
    GrimHooksCancelBackSample();
    // The original TERMINATING filter destroys Lua on the UI thread. Let
    // SDL_QUIT perform teardown on the owner, waking it before it can exit.
    std::string error;
    if (!EnsureGrimGuest(env, error)) { ThrowBridge(env, error); return; }
    // Submit once. Pending is published only after the UI queue transaction returns.
    const bool submit_quit = GrimHooksBeginQuit();
    const uint32_t resume = g_host->FindLibrarySymbol(kGuestLibrary, "Android_ResumeSem");
    if (!resume) { ThrowBridge(env, "Guest Android resume semaphore symbol absent"); return; }
    const uint32_t semaphore = g_host->MemoryRead32(resume);
    if (semaphore) {
        const uint32_t posted = Invoke<false>(env, receiver, "SDL_SemPost", static_cast<jint>(semaphore));
        if (env->ExceptionCheck()) return;
        if (posted) { ThrowBridge(env, "Guest SDL resume semaphore post failed"); return; }
    }
    // Teardown may retire the request before nativePause parks the SDL owner.
    if (!submit_quit) return;
    const uint32_t queued = Invoke<false>(env, receiver, "SDL_SendQuit");
    if (env->ExceptionCheck()) return;
    if (semaphore && queued != 1) {
        ThrowBridge(env, "Guest SDL quit event was not queued");
        return;
    }
    GrimHooksCommitQuit();
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG,
        "guest quit request: resume=%08x queued=%u", semaphore, queued);
}

static void Native_1_nativeResume(JNIEnv* env, jclass receiver) {
    GrimFramePacing::Suspend(false);
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativeResume");
}

static void Native_1_nativeSetMaxScreenResolution(JNIEnv* env, jclass receiver, jint a0, jint a1) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativeSetMaxScreenResolution", a0, a1);
}

static void Native_1_nativeUpdateScaledWindowBufferSize(JNIEnv* env, jclass receiver, jint a0, jint a1, jobject a2) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_nativeUpdateScaledWindowBufferSize", a0, a1, a2);
}

static void Native_1_onNativeAccel(JNIEnv* env, jclass receiver, jfloat a0, jfloat a1, jfloat a2) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeAccel", a0, a1, a2);
}

static void Native_1_onNativeAxis(JNIEnv* env, jclass receiver, jfloatArray a0) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeAxis", a0);
}

static void Native_1_onNativeButton(JNIEnv* env, jclass receiver, jint a0, jboolean a1) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeButton", a0, a1);
}

static void Native_1_onNativeKeyDown(JNIEnv* env, jclass receiver, jint a0) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeKeyDown", a0);
}

static void Native_1_onNativeKeyUp(JNIEnv* env, jclass receiver, jint a0) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeKeyUp", a0);
}

static void Native_1_onNativeKeyboardFocusLost(JNIEnv* env, jclass receiver) {
    GrimFramePacing::Reset();
    GrimHooksCancelBackSample();
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeKeyboardFocusLost");
}

static void Native_1_onNativeResize(JNIEnv* env, jclass receiver, jint a0, jint a1, jint a2) {
    if (a0 > 0 && a1 > 0) {
        ThunkManager::s_screenWidth = static_cast<uint32_t>(a0);
        ThunkManager::s_screenHeight = static_cast<uint32_t>(a1);
    }
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeResize", a0, a1, a2);
}

static void Native_1_onNativeSurfaceChanged(JNIEnv* env, jclass receiver) {
    GrimFramePacing::Reset();
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeSurfaceChanged");
}

static void Native_1_onNativeSurfaceDestroyed(JNIEnv* env, jclass receiver) {
    GrimFramePacing::Publish(nullptr, 0, 0, false);
    GrimHooksCancelBackSample();
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeSurfaceDestroyed");
}

static void Native_1_onNativeTouch(JNIEnv* env, jclass receiver, jint a0, jint a1, jint a2, jfloat a3, jfloat a4, jfloat a5) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLActivity_onNativeTouch", a0, a1, a2, a3, a4, a5);
}

static void Native_2_nativeCommitText(JNIEnv* env, jobject receiver, jstring a0, jint a1) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLInputConnection_nativeCommitText", a0, a1);
}

static void Native_2_nativeSetComposingText(JNIEnv* env, jobject receiver, jstring a0, jint a1) {
    Invoke(env, receiver, "Java_org_libsdl_app_SDLInputConnection_nativeSetComposingText", a0, a1);
}

static void Native_3_nativeSetVideoSize(JNIEnv* env, jclass receiver, jint a0, jint a1) {
    Invoke(env, receiver, "Java_com_doublefine_grimfandangoremastered_VideoSurface_nativeSetVideoSize", a0, a1);
}

// Bootstrap export: FindClass(CacheReader) can initialize it before its native
// table is registered. This host-only method must not initialize the guest.
extern "C" JNIEXPORT jboolean JNICALL
Java_com_doublefine_grimfandangoremastered_CacheReader_audioProofEnabled(JNIEnv* env, jclass cls) {
    return GrimCache_audioProofEnabled(env, cls);
}

static const JNINativeMethod kMethods0[] = {
    {const_cast<char*>("grimNativeInit"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_0_grimNativeInit)},
    {const_cast<char*>("setExternalFileDir"), const_cast<char*>("(Ljava/lang/String;)V"), reinterpret_cast<void*>(Native_0_setExternalFileDir)},
    {const_cast<char*>("setMountedPackage"), const_cast<char*>("(ILjava/lang/String;)V"), reinterpret_cast<void*>(Native_0_setMountedPackage)},
};

static const JNINativeMethod kMethods1[] = {
    {const_cast<char*>("nativeFlipBuffers"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_nativeFlipBuffers)},
    {const_cast<char*>("nativeInit"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_nativeInit)},
    {const_cast<char*>("nativeLowMemory"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_nativeLowMemory)},
    {const_cast<char*>("nativePause"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_nativePause)},
    {const_cast<char*>("nativeQuit"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_nativeQuit)},
    {const_cast<char*>("nativeResume"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_nativeResume)},
    {const_cast<char*>("nativeSetMaxScreenResolution"), const_cast<char*>("(II)V"), reinterpret_cast<void*>(Native_1_nativeSetMaxScreenResolution)},
    {const_cast<char*>("nativeUpdateScaledWindowBufferSize"), const_cast<char*>("(IILjava/lang/Object;)V"), reinterpret_cast<void*>(Native_1_nativeUpdateScaledWindowBufferSize)},
    {const_cast<char*>("onNativeAccel"), const_cast<char*>("(FFF)V"), reinterpret_cast<void*>(Native_1_onNativeAccel)},
    {const_cast<char*>("onNativeAxis"), const_cast<char*>("([F)V"), reinterpret_cast<void*>(Native_1_onNativeAxis)},
    {const_cast<char*>("onNativeButton"), const_cast<char*>("(IZ)V"), reinterpret_cast<void*>(Native_1_onNativeButton)},
    {const_cast<char*>("onNativeKeyDown"), const_cast<char*>("(I)V"), reinterpret_cast<void*>(Native_1_onNativeKeyDown)},
    {const_cast<char*>("onNativeKeyUp"), const_cast<char*>("(I)V"), reinterpret_cast<void*>(Native_1_onNativeKeyUp)},
    {const_cast<char*>("onNativeKeyboardFocusLost"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_onNativeKeyboardFocusLost)},
    {const_cast<char*>("onNativeResize"), const_cast<char*>("(III)V"), reinterpret_cast<void*>(Native_1_onNativeResize)},
    {const_cast<char*>("onNativeSurfaceChanged"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_onNativeSurfaceChanged)},
    {const_cast<char*>("onNativeSurfaceDestroyed"), const_cast<char*>("()V"), reinterpret_cast<void*>(Native_1_onNativeSurfaceDestroyed)},
    {const_cast<char*>("onNativeTouch"), const_cast<char*>("(IIIFFF)V"), reinterpret_cast<void*>(Native_1_onNativeTouch)},
};

static const JNINativeMethod kMethods2[] = {
    {const_cast<char*>("nativeCommitText"), const_cast<char*>("(Ljava/lang/String;I)V"), reinterpret_cast<void*>(Native_2_nativeCommitText)},
    {const_cast<char*>("nativeSetComposingText"), const_cast<char*>("(Ljava/lang/String;I)V"), reinterpret_cast<void*>(Native_2_nativeSetComposingText)},
};

static const JNINativeMethod kMethods3[] = {
    {const_cast<char*>("nativeSetVideoSize"), const_cast<char*>("(II)V"), reinterpret_cast<void*>(Native_3_nativeSetVideoSize)},
};

static jint FramePacingState(JNIEnv*, jclass) {
    return GrimFramePacing::PolicyState();
}
static void PublishFrameDisplay(JNIEnv* env, jclass, jobject surface, jfloat hz, jint mode, jboolean ready) {
    const int incoming_errno = errno;
    ANativeWindow* window = ready && surface ? ANativeWindow_fromSurface(env, surface) : nullptr;
    GrimFramePacing::Publish(window, hz, mode, ready && !env->ExceptionCheck());
    errno = incoming_errno;
}

static const JNINativeMethod kMethods4[] = {
    {const_cast<char*>("framePacingState"), const_cast<char*>("()I"), reinterpret_cast<void*>(FramePacingState)},
    {const_cast<char*>("publishFrameDisplay"), const_cast<char*>("(Landroid/view/Surface;FIZ)V"), reinterpret_cast<void*>(PublishFrameDisplay)},
    {const_cast<char*>("audioAccepted"), const_cast<char*>("(IIII)V"), reinterpret_cast<void*>(GrimCache_audioAccepted)},
    {const_cast<char*>("audioProofEnabled"), const_cast<char*>("()Z"), reinterpret_cast<void*>(Java_com_doublefine_grimfandangoremastered_CacheReader_audioProofEnabled)},
    {const_cast<char*>("configureRussian"), const_cast<char*>("(ZZ)V"), reinterpret_cast<void*>(GrimCache_configureRussian)},
    {const_cast<char*>("configureLanguage"), const_cast<char*>("(I)V"), reinterpret_cast<void*>(GrimCache_configureLanguage)},
    {const_cast<char*>("languageSaved"), const_cast<char*>("(JZ)V"), reinterpret_cast<void*>(GrimCache_languageSaved)},
    {const_cast<char*>("configureSurfaceGeometry"), const_cast<char*>("(Landroid/view/Surface;II)I"), reinterpret_cast<void*>(GrimCache_configureSurfaceGeometry)},
    {const_cast<char*>("initialize"), const_cast<char*>("(Landroid/content/res/AssetManager;[Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;"), reinterpret_cast<void*>(GrimCache_initialize)},
    {const_cast<char*>("onTouch"), const_cast<char*>("(IIIFFF)V"), reinterpret_cast<void*>(GrimCache_onTouch)},
    {const_cast<char*>("pauseQa"), const_cast<char*>("()V"), reinterpret_cast<void*>(GrimCache_pauseQa)},
    {const_cast<char*>("qaCommand"), const_cast<char*>("(IJLjava/lang/String;)J"), reinterpret_cast<void*>(GrimCache_qaCommand)},
    {const_cast<char*>("qaState"), const_cast<char*>("()[Ljava/lang/String;"), reinterpret_cast<void*>(GrimCache_qaState)},
    {const_cast<char*>("resetInput"), const_cast<char*>("()V"), reinterpret_cast<void*>(GrimCache_resetInput)},
    {const_cast<char*>("selfCheck"), const_cast<char*>("()Ljava/lang/String;"), reinterpret_cast<void*>(GrimCache_selfCheck)},
    {const_cast<char*>("setVideoSource"), const_cast<char*>("(Landroid/media/MediaPlayer;Ljava/lang/String;)V"), reinterpret_cast<void*>(GrimCache_setVideoSource)},
};

namespace {
struct NativeTable {
    const char* class_name;
    const JNINativeMethod* methods;
    jint count;
};
const NativeTable kTables[] = {
    {"com/doublefine/grimfandangoremastered/GrimFandango", kMethods0, static_cast<jint>(sizeof(kMethods0) / sizeof(kMethods0[0]))},
    {"org/libsdl/app/SDLActivity", kMethods1, static_cast<jint>(sizeof(kMethods1) / sizeof(kMethods1[0]))},
    {"org/libsdl/app/SDLInputConnection", kMethods2, static_cast<jint>(sizeof(kMethods2) / sizeof(kMethods2[0]))},
    {"com/doublefine/grimfandangoremastered/VideoSurface", kMethods3, static_cast<jint>(sizeof(kMethods3) / sizeof(kMethods3[0]))},
    {"com/doublefine/grimfandangoremastered/CacheReader", kMethods4, static_cast<jint>(sizeof(kMethods4) / sizeof(kMethods4[0]))},
};
static_assert(sizeof(kMethods0) / sizeof(kMethods0[0]) == 3);
static_assert(sizeof(kMethods1) / sizeof(kMethods1[0]) == 18);
static_assert(sizeof(kMethods2) / sizeof(kMethods2[0]) == 2);
static_assert(sizeof(kMethods3) / sizeof(kMethods3[0]) == 1);
static_assert(sizeof(kMethods4) / sizeof(kMethods4[0]) == 16);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    JNIEnv* env = nullptr;
    if (!vm || vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    FakeJniEnv::Instance().SetJavaVM(vm);
    // Resolve/register in this order. CacheReader is last and has the explicit
    // bootstrap export above; every table uses the packaged exact descriptor.
    jclass classes[5]{};
    size_t registered = 0;
    for (size_t i = 0; i < 5; ++i) {
        classes[i] = env->FindClass(kTables[i].class_name);
        if (!classes[i] || env->ExceptionCheck()) break;
        if (i == 0 && !FakeJniEnv::Instance().CacheClassLoader(env, classes[i])) break;
        if (env->RegisterNatives(classes[i], kTables[i].methods, kTables[i].count) != JNI_OK ||
            env->ExceptionCheck()) break;
        ++registered;
    }
    const bool complete = registered == 5;
    if (!complete) {
        LOGE("Native registration failed after %zu/5 classes", registered);
        // Preserve the original Java failure while rolling back all registered tables.
        jthrowable failure = env->ExceptionOccurred();
        if (failure) env->ExceptionClear();
        for (size_t i = 0; i < registered; ++i) {
            if (env->UnregisterNatives(classes[i]) != JNI_OK) LOGE("Native rollback failed: %s", kTables[i].class_name);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (failure) { env->Throw(failure); env->DeleteLocalRef(failure); }
    }
    for (jclass cls : classes) if (cls) env->DeleteLocalRef(cls);
    if (!complete) return JNI_ERR;
    __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "host JNI registered: 40 methods, 5 classes, engine24+reader16");
    return JNI_VERSION_1_6;
}
