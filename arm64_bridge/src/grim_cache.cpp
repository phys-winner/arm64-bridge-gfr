// Host64 port of the immutable dbb67094 direct OBB reader's VFS.
// ZIP/source/lookup/cookie algorithms retain their ARM32 logical limits.
#include "grim_cache.h"
#include "grim_hooks.h"
#include "grim_runtime.h"
#include "dynarmic_host.h"
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/native_window_jni.h>
#include <android/log.h>
#include <cerrno>
#include <climits>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <atomic>
#include <algorithm>
#include "grim_cache_index.h"
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "GrimCache", __VA_ARGS__)
namespace {
std::atomic<DynarmicHost*> guest{nullptr};
typedef struct { int fd; uint64_t start, length; } Source;
static Source sources[COUNT(cache_specs)];
static unsigned main_source, patch_source = 1;
static int legacy_cache;
static AAssetManager *manager;
static int ready, text_enabled, voice_enabled, configured;
static int language_selection = -1;
static int (*get_language)(void);
static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t crc_table[256];
static char init_error[256];
static FILE *(*real_fopen)(const char *, const char *);
static int (*real_stat)(const char *, struct stat *);
static DIR *(*real_opendir)(const char *);
static struct dirent *(*real_readdir)(DIR *);
static int (*real_closedir)(DIR *);

static int read_exact(int fd, void *buffer, size_t length, uint64_t offset) {
    size_t done = 0;
    while (done < length) {
        ssize_t got = pread64(fd, (char *)buffer + done, length - done, (off64_t)(offset + done));
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) { if (!got) errno = EIO; return -1; }
        done += (size_t)got;
    }
    return 0;
}
/* Bounded ZIP32 directory lookup for signed STORED APK assets; no payload mmap. */
static uint16_t zip16(const unsigned char *p) {
    return (uint16_t)((unsigned)p[0] | (unsigned)p[1] << 8);
}
static uint32_t zip32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static int zip_error(char *error, size_t capacity, const char *message) {
    snprintf(error, capacity, "%s", message);
    return -1;
}

/* Returns 1 for the exact entry, 0 for absent, -1 for malformed/unsupported ZIP. */
static int zip_asset_range(int fd, uint64_t file_size, const char *name,
        uint64_t *start, uint64_t *length, char *error, size_t capacity) {
    if (file_size < 22 || file_size > UINT32_MAX)
        return zip_error(error, capacity, "APK ZIP32 size invalid (ZIP64 unsupported)");
    size_t tail_length = file_size < 65557 ? (size_t)file_size : 65557;
    unsigned char *tail = static_cast<unsigned char *>(malloc(tail_length));
    if (!tail) return zip_error(error, capacity, "Cannot allocate APK directory buffer");
    if (read_exact(fd, tail, tail_length, file_size - tail_length)) {
        free(tail);
        return zip_error(error, capacity, "Cannot read APK ZIP end record");
    }
    size_t eocd = SIZE_MAX;
    for (size_t p = tail_length - 22;; p--) {
        if (zip32(tail + p) == 0x06054b50 && p + 22 + zip16(tail + p + 20) == tail_length) {
            eocd = p;
            break;
        }
        if (!p) break;
    }
    if (eocd == SIZE_MAX) {
        free(tail);
        return zip_error(error, capacity, "APK ZIP end record absent");
    }
    const unsigned char *end = tail + eocd;
    unsigned entries = zip16(end + 10);
    uint64_t directory_size = zip32(end + 12), directory_start = zip32(end + 16);
    uint64_t end_offset = file_size - tail_length + eocd;
    int zip64 = entries == UINT16_MAX || directory_size == UINT32_MAX || directory_start == UINT32_MAX;
    int disks = zip16(end + 4) || zip16(end + 6) || zip16(end + 8) != entries;
    free(tail);
    if (zip64) return zip_error(error, capacity, "APK ZIP64 unsupported");
    if (disks || directory_start > end_offset || directory_size > end_offset - directory_start)
        return zip_error(error, capacity, "APK ZIP directory range invalid");
    uint64_t cursor = directory_start, directory_end = directory_start + directory_size;
    size_t wanted_length = strlen(name);
    int found = 0;
    for (unsigned n = 0; n < entries; n++) {
        unsigned char central[46];
        if (cursor > directory_end || sizeof(central) > directory_end - cursor
                || read_exact(fd, central, sizeof(central), cursor) || zip32(central) != 0x02014b50)
            return zip_error(error, capacity, "APK ZIP central header invalid");
        unsigned name_length = zip16(central + 28), extra_length = zip16(central + 30), comment_length = zip16(central + 32);
        uint64_t record_size = sizeof(central) + name_length + extra_length + comment_length;
        if (record_size > directory_end - cursor)
            return zip_error(error, capacity, "APK ZIP central record exceeds directory");
        if (name_length == wanted_length) {
            char entry_name[192];
            if (name_length >= sizeof(entry_name))
                return zip_error(error, capacity, "APK OBB entry name too long");
            if (read_exact(fd, entry_name, name_length, cursor + sizeof(central)))
                return zip_error(error, capacity, "Cannot read APK ZIP entry name");
            if (!memcmp(entry_name, name, name_length)) {
                if (found) return zip_error(error, capacity, "Duplicate APK OBB entry");
                unsigned flags = zip16(central + 8), method = zip16(central + 10);
                uint64_t packed = zip32(central + 20), plain = zip32(central + 24), local_offset = zip32(central + 42);
                if (packed == UINT32_MAX || plain == UINT32_MAX || local_offset == UINT32_MAX)
                    return zip_error(error, capacity, "APK ZIP64 OBB entry unsupported");
                if (flags & (1U | 64U)) return zip_error(error, capacity, "Encrypted APK OBB entry unsupported");
                if (method || packed != plain) return zip_error(error, capacity, "APK OBB entry must be STORED");
                if (zip16(central + 34)) return zip_error(error, capacity, "Multi-disk APK OBB entry unsupported");
                unsigned char local[30];
                if (local_offset > directory_start || sizeof(local) > directory_start - local_offset
                        || read_exact(fd, local, sizeof(local), local_offset) || zip32(local) != 0x04034b50)
                    return zip_error(error, capacity, "APK ZIP local header invalid");
                unsigned local_name_length = zip16(local + 26), local_extra_length = zip16(local + 28);
                if (zip16(local + 6) != flags || zip16(local + 8) != method || local_name_length != name_length)
                    return zip_error(error, capacity, "APK ZIP local/central header mismatch");
                uint64_t payload = local_offset + sizeof(local) + local_name_length + local_extra_length;
                if (payload > directory_start || packed > directory_start - payload
                        || read_exact(fd, entry_name, name_length, local_offset + sizeof(local))
                        || memcmp(entry_name, name, name_length))
                    return zip_error(error, capacity, "APK OBB payload range/name invalid");
                if (!(flags & 8U) && (zip32(local + 14) != zip32(central + 16)
                        || zip32(local + 18) != packed || zip32(local + 22) != plain))
                    return zip_error(error, capacity, "APK ZIP local/central size or CRC mismatch");
                *start = payload;
                *length = plain;
                found = 1;
            }
        }
        cursor += record_size;
    }
    if (cursor != directory_end) return zip_error(error, capacity, "APK ZIP directory length mismatch");
    return found;
}


static int valid_source(Source source, unsigned index) {
    const CacheSpec *spec = &cache_specs[index];
    if (source.length != spec->size) return 0;
    char buffer[65536];
    for (unsigned i = spec->first; i < spec->first + spec->count; i++) {
        const CacheCheck *check = &cache_checks[i];
        if (check->offset > source.length || check->length > source.length - check->offset) return 0;
        uint32_t crc = 0xffffffffU;
        for (uint64_t pos = 0; pos < check->length;) {
            size_t amount = check->length - pos < sizeof(buffer) ? (size_t)(check->length - pos) : sizeof(buffer);
            if (read_exact(source.fd, buffer, amount, source.start + check->offset + pos)) return 0;
            for (size_t n = 0; n < amount; n++) crc = crc_table[(crc ^ (unsigned char)buffer[n]) & 255] ^ (crc >> 8);
            pos += amount;
        }
        if ((crc ^ 0xffffffffU) != check->crc) return 0;
    }
    return 1;
}

static Source embedded_source(JNIEnv *env, jobjectArray apk_paths, unsigned index) {
    Source source = {-1,0,0};
    if (!apk_paths) return source;
    char name[192];
    int name_length = snprintf(name, sizeof(name), "assets/%s", cache_specs[index].asset);
    if (name_length < 0 || name_length >= (int)sizeof(name)) {
        snprintf(init_error, sizeof(init_error), "OBB ZIP asset name too long");
        return source;
    }
    jsize count = env->GetArrayLength(apk_paths);
    for (jsize n = 0; n < count; n++) {
        jstring path = static_cast<jstring>(env->GetObjectArrayElement(apk_paths, n));
        if (!path) { if (env->ExceptionCheck()) return source; continue; }
        const char *filename = env->GetStringUTFChars(path, NULL);
        if (!filename) { env->DeleteLocalRef(path); return source; }
        int fd = open(filename, O_RDONLY | O_CLOEXEC);
        struct stat st;
        int found = 0;
        if (fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size >= 0)
            found = zip_asset_range(fd, (uint64_t)st.st_size, name, &source.start, &source.length, init_error, sizeof(init_error));
        if (found == 1) {
            source.fd = fd;
            LOG("APK container file=%s apk=%s offset=%llu bytes=%llu payload_mmap=0", name, filename,
                (unsigned long long)source.start, (unsigned long long)source.length);
        } else if (fd >= 0) close(fd);
        env->ReleaseStringUTFChars(path, filename);
        env->DeleteLocalRef(path);
        if (found) return source;
    }
    return source;
}

static Source external_source(JNIEnv *env, jobjectArray directories, unsigned index) {
    Source source = {-1,0,0};
    if (!directories) return source;
    jsize count = env->GetArrayLength(directories);
    for (jsize n = 0; n < count; n++) {
        jstring path = static_cast<jstring>(env->GetObjectArrayElement(directories, n));
        if (!path) { if (env->ExceptionCheck()) return source; continue; }
        const char *directory = env->GetStringUTFChars(path, NULL);
        if (!directory) { env->DeleteLocalRef(path); return source; }
        char filename[PATH_MAX];
        int length = snprintf(filename, sizeof(filename), "%s/%s", directory, cache_specs[index].external);
        env->ReleaseStringUTFChars(path, directory);
        env->DeleteLocalRef(path);
        if (length < 0 || length >= (int)sizeof(filename)) continue;
        int fd = open(filename, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) { close(fd); continue; }
        source.fd = fd;
        source.length = (uint64_t)st.st_size;
        return source;
    }
    return source;
}

/* Only immutable resource roots participate; saves and unrelated paths use libc. */
static int resource_name(const char *path, char *name, size_t capacity) {
    if (!path) return 0;
    std::string root = GrimGuestExternalRoot();
    const char* external_root = root.c_str();
    const char *part = path;
    if (!strncmp(path, "/cache/main", 11) && (path[11] == '/' || !path[11])) part = path + 11;
    else if (!strncmp(path, "/cache/patch", 12) && (path[12] == '/' || !path[12])) part = path + 12;
    else if (path[0] == '/') {
        size_t root_length = external_root ? strlen(external_root) : 0;
        if (!root_length || strncmp(path, external_root, root_length)
                || (path[root_length] && path[root_length] != '/')) return 0;
        part = path + root_length;
    }
    while (*part == '/') part++;
    size_t length = strlen(part);
    if (length >= capacity || strstr(part, "../") || strstr(part, "..\\") || !strcmp(part, "..")) return 0;
    for (size_t n = 0; n <= length; n++) {
        char c = part[n];
        name[n] = c == '\\' ? '/' : c >= 'A' && c <= 'Z' ? (char)(c + 'a' - 'A') : c;
    }
    while (length && name[length - 1] == '/') name[--length] = 0;
    return 1;
}

static int original_voice_source(void) {
    int language = get_language ? get_language() : 0;
    return !legacy_cache && language > 0 && language < (int)COUNT(cache_voice_sources)
           ? cache_voice_sources[language] : -1;
}

static int voice_lab(const CacheEntry *entry) {
    size_t length = strlen(entry->name);
    return entry->source >= 4 && entry->source < CACHE_ORIGINAL_MAIN
           && length > 4 && !strcmp(entry->name + length - 4, ".lab");
}

static const CacheEntry *entry_from_source(const char *name, int source) {
    if (source < 0 || (unsigned)source >= COUNT(sources) || sources[source].fd < 0) return NULL;
    for (unsigned n = 0; n < COUNT(cache_entries); n++)
        if (cache_entries[n].source == (unsigned)source && !strcmp(name, cache_entries[n].name)) return &cache_entries[n];
    return NULL;
}

static const CacheEntry *find_entry(const char *name) {
    int english = !get_language || get_language() == 0;
    const int order[] = {original_voice_source(), english && voice_enabled ? 3 : -1,
                         english && text_enabled ? 2 : -1, (int)patch_source, (int)main_source};
    for (unsigned n = 0; n < COUNT(order); n++) {
        const CacheEntry *entry = entry_from_source(name, order[n]);
        if (entry) return entry;
    }
    // Explicit bank opens and self-checks can inspect every installed voice pack.
    // Directory discovery exposes only the language initialized by Main_Startup.
    if (!legacy_cache) for (unsigned n = 0; n < COUNT(cache_entries); n++) {
        const CacheEntry *entry = &cache_entries[n];
        if (voice_lab(entry) && sources[entry->source].fd >= 0 && !strcmp(name, entry->name)) return entry;
    }
    return NULL;
}

static int mounted_entry(unsigned source, const CacheEntry *entry) {
    return sources[entry->source].fd >= 0 && (entry->source == source
           || (source == main_source && voice_lab(entry)
               && (int)entry->source == original_voice_source()));
}

static const char *base_asset(const char *name) {
    for (unsigned n = 0; n < COUNT(cache_base_assets); n++)
        if (!strcasecmp(cache_base_assets[n], name)) return cache_base_assets[n];
    return NULL;
}

typedef struct { Source source; AAsset *asset; uint64_t start, length; int64_t cursor; } FileCookie;
static int cookie_read(void *opaque, char *buffer, int amount) {
    FileCookie *cookie = static_cast<FileCookie *>(opaque);
    if (cookie->cursor < 0 || (uint64_t)cookie->cursor >= cookie->length) return 0;
    if ((uint64_t)amount > cookie->length - (uint64_t)cookie->cursor) amount = (int)(cookie->length - (uint64_t)cookie->cursor);
    int got;
    if (cookie->asset) got = AAsset_read(cookie->asset, buffer, (size_t)amount);
    else {
        ssize_t result;
        do { result = pread64(cookie->source.fd, buffer, (size_t)amount,
                     (off64_t)(cookie->source.start + cookie->start + (uint64_t)cookie->cursor)); }
        while (result < 0 && errno == EINTR);
        got = (int)result;
        if (!got && amount) { errno = EIO; return -1; }
    }
    if (got > 0) cookie->cursor += got;
    return got;
}

static fpos_t cookie_seek(void *opaque, fpos_t offset, int whence) {
    FileCookie *cookie = static_cast<FileCookie *>(opaque);
    int64_t base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? cookie->cursor : whence == SEEK_END ? (int64_t)cookie->length : -1;
    if (base < 0 || (int64_t)offset < -base || (int64_t)offset > INT32_MAX - base) { errno = EINVAL; return -1; }
    int64_t position = base + (int64_t)offset;
    if (cookie->asset && AAsset_seek64(cookie->asset, (off64_t)position, SEEK_SET) < 0) return -1;
    cookie->cursor = position;
    return (fpos_t)position;
}

static int cookie_close(void *opaque) {
    FileCookie *cookie = static_cast<FileCookie *>(opaque);
    if (cookie->asset) AAsset_close(cookie->asset);
    free(cookie);
    return 0;
}

static FILE *cache_fopen(const char *path, const char *mode) {
    if (!ready || !mode || mode[0] != 'r' || strchr(mode, '+')) return real_fopen(path, mode);
    char name[PATH_MAX];
    if (!resource_name(path, name, sizeof(name))) return real_fopen(path, mode);
    const CacheEntry *entry = find_entry(name);
    const char *asset_name = entry ? NULL : base_asset(name);
    if (!entry && !asset_name) return real_fopen(path, mode);
    FileCookie *cookie = static_cast<FileCookie *>(calloc(1, sizeof(*cookie)));
    if (!cookie) return NULL;
    if (entry) {
        cookie->source = sources[entry->source];
        cookie->start = entry->offset;
        cookie->length = entry->size;
        if (entry->offset > cookie->source.length || entry->size > cookie->source.length - entry->offset) { free(cookie); errno = EIO; return NULL; }
    } else {
        cookie->asset = AAssetManager_open(manager, asset_name, AASSET_MODE_RANDOM);
        if (!cookie->asset) { free(cookie); errno = ENOENT; return NULL; }
        cookie->length = (uint64_t)AAsset_getLength64(cookie->asset);
    }
    if (cookie->length > INT32_MAX) { cookie_close(cookie); errno = EOVERFLOW; return NULL; }
    FILE *fp = funopen(cookie, cookie_read, NULL, cookie_seek, cookie_close);
    if (!fp) cookie_close(cookie);
    return fp;
}

static int known_directory(const char *name) {
    if (!name[0]) return 1;
    size_t length = strlen(name);
    for (unsigned n = 0; n < COUNT(cache_entries); n++)
        if (sources[cache_entries[n].source].fd >= 0 && !strncmp(name, cache_entries[n].name, length) && cache_entries[n].name[length] == '/') return 1;
    for (unsigned n = 0; n < COUNT(cache_base_assets); n++)
        if (!strncasecmp(name, cache_base_assets[n], length) && cache_base_assets[n][length] == '/') return 1;
    return 0;
}

static int cache_stat(const char *path, struct stat *st) {
    char name[PATH_MAX];
    if (!ready || !resource_name(path, name, sizeof(name))) return real_stat(path, st);
    const CacheEntry *entry = find_entry(name);
    const char *asset_name = entry ? NULL : base_asset(name);
    uint64_t size = entry ? entry->size : 0;
    if (asset_name) {
        AAsset *asset = AAssetManager_open(manager, asset_name, AASSET_MODE_RANDOM);
        if (!asset) { errno = ENOENT; return -1; }
        size = (uint64_t)AAsset_getLength64(asset);
        AAsset_close(asset);
    }
    int directory = !entry && !asset_name && known_directory(name);
    if (!entry && !asset_name && !directory) return real_stat(path, st);
    memset(st, 0, sizeof(*st));
    st->st_mode = directory ? S_IFDIR | 0555 : S_IFREG | 0444;
    st->st_size = (off64_t)size;
    st->st_nlink = 1;
    st->st_blksize = 4096;
    st->st_blocks = (size + 511) / 512;
    return 0;
}

typedef struct VirtualDir {
    struct VirtualDir *next;
    unsigned cursor, count, capacity;
    char **names;
    unsigned char *types;
    struct dirent result;
} VirtualDir;
static VirtualDir *directories;
static pthread_mutex_t directory_lock = PTHREAD_MUTEX_INITIALIZER;

static int dir_add(VirtualDir *dir, const char *file, const char *prefix) {
    size_t prefix_length = strlen(prefix);
    if (prefix_length && (strncasecmp(file, prefix, prefix_length) || file[prefix_length] != '/')) return 0;
    const char *child = file + prefix_length + (prefix_length ? 1 : 0);
    const char *slash = strchr(child, '/');
    size_t length = slash ? (size_t)(slash - child) : strlen(child);
    if (!length || length > 255) return 0;
    for (unsigned n = 0; n < dir->count; n++)
        if (strlen(dir->names[n]) == length && !strncasecmp(dir->names[n], child, length)) return 0;
    if (dir->count == dir->capacity) {
        unsigned capacity = dir->capacity ? dir->capacity * 2 : 32;
        if (capacity > 65536) { errno = EOVERFLOW; return -1; }
        char **names = static_cast<char **>(realloc(dir->names, capacity * sizeof(char *)));
        if (!names) return -1;
        dir->names = names;
        unsigned char *types = static_cast<unsigned char *>(realloc(dir->types, capacity));
        if (!types) return -1;
        dir->types = types;
        dir->capacity = capacity;
    }
    char *name = strndup(child, length);
    if (!name) return -1;
    dir->names[dir->count] = name;
    dir->types[dir->count++] = slash ? DT_DIR : DT_REG;
    return 0;
}

static int free_directory(VirtualDir *dir) {
    for (unsigned n = 0; n < dir->count; n++) free(dir->names[n]);
    free(dir->names);
    free(dir->types);
    free(dir);
    return 0;
}

static DIR *cache_opendir(const char *path) {
    char name[PATH_MAX];
    if (!ready || !resource_name(path, name, sizeof(name)) || !known_directory(name)) return real_opendir(path);
    VirtualDir *dir = static_cast<VirtualDir *>(calloc(1, sizeof(*dir)));
    if (!dir) return NULL;
    int source = !strncmp(path, "/cache/main", 11) ? (int)main_source
                 : !strncmp(path, "/cache/patch", 12) ? (int)patch_source : -1;
    for (unsigned n = 0; n < COUNT(cache_entries); n++) {
        const CacheEntry *entry = &cache_entries[n];
        if (voice_lab(entry) && (int)entry->source != original_voice_source()) continue;
        if (sources[entry->source].fd < 0 || (source >= 0 && !mounted_entry((unsigned)source, entry))) continue;
        if (dir_add(dir, entry->name, name)) { free_directory(dir); return NULL; }
    }
    if (source < 0) for (unsigned n = 0; n < COUNT(cache_base_assets); n++)
        if (dir_add(dir, cache_base_assets[n], name)) { free_directory(dir); return NULL; }
    if (source < 0) {
        DIR *actual = real_opendir(path);
        if (actual) {
            struct dirent *entry;
            while ((entry = real_readdir(actual))) {
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                unsigned before = dir->count;
                if (dir_add(dir, entry->d_name, "")) { real_closedir(actual); free_directory(dir); return NULL; }
                if (dir->count > before) dir->types[dir->count - 1] = entry->d_type;
            }
            real_closedir(actual);
        }
    }
    pthread_mutex_lock(&directory_lock);
    dir->next = directories;
    directories = dir;
    pthread_mutex_unlock(&directory_lock);
    return (DIR *)dir;
}

static struct dirent *cache_readdir(DIR *handle) {
    pthread_mutex_lock(&directory_lock);
    VirtualDir *dir = directories;
    while (dir && (DIR *)dir != handle) dir = dir->next;
    if (!dir) { pthread_mutex_unlock(&directory_lock); return real_readdir(handle); }
    struct dirent *result = NULL;
    if (dir->cursor < dir->count) {
        memset(&dir->result, 0, sizeof(dir->result));
        dir->result.d_ino = dir->cursor + 1;
        dir->result.d_type = dir->types[dir->cursor];
        dir->result.d_reclen = sizeof(dir->result);
        strcpy(dir->result.d_name, dir->names[dir->cursor++]);
        result = &dir->result;
    }
    pthread_mutex_unlock(&directory_lock);
    return result;
}

static int cache_closedir(DIR *handle) {
    pthread_mutex_lock(&directory_lock);
    VirtualDir **link = &directories;
    while (*link && (DIR *)*link != handle) link = &(*link)->next;
    VirtualDir *dir = *link;
    if (dir) *link = dir->next;
    pthread_mutex_unlock(&directory_lock);
    return dir ? free_directory(dir) : real_closedir(handle);
}

int russian_locale(JNIEnv* env) {
    jclass cls = env->FindClass("java/util/Locale");
    if (!cls) return 0;
    jmethodID get_default = env->GetStaticMethodID(cls,"getDefault","()Ljava/util/Locale;");
    jmethodID language_id = !env->ExceptionCheck() ? env->GetMethodID(cls,"getLanguage","()Ljava/lang/String;") : nullptr;
    jobject locale = get_default && !env->ExceptionCheck() ? env->CallStaticObjectMethod(cls,get_default) : nullptr;
    jstring language = locale && language_id && !env->ExceptionCheck() ? static_cast<jstring>(env->CallObjectMethod(locale,language_id)) : nullptr;
    const char* value = language && !env->ExceptionCheck() ? env->GetStringUTFChars(language,nullptr) : nullptr;
    int answer = value && !strcmp(value,"ru");
    if (value) env->ReleaseStringUTFChars(language,value);
    if (language) env->DeleteLocalRef(language);
    if (locale) env->DeleteLocalRef(locale);
    env->DeleteLocalRef(cls);
    return answer;
}
void CloseSources() {
    for (Source& source : sources) {
        if (source.fd >= 0) close(source.fd);
        source = Source{-1,0,0};
    }
}
}

bool BindGrimCacheGuest(DynarmicHost& host, JNIEnv*, std::string& error) {
    if (!host.FindModule("libGrimFandango.so") || !host.FindLibrarySymbol("libGrimFandango.so","zg_GetLanguage")) {
        error = "Original engine module/language binding missing"; return false;
    }
    DynarmicHost* current = guest.load(std::memory_order_acquire);
    if (current && current != &host) { error = "Cache is already bound to a different guest"; return false; }
    guest.store(&host,std::memory_order_release);
    return true;
}
bool GrimCacheReady() { return ready != 0; }
bool GrimCacheLegacy() { return legacy_cache != 0; }
bool GrimCacheSourcePresent(unsigned source) { return ready && source < COUNT(sources) && sources[source].fd >= 0; }
bool GrimCacheRussianText() { return text_enabled && GrimCacheSourcePresent(2); }
int GrimCacheLanguageSelection() {
    if (language_selection >= 0) return language_selection;
    return (text_enabled && GrimCacheSourcePresent(2)) || (voice_enabled && GrimCacheSourcePresent(3)) ? 6 : -1;
}
FILE* GrimCacheOpen(const char* path,const char* mode) { return cache_fopen(path,mode); }
int GrimCacheStat(const char* path,struct stat* st) { return cache_stat(path,st); }
bool GrimCacheHasDirectory(const char* path) { char name[PATH_MAX];return ready && resource_name(path,name,sizeof(name)) && known_directory(name); }
DIR* GrimCacheOpenDir(const char* path) { return cache_opendir(path); }
struct dirent* GrimCacheReadDir(DIR* dir) { return cache_readdir(dir); }
int GrimCacheCloseDir(DIR* dir) { return cache_closedir(dir); }
bool GrimCacheLookup(const char* path,GrimCacheEntry& result) {
    char name[PATH_MAX];
    const CacheEntry* entry = ready && resource_name(path,name,sizeof(name)) ? find_entry(name) : nullptr;
    if (!entry) return false;
    result = {entry->name,entry->source,entry->offset,entry->size,entry->video_duration_ms};
    return true;
}

extern "C" jstring GrimCache_initialize(JNIEnv* env,jclass,jobject assets,jobjectArray dirs,jobjectArray apks) {
    std::string error;
    if (env->ExceptionCheck()) return nullptr;
    if (!EnsureGrimGuest(env,error)) return env->ExceptionCheck() ? nullptr : env->NewStringUTF(error.c_str());
    DynarmicHost* host=guest.load(std::memory_order_acquire);
    if (!host) return env->NewStringUTF("Cache guest was not bound during bootstrap");
    pthread_mutex_lock(&init_lock);
    init_error[0]=0;
    real_fopen=fopen;real_stat=stat;real_opendir=opendir;real_readdir=readdir;real_closedir=closedir;
    get_language=GrimGuestLanguage;
    if (!ready) {
        for (Source& source : sources) source=Source{-1,0,0};
        manager=AAssetManager_fromJava(env,assets);
        if (!manager) { snprintf(init_error,sizeof(init_error),"AssetManager unavailable");goto done; }
        for (unsigned n=0;n<256;n++) {
            uint32_t value=n;
            for(unsigned bit=0;bit<8;bit++)value=(value>>1)^((value&1)?0xedb88320U:0);
            crc_table[n]=value;
        }
        sources[CACHE_ORIGINAL_MAIN]=embedded_source(env,apks,CACHE_ORIGINAL_MAIN);
        if (init_error[0] || env->ExceptionCheck()) goto failed;
        sources[CACHE_ORIGINAL_PATCH]=embedded_source(env,apks,CACHE_ORIGINAL_PATCH);
        if (init_error[0] || env->ExceptionCheck()) goto failed;
        main_source=CACHE_ORIGINAL_MAIN;patch_source=CACHE_ORIGINAL_PATCH;legacy_cache=1;
        if (sources[main_source].fd<0 || sources[patch_source].fd<0) {
            for(unsigned n=CACHE_ORIGINAL_MAIN;n<=CACHE_ORIGINAL_PATCH;n++) {
                if(sources[n].fd>=0)close(sources[n].fd);
                sources[n]=Source{-1,0,0};
            }
            sources[0]=embedded_source(env,apks,0);
            if (init_error[0] || env->ExceptionCheck()) goto failed;
            sources[1]=embedded_source(env,apks,1);
            if (init_error[0] || env->ExceptionCheck()) goto failed;
            main_source=0;patch_source=1;legacy_cache=0;
        }
        if (!legacy_cache && (sources[0].fd<0 || sources[1].fd<0)) {
            for(unsigned n=0;n<2;n++) {
                if(sources[n].fd>=0)close(sources[n].fd);
                sources[n]=external_source(env,dirs,n);
                if (env->ExceptionCheck()) goto failed;
            }
        }
        if (sources[main_source].fd<0 || sources[patch_source].fd<0) {
            for(unsigned n=0;n<2;n++) { if(sources[n].fd>=0)close(sources[n].fd);sources[n]=Source{-1,0,0}; }
            sources[CACHE_ORIGINAL_MAIN]=external_source(env,dirs,CACHE_ORIGINAL_MAIN);
            if (env->ExceptionCheck()) goto failed;
            sources[CACHE_ORIGINAL_PATCH]=external_source(env,dirs,CACHE_ORIGINAL_PATCH);
            if (env->ExceptionCheck()) goto failed;
            main_source=CACHE_ORIGINAL_MAIN;patch_source=CACHE_ORIGINAL_PATCH;legacy_cache=1;
        }
        if (sources[main_source].fd<0 || sources[patch_source].fd<0) {
            snprintf(init_error,sizeof(init_error),"Кеш неполон: установите obb_main и obb_patch либо полную внешнюю пару main_en/patch_en или исходные main.150/patch.1512 OBB.");goto failed;
        }
        for(unsigned n=2;n<CACHE_ORIGINAL_MAIN;n++) {
            sources[n]=embedded_source(env,apks,n);
            if (init_error[0] || env->ExceptionCheck()) goto failed;
        }
        if (init_error[0] || env->ExceptionCheck()) goto failed;
        for(unsigned n=0;n<COUNT(sources);n++) {
            if(sources[n].fd<0)continue;
            if(!valid_source(sources[n],n)) { snprintf(init_error,sizeof(init_error),"Повреждён или несовместим кеш: %s",cache_specs[n].external);goto failed; }
            LOG("source=%u file=%s fd=%d base=%llu bytes=%llu metadata_crc=verified",n,cache_specs[n].external,sources[n].fd,(unsigned long long)sources[n].start,(unsigned long long)sources[n].length);
        }
        if(!InstallGrimHooks(*host,error)) { snprintf(init_error,sizeof(init_error),"Host cache/functional hook contract: %.200s",error.c_str());goto failed; }
        if(!configured)text_enabled=voice_enabled=russian_locale(env);
        if (env->ExceptionCheck()) goto failed;
        ready=1;
        unsigned mask=0;
        for(unsigned n=1;n<COUNT(cache_voice_sources);n++)if(sources[cache_voice_sources[n]].fd>=0)mask|=1U<<n;
        LOG("ready host64 rus_text=%d rus_voice=%d optional_text=%d optional_voice=%d legacy_multilingual=%d voice_packs_mask=0x%x",text_enabled,voice_enabled,sources[2].fd>=0,sources[3].fd>=0,legacy_cache,mask);
    }
    for(unsigned n=0;n<2;n++) {
        if(!MountGrimCache(env,n,n?"/cache/patch":"/cache/main",error)) {
            snprintf(init_error,sizeof(init_error),"Native mount binding: %.220s",error.c_str());goto done;
        }
    }
    goto done;
failed:
    CloseSources();
done:
    jstring result=init_error[0] && !env->ExceptionCheck()?env->NewStringUTF(init_error):nullptr;
    pthread_mutex_unlock(&init_lock);
    return result;
}
extern "C" void GrimCache_configureRussian(JNIEnv*,jclass,jboolean text,jboolean voice) {
    text_enabled=text!=JNI_FALSE;voice_enabled=voice!=JNI_FALSE;configured=1;
    LOG("Russian selection text=%d voice=%d (restart to reload open resource archives)",text_enabled,voice_enabled);
}
extern "C" void GrimCache_configureLanguage(JNIEnv*,jclass,jint selection) {
    if (selection >= -1 && selection <= 6) language_selection = selection;
}
extern "C" void GrimCache_languageSaved(JNIEnv*,jclass,jlong sequence,jboolean saved) {
    GrimHooksLanguageSaved(sequence, saved != JNI_FALSE);
}
extern "C" jint GrimCache_configureSurfaceGeometry(JNIEnv* env,jclass,jobject surface,jint width,jint height) {
    int saved=errno;int result=-EINVAL;
    if(surface && width>0 && height>0) {
        ANativeWindow* window=ANativeWindow_fromSurface(env,surface);
        if(window){result=ANativeWindow_setBuffersGeometry(window,width,height,0);ANativeWindow_release(window);}else result=-ENODEV;
    }
    errno=saved;return result;
}
extern "C" jboolean GrimCache_audioProofEnabled(JNIEnv*,jclass) { return JNI_FALSE; }
extern "C" void GrimCache_audioAccepted(JNIEnv*,jclass,jint,jint,jint,jint) {}
extern "C" void GrimCache_onTouch(JNIEnv* e,jclass,jint device,jint pointer,jint action,jfloat x,jfloat y,jfloat pressure) { GrimHooksTouch(e,device,pointer,action,x,y,pressure); }
extern "C" void GrimCache_resetInput(JNIEnv*,jclass) { GrimHooksResetInput(); }
extern "C" void GrimCache_pauseQa(JNIEnv*,jclass) { GrimHooksPauseQa(); }
extern "C" jlong GrimCache_qaCommand(JNIEnv* e,jclass,jint command,jlong epoch,jstring key) { return GrimHooksQaCommand(e,command,epoch,key); }
extern "C" jobjectArray GrimCache_qaState(JNIEnv* e,jclass) { return GrimHooksQaState(e); }
extern "C" void GrimCache_setVideoSource(JNIEnv* env, jclass, jobject player, jstring path) {
    GrimSelectVideoEntry(nullptr);
    if (env->ExceptionCheck()) return;
    if (!player || !path) {
        jclass exception = env->FindClass("java/lang/IllegalArgumentException");
        if (exception) { env->ThrowNew(exception,"Movie player/path is null"); env->DeleteLocalRef(exception); }
        return;
    }
    const char* filename = env->GetStringUTFChars(path,nullptr);
    if (!filename) return;
    char name[PATH_MAX];
    const CacheEntry* entry = ready && resource_name(filename,name,sizeof(name)) ? find_entry(name) : nullptr;
    jclass player_class = env->GetObjectClass(player);
    if (player_class && !env->ExceptionCheck()) {
        if (entry) {
            Source source = sources[entry->source];
            int fd = dup(source.fd);
            if (fd < 0) {
                jclass exception = env->FindClass("java/io/IOException");
                if (exception) { env->ThrowNew(exception,"Cannot duplicate OBB descriptor"); env->DeleteLocalRef(exception); }
            } else {
                jclass fd_class = env->FindClass("java/io/FileDescriptor");
                jmethodID constructor = fd_class ? env->GetMethodID(fd_class,"<init>","()V") : nullptr;
                jobject descriptor = constructor && !env->ExceptionCheck() ? env->NewObject(fd_class,constructor) : nullptr;
                jfieldID field = descriptor && !env->ExceptionCheck() ? env->GetFieldID(fd_class,"descriptor","I") : nullptr;
                if (field && !env->ExceptionCheck()) {
                    env->SetIntField(descriptor,field,fd);
                    jmethodID method = !env->ExceptionCheck() ? env->GetMethodID(player_class,"setDataSource","(Ljava/io/FileDescriptor;JJ)V") : nullptr;
                    if (method && !env->ExceptionCheck()) env->CallVoidMethod(player,method,descriptor,jlong(source.start + entry->offset),jlong(entry->size));
                    if (method && !env->ExceptionCheck()) {
                        GrimCacheEntry selected{entry->name,entry->source,entry->offset,entry->size,entry->video_duration_ms};
                        GrimSelectVideoEntry(&selected);
                    }
                    // Invalidate this temporary owner even when MediaPlayer throws.
                    // Preserve its exception while completing the descriptor cleanup.
                    jthrowable pending = env->ExceptionOccurred();
                    if (pending) env->ExceptionClear();
                    env->SetIntField(descriptor,field,-1);
                    if (pending) { if (env->ExceptionCheck()) env->ExceptionClear(); env->Throw(pending); env->DeleteLocalRef(pending); }
                }
                close(fd); // MediaPlayer duplicated synchronously; ownership never escapes.
                if (descriptor) env->DeleteLocalRef(descriptor);
                if (fd_class) env->DeleteLocalRef(fd_class);
            }
        } else {
            jmethodID method = env->GetMethodID(player_class,"setDataSource","(Ljava/lang/String;)V");
            if (method && !env->ExceptionCheck()) env->CallVoidMethod(player,method,path);
        }
    }
    if (player_class) env->DeleteLocalRef(player_class);
    env->ReleaseStringUTFChars(path,filename);
}
extern "C" jstring GrimCache_selfCheck(JNIEnv *env, jclass cls) {
    (void)cls;
    if (!ready) return env->NewStringUTF("cache is not initialized");
    unsigned checked = 0;
    for (unsigned n = 0; n < COUNT(cache_entries); n++) {
        const CacheEntry *entry = &cache_entries[n];
        if (sources[entry->source].fd < 0 || find_entry(entry->name) != entry) continue;
        FILE *first = cache_fopen(entry->name, "rb");
        FILE *second = cache_fopen(entry->name, "rb");
        char actual[16], expected[16], other[16];
        struct stat st;
        int ok = first && second && !read_exact(sources[entry->source].fd, expected, sizeof(expected), sources[entry->source].start + entry->offset)
                 && fread(actual, 1, sizeof(actual), first) == sizeof(actual)
                 && fread(other, 1, sizeof(other), second) == sizeof(other)
                 && !memcmp(actual, expected, sizeof(actual)) && !memcmp(other, expected, sizeof(other))
                 && !fseek(first, 0, SEEK_END) && ftell(first) == (long)entry->size && fread(actual, 1, 1, first) == 0
                 && !fseek(first, -1, SEEK_END) && fread(actual, 1, 1, first) == 1
                 && !cache_stat(entry->name, &st) && (uint64_t)st.st_size == entry->size;
        if (first) fclose(first);
        if (second) fclose(second);
        if (!ok) return env->NewStringUTF(entry->name);
        checked++;
    }
    DIR *dir = cache_opendir("/cache/main");
    if (!dir) return env->NewStringUTF("main directory open failed");
    unsigned count = 0;
    while (cache_readdir(dir)) count++;
    cache_closedir(dir);
    unsigned expected_count = 0;
    for (unsigned n = 0; n < COUNT(cache_entries); n++)
        if (mounted_entry(main_source, &cache_entries[n]) && !strchr(cache_entries[n].name, '/')) expected_count++;
    if (count != expected_count) return env->NewStringUTF("main directory entry count mismatch");
    FILE *asset = cache_fopen("DATA000.LAB", "rb");
    char header[4];
    int asset_ok = asset && fread(header, 1, 4, asset) == 4 && !memcmp(header, "LABN", 4)
                   && !fseek(asset, 0, SEEK_END) && ftell(asset) > 0
                   && !fseek(asset, 0, SEEK_SET) && fread(header, 1, 4, asset) == 4 && !memcmp(header, "LABN", 4);
    if (asset) fclose(asset);
    if (!asset_ok) return env->NewStringUTF("compressed DATA000.LAB asset read/seek failed");
    LOG("selfCheck PASSED entries=%u main_directory=%u independent_cursors=verified EOF=verified", checked, count);
    return NULL;
}

bool RegisterGrimCacheNatives(JNIEnv* env) {
    jclass cls=env->FindClass("com/doublefine/grimfandangoremastered/CacheReader");
    if(!cls)return false;
#define METHOD(name,signature) {const_cast<char*>(#name),const_cast<char*>(signature),reinterpret_cast<void*>(GrimCache_##name)}
    const JNINativeMethod methods[]={
        METHOD(initialize,"(Landroid/content/res/AssetManager;[Ljava/lang/String;[Ljava/lang/String;)Ljava/lang/String;"),
        METHOD(configureRussian,"(ZZ)V"),METHOD(configureLanguage,"(I)V"),METHOD(languageSaved,"(JZ)V"),METHOD(configureSurfaceGeometry,"(Landroid/view/Surface;II)I"),
        METHOD(setVideoSource,"(Landroid/media/MediaPlayer;Ljava/lang/String;)V"),METHOD(selfCheck,"()Ljava/lang/String;"),
        METHOD(onTouch,"(IIIFFF)V"),METHOD(resetInput,"()V"),METHOD(pauseQa,"()V"),
        METHOD(qaCommand,"(IJLjava/lang/String;)J"),METHOD(qaState,"()[Ljava/lang/String;"),
        METHOD(audioAccepted,"(IIII)V"),METHOD(audioProofEnabled,"()Z")};
#undef METHOD
    bool ok=env->RegisterNatives(cls,methods,COUNT(methods))==JNI_OK;env->DeleteLocalRef(cls);return ok;
}
