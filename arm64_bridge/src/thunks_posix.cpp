#include "thunk_manager.h"
#include "frame_pacing.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include "jni_fake_env.h"
#include "elf_loader.h"
#include "bridge_io.h"
#include <android/log.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <chrono>
#include <ctime>
#include <cwchar>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <functional>
#include <libgen.h>
#include <limits>
#include <locale.h>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <string>
#include <thread>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <zlib.h>

#define LOG_TAG "Arm32Bridge_Libc"
#include "bridge_log.h"

extern FILE* BridgeFopen(const char*, const char*);
extern int BridgeFstat(int, struct stat*);
extern "C" int BionicStrerrorR(int,char*,size_t) __asm__("strerror_r");

namespace {
using Jit = Dynarmic::A32::Jit;
using Host = DynarmicHost;

[[noreturn]] void Invalid(const char* what) {
    LOGE("libc boundary FAILED: %s", what);
    std::abort();
}

void* Span(Host& host, uint32_t p, size_t n) {
    if ((!p && n) || uint64_t(p) + n > host.GetGuestMemorySize()) {
        uint32_t pc = 0, lr = 0;
        if (host.IsJitRunning()) {
            auto& jit = host.CurrentJit();
            pc = jit.Regs()[15];
            lr = jit.Regs()[14];
        }
        LOGE("invalid guest memory range p=0x%08x n=%zu pc=0x%08x lr=0x%08x", p, n, pc, lr);
        Invalid("guest memory range");
    }
    return p ? host.GetGuestMemoryBase() + p : nullptr;
}

const char* String(Host& host, uint32_t p) {
    if (!p) return nullptr;
    auto* s = static_cast<const char*>(Span(host, p, 1));
    // libc strings are bounded to 1 MiB; raise only for a measured larger caller.
    size_t available = std::min<size_t>(host.GetGuestMemorySize() - p, 1024 * 1024);
    if (!memchr(s, 0, available)) Invalid("unterminated or oversized guest string");
    return s;
}

const char* BoundedString(Host& host,uint32_t p,size_t n){
    if(!n)return nullptr;
    auto* s=static_cast<const char*>(Span(host,p,1));
    size_t available=host.GetGuestMemorySize()-p;
    if(n>available && !memchr(s,0,available))Invalid("bounded string exceeds guest arena");
    return s;
}
constexpr uint8_t CtypeByte(unsigned c){
    if(c>=128)return 0;
    uint8_t flags=0;
    if(c<' '||c==127)flags|=0x20;
    if(c==' '||(c>=9&&c<=13))flags|=0x08;
    if(c==' ')flags|=0x80;
    if(c>='0'&&c<='9')flags|=0x04;
    if(c>='A'&&c<='Z')flags|=0x01;
    if(c>='a'&&c<='z')flags|=0x02;
    if((c>='A'&&c<='F')||(c>='a'&&c<='f'))flags|=0x40;
    if(c>' '&&c<127&&!(flags&0x07))flags|=0x10;
    return flags;
}
static_assert(CtypeByte(' ')==0x88 && CtypeByte('\t')==0x28 && CtypeByte('A')==0x41 && CtypeByte('0')==4);
uint32_t Address(Host& host,const void* p) {
    if(!p)return 0;
    uintptr_t value=reinterpret_cast<uintptr_t>(p),base=reinterpret_cast<uintptr_t>(host.GetGuestMemoryBase());
    if(value<base || value-base>=host.GetGuestMemorySize())Invalid("host pointer cannot be a guest pointer");
    return static_cast<uint32_t>(value-base);
}
void Errno(Host& host, int value) { host.MemoryWrite32(host.GuestErrnoAddress(), value); }
void Result(Jit& jit, Host& host, int64_t value) {
    const int saved = errno;
    jit.Regs()[0] = static_cast<uint32_t>(value);
    if (value < 0) Errno(host, saved);
}
void Failure(Jit& jit, Host& host, int error) { errno = error; Result(jit, host, -1); }

bool AffinityWideEnabled() {
    static const bool enabled = [] {
        char override_value[PROP_VALUE_MAX]{};
        if (__system_property_get("debug.arm32bridge.affinity_wide", override_value) > 0) {
            if (std::strcmp(override_value, "0") == 0) {
                LOGI("affinity-wide policy disabled by debug override");
                return false;
            }
            if (std::strcmp(override_value, "1") == 0) {
                LOGI("affinity-wide policy enabled by debug override");
                return true;
            }
            LOGW("invalid debug.arm32bridge.affinity_wide='%s'; affinity-wide policy disabled by default",
                  override_value);
            return false;
        }

        LOGI("affinity-wide policy disabled by default");
        return false;
    }();
    return enabled;
}

uint32_t Low32CpuMask(const cpu_set_t& native, bool* has_high = nullptr) {
    uint32_t mask = 0;
    bool high = false;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &native)) continue;
        if (cpu < 32) mask |= 1u << cpu;
        else high = true;
    }
    if (has_high) *has_high = high;
    return mask;
}

bool ReadCurrentThreadAllowedCpuMask(cpu_set_t& native, uint32_t& low, bool& has_high) {
    char path[64]{};
    const int path_size = std::snprintf(
        path, sizeof(path), "/proc/self/task/%d/status", static_cast<int>(gettid()));
    if (path_size <= 0 || static_cast<size_t>(path_size) >= sizeof(path)) return false;
    FILE* file = std::fopen(path, "r");
    if (!file) return false;

    char* line = nullptr;
    size_t capacity = 0;
    bool parsed = false;
    constexpr char prefix[] = "Cpus_allowed_list:";
    while (getline(&line, &capacity, file) >= 0) {
        if (std::strncmp(line, prefix, sizeof(prefix) - 1) != 0) continue;
        cpu_set_t candidate{};
        CPU_ZERO(&candidate);
        uint32_t candidate_low = 0;
        bool candidate_high = false;
        bool any = false;
        char* cursor = line + sizeof(prefix) - 1;
        parsed = true;
        for (;;) {
            while (*cursor && std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            if (!*cursor) break;
            errno = 0;
            char* end = nullptr;
            const unsigned long first = std::strtoul(cursor, &end, 10);
            if (errno || end == cursor) { parsed = false; break; }
            unsigned long last = first;
            cursor = end;
            if (*cursor == '-') {
                errno = 0;
                last = std::strtoul(cursor + 1, &end, 10);
                if (errno || end == cursor + 1) { parsed = false; break; }
                cursor = end;
            }
            if (first > last || last >= CPU_SETSIZE) { parsed = false; break; }
            for (unsigned long cpu = first; cpu <= last; ++cpu) {
                CPU_SET(static_cast<int>(cpu), &candidate);
                if (cpu < 32) candidate_low |= 1u << cpu;
                else candidate_high = true;
            }
            any = true;
            while (*cursor && std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            if (!*cursor) break;
            if (*cursor != ',') { parsed = false; break; }
            ++cursor;
        }
        parsed = parsed && any;
        if (parsed) {
            native = candidate;
            low = candidate_low;
            has_high = candidate_high;
        }
        break;
    }
    std::free(line);
    std::fclose(file);
    return parsed;
}

// A successful real getaffinity plus the same thread's kernel-reported allowed
// list may feed exactly one immediately following guest setaffinity.  The list
// retains temporarily-offline CPUs, stays inside the app's allowed cpuset, and
// never changes the syscall result reported to the guest.
thread_local cpu_set_t g_affinity_before_guest_pin{};
thread_local uint32_t g_affinity_before_guest_pin_low = 0;
thread_local uint32_t g_affinity_before_guest_pin_observed_low = 0;
thread_local bool g_affinity_before_guest_pin_valid = false;

uint32_t CopyString(Host& host, const char* s) {
    if (!s) return 0;
    size_t size = strlen(s) + 1;
    uint32_t p = host.GuestAlloc(size, 4);
    if (p) memcpy(Span(host, p, size), s, size);
    return p;
}

struct Time32 { int32_t sec, nsec; };
static_assert(sizeof(Time32) == 8);
bool ReadTime(Host& host, uint32_t p, timespec& result) {
    auto* t = static_cast<const Time32*>(Span(host, p, sizeof(Time32)));
    if (t->nsec < 0 || t->nsec >= 1000000000) return false;
    result = {t->sec, t->nsec};
    return true;
}
bool WriteTime(Host& host, uint32_t p, const timespec& value) {
    if (value.tv_sec < INT32_MIN || value.tv_sec > INT32_MAX) { errno = EOVERFLOW; return false; }
    Time32 t{static_cast<int32_t>(value.tv_sec), static_cast<int32_t>(value.tv_nsec)};
    memcpy(Span(host, p, sizeof(t)), &t, sizeof(t));
    return true;
}

// Bionic ARM32 stat/stat64 is 104 bytes, not the generic Linux 64-byte old stat.
struct alignas(8) Stat32 {
    uint64_t dev;
    uint32_t pad0, ino32, mode, nlink, uid, gid;
    uint64_t rdev;
    uint32_t pad3, pad4;
    int64_t size;
    uint32_t blksize, pad5;
    uint64_t blocks;
    Time32 atime, mtime, ctime;
    uint64_t ino;
};
static_assert(sizeof(Stat32) == 104 && offsetof(Stat32, size) == 48 && offsetof(Stat32, ino) == 96);
bool WriteStat(Host& host, uint32_t p, const struct stat& s) {
    if (s.st_atim.tv_sec > INT32_MAX || s.st_atim.tv_sec < INT32_MIN ||
        s.st_mtim.tv_sec > INT32_MAX || s.st_mtim.tv_sec < INT32_MIN ||
        s.st_ctim.tv_sec > INT32_MAX || s.st_ctim.tv_sec < INT32_MIN) { errno = EOVERFLOW; return false; }
    Stat32 g{};
    g.dev=s.st_dev; g.ino32=static_cast<uint32_t>(s.st_ino); g.mode=s.st_mode;
    g.nlink=s.st_nlink; g.uid=s.st_uid; g.gid=s.st_gid; g.rdev=s.st_rdev;
    g.size=s.st_size; g.blksize=s.st_blksize; g.blocks=s.st_blocks; g.ino=s.st_ino;
    g.atime={static_cast<int32_t>(s.st_atim.tv_sec),static_cast<int32_t>(s.st_atim.tv_nsec)};
    g.mtime={static_cast<int32_t>(s.st_mtim.tv_sec),static_cast<int32_t>(s.st_mtim.tv_nsec)};
    g.ctime={static_cast<int32_t>(s.st_ctim.tv_sec),static_cast<int32_t>(s.st_ctim.tv_nsec)};
    memcpy(Span(host,p,sizeof(g)),&g,sizeof(g));
    return true;
}
struct alignas(8) Dirent32 {
    uint64_t ino;
    int64_t off;
    uint16_t reclen;
    uint8_t type;
    char name[256];
};
static_assert(sizeof(Dirent32)==280 && offsetof(Dirent32,name)==19);
struct Tm32 { int32_t sec,min,hour,mday,mon,year,wday,yday,isdst,gmtoff; uint32_t zone; };
static_assert(sizeof(Tm32)==44);
struct Attr32 { uint32_t flags,base,size,guard; int32_t policy,priority; };
static_assert(sizeof(Attr32)==24);

struct ThreadCache {
    std::unordered_map<std::string, std::pair<uint32_t,size_t>> strings;
    uint32_t tm=0, passwd=0;
    size_t passwd_capacity=0;
    uint32_t strtok_next=0;
    std::string dl_error;
    bool dl_error_pending=false;
    uint32_t hostent=0;
};
thread_local ThreadCache t_cache;
uint32_t CachedString(Host& host, const std::string& key, const char* value) {
    if (!value) return 0;
    size_t n=strlen(value)+1;
    auto& entry=t_cache.strings[key];
    if (entry.second<n) {
        uint32_t next=host.GuestAlloc(n,4);
        if (!next) return 0;
        host.GuestFree(entry.first); entry={next,n};
    }
    memcpy(Span(host,entry.first,n),value,n);
    return entry.first;
}
void WriteTm(Host& host,uint32_t p,const tm& t) {
    Tm32 g{t.tm_sec,t.tm_min,t.tm_hour,t.tm_mday,t.tm_mon,t.tm_year,t.tm_wday,t.tm_yday,t.tm_isdst,
           static_cast<int32_t>(t.tm_gmtoff),CachedString(host,"tm_zone",t.tm_zone)};
    memcpy(Span(host,p,sizeof(g)),&g,sizeof(g));
}

std::atomic<int> g_standard_fds[3]={-1,-1,-1};
FILE* g_standard_streams[3]={};
int NativeFd(int fd){return fd>=0&&fd<3?g_standard_fds[fd].load():fd;}
struct File {
    std::mutex mutex;
    FILE* stream;
    explicit File(FILE* f):stream(f) {}
    ~File(){ if(stream) fclose(stream); }
};
struct Directory {
    std::mutex mutex;
    DIR* directory;
    uint32_t entry;
    Directory(DIR* d,uint32_t p):directory(d),entry(p) {}
    ~Directory(){ if(directory) closedir(directory); }
};
struct Gzip {
    std::mutex mutex;
    gzFile file;
    explicit Gzip(gzFile f):file(f) {}
    ~Gzip(){ if(file) gzclose(file); }
};
std::mutex g_handles_mutex;
std::unordered_map<uint32_t,std::shared_ptr<File>> g_files;
std::unordered_map<uint32_t,std::shared_ptr<Directory>> g_dirs;
std::unordered_map<uint32_t,std::shared_ptr<Gzip>> g_gzip;
std::unordered_map<uint32_t,std::vector<uint32_t>> g_addrinfo;

template<class T> std::shared_ptr<T> Lookup(const std::unordered_map<uint32_t,std::shared_ptr<T>>& table,uint32_t p) {
    std::lock_guard lock(g_handles_mutex);
    auto it=table.find(p);
    if(it==table.end()){ errno=EBADF; return {}; }
    return it->second;
}
template<class R,class Fn> R WithFile(uint32_t p,R fail,Fn&& fn) {
    auto file=Lookup(g_files,p);
    if(!file) return fail;
    std::lock_guard lock(file->mutex);
    if(!file->stream){errno=EBADF;return fail;}
    return fn(file->stream);
}
uint32_t AddFile(Host& host,FILE* file) {
    if(!file)return 0;
    uint32_t p=host.GuestAlloc(84,4);
    if(!p){fclose(file);errno=ENOMEM;return 0;}
    memset(Span(host,p,84),0,84);
    host.MemoryWrite16(p+14,static_cast<uint16_t>(fileno(file)));
    std::lock_guard lock(g_handles_mutex);
    g_files.emplace(p,std::make_shared<File>(file));
    return p;
}
int CloseFile(Host& host,uint32_t p){
    auto f=Lookup(g_files,p);if(!f){errno=EBADF;return -1;}
    bool standard=p>=0x200&&p<0x200+3*84;
    int rc;
    {std::lock_guard lock(f->mutex);
        if(!f->stream){errno=EBADF;return -1;}
        if(standard)g_standard_fds[(p-0x200)/84]=-1;
        rc=fclose(f->stream);f->stream=nullptr;
    }
    int saved=errno;{std::lock_guard lock(g_handles_mutex);g_files.erase(p);}
    if(!standard)host.GuestFree(p);errno=saved;return rc;
}
int LogWrite(FILE* file,const char* s,size_t count) {
    bool standard_out=file==g_standard_streams[1]&&g_standard_fds[1]>=0;
    bool standard_error=file==g_standard_streams[2]&&g_standard_fds[2]>=0;
    if(standard_out || standard_error){
        for(size_t i=0;i<count;i+=4000) __android_log_print(standard_error?ANDROID_LOG_ERROR:ANDROID_LOG_INFO,
            "Arm32Guest","%.*s",static_cast<int>(std::min<size_t>(4000,count-i)),s+i);
        return static_cast<int>(count);
    }
    size_t n=fwrite(s,1,count,file);
    return n==count?static_cast<int>(n):-1;
}

// Address-keyed host objects retain their lifetime while waits release the registry lock.
struct Mutex {
    pthread_mutex_t value;
    bool live=false;
    explicit Mutex(int type){
        pthread_mutexattr_t attr;
        int rc=pthread_mutexattr_init(&attr);
        if(rc)Invalid("host mutex attributes");
        rc=pthread_mutexattr_settype(&attr,type);
        if(!rc)rc=pthread_mutex_init(&value,&attr);
        pthread_mutexattr_destroy(&attr);
        if(rc)Invalid("host mutex initialization");
        live=true;
    }
    ~Mutex(){if(live && pthread_mutex_destroy(&value))Invalid("destroying live guest mutex");}
};
struct Condition {
    pthread_cond_t value;
    clockid_t clock;
    bool live=false;
    std::mutex legacy_mutex;
    std::condition_variable legacy_cv;
    size_t legacy_waiters=0;
    size_t legacy_wakeups=0;
    std::atomic<bool> legacy_logged=false;
    explicit Condition(clockid_t c):clock(c){
        pthread_condattr_t attr;
        int rc=pthread_condattr_init(&attr);
        if(rc)Invalid("host condition attributes");
        rc=pthread_condattr_setclock(&attr,c);
        if(!rc)rc=pthread_cond_init(&value,&attr);
        pthread_condattr_destroy(&attr);
        if(rc)Invalid("host condition initialization");
        live=true;
    }
    int WaitWithoutMutex(){
        std::unique_lock lock(legacy_mutex);
        ++legacy_waiters;
        legacy_cv.wait(lock,[&]{return legacy_wakeups!=0;});
        --legacy_wakeups;
        --legacy_waiters;
        return 0;
    }
    int Signal(){
        bool notify=false;
        {
            std::lock_guard lock(legacy_mutex);
            if(legacy_waiters>legacy_wakeups){++legacy_wakeups;notify=true;}
        }
        if(notify){legacy_cv.notify_one();return 0;}
        return pthread_cond_signal(&value);
    }
    int Broadcast(){
        int rc=pthread_cond_broadcast(&value);
        bool notify=false;
        {
            std::lock_guard lock(legacy_mutex);
            if(legacy_waiters){legacy_wakeups=legacy_waiters;notify=true;}
        }
        if(notify)legacy_cv.notify_all();
        return rc;
    }
    size_t LegacyWaiters(){
        std::lock_guard lock(legacy_mutex);
        return legacy_waiters;
    }
    ~Condition(){if(live && pthread_cond_destroy(&value))Invalid("destroying live guest condition");}
};
struct Semaphore {
    sem_t value;
    bool live=false;
    explicit Semaphore(unsigned count){if(sem_init(&value,0,count))Invalid("host semaphore initialization");live=true;}
    ~Semaphore(){if(live && sem_destroy(&value))Invalid("destroying live guest semaphore");}
};
struct Once {
    std::mutex mutex;
    std::condition_variable cv;
    unsigned state=0;
    std::thread::id owner{};
    bool Run(const std::function<bool()>& init){
        std::unique_lock lock(mutex);
        cv.wait(lock,[&]{return state!=1;});
        if(state==2)return true;
        state=1;lock.unlock();
        bool complete=init();
        lock.lock();state=complete?2:0;lock.unlock();cv.notify_all();
        return complete;
    }
};
std::mutex g_sync_mutex;
std::unordered_map<uint32_t,std::shared_ptr<Mutex>> g_mutexes;
std::unordered_map<uint32_t,std::shared_ptr<Condition>> g_conditions;
std::unordered_map<uint32_t,std::shared_ptr<Semaphore>> g_semaphores;
std::unordered_map<uint32_t,std::shared_ptr<Once>> g_once;

std::shared_ptr<Mutex> GetMutex(Host& host,uint32_t p){
    if(!p){errno=EINVAL;return {};}
    Span(host,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto it=g_mutexes.find(p);
    if(it!=g_mutexes.end())return it->second;
    uint32_t word=host.MemoryRead32(p);
    if(word&~0xc000u || (word>>14)>2){errno=EINVAL;return {};}
    auto value=std::make_shared<Mutex>(static_cast<int>(word>>14));
    g_mutexes.emplace(p,value);return value;
}
std::shared_ptr<Condition> GetCondition(Host& host,uint32_t p){
    if(!p){errno=EINVAL;return {};}
    Span(host,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto it=g_conditions.find(p);
    if(it!=g_conditions.end())return it->second;
    uint32_t word=host.MemoryRead32(p);
    if(word&~2u){errno=(word&1)?ENOTSUP:EINVAL;return {};}
    auto value=std::make_shared<Condition>((word&2)?CLOCK_MONOTONIC:CLOCK_REALTIME);
    g_conditions.emplace(p,value);return value;
}
std::shared_ptr<Semaphore> GetSemaphore(uint32_t p){
    std::lock_guard lock(g_sync_mutex);
    auto it=g_semaphores.find(p);
    if(it==g_semaphores.end()){errno=EINVAL;return {};}
    return it->second;
}
int WaitCondition(Host& host,uint32_t cond,uint32_t mutex,uint32_t deadline,bool relative){
    auto c=GetCondition(host,cond);if(!c)return errno;
    // Immersion's legacy Android library deliberately passes a null mutex and
    // treats pthread_cond_wait as an event wait. Bionic tolerated this pattern;
    // returning EINVAL makes its haptic worker spin at 100% instead of sleeping.
    if(!mutex){
        if(relative || deadline)return EINVAL;
        if(!c->legacy_logged.exchange(true,std::memory_order_relaxed))
            LOGI("legacy pthread_cond_wait(cond=0x%08x, mutex=null): event wait enabled",cond);
        return c->WaitWithoutMutex();
    }
    auto m=GetMutex(host,mutex);if(!m)return errno;
    if(!relative && !deadline)return pthread_cond_wait(&c->value,&m->value);
    timespec time{};
    if(relative){
        if(clock_gettime(c->clock,&time))return errno;
        time.tv_sec+=deadline/1000;time.tv_nsec+=(deadline%1000)*1000000LL;
        time.tv_sec+=time.tv_nsec/1000000000;time.tv_nsec%=1000000000;
    }else if(!ReadTime(host,deadline,time))return EINVAL;
    return pthread_cond_timedwait(&c->value,&m->value,&time);
}

struct Thread {
    std::mutex mutex;
    pthread_t native{};
    bool detached=false,finished=false,joining=false,external=false;
    uint32_t retval=0,id=0;
};
std::mutex g_threads_mutex;
std::unordered_map<uint32_t,std::shared_ptr<Thread>> g_threads;
uint32_t g_next_thread=1;
thread_local std::shared_ptr<Thread> t_thread;
struct Key {uint32_t destructor;};
std::mutex g_keys_mutex;
std::unordered_map<uint32_t,Key> g_keys;
// ponytail: opaque monotonic keys avoid stale deleted-key values; 2^32 creations per process.
uint32_t g_next_key=1;
thread_local std::unordered_map<uint32_t,uint32_t> t_keys;

struct GuestJumpContext {
    std::thread::id owner{};
    Jit* jit=nullptr;
    std::array<uint32_t,8> callee_saved{};
    std::array<uint32_t,16> ext_regs{}; // D8-D15, as S16-S31.
    uint32_t fpscr=0;
    uint32_t sp=0;
    uint32_t lr=0;
    uint32_t cpsr=0;
    uint32_t signal_mask=0;
    bool saves_signal_mask=false;
};
struct GuestSignalAction {
    uint32_t handler=0;
    uint32_t mask=0;
    uint32_t flags=0;
    uint32_t restorer=0;
};
struct GuestAlarm {
    bool armed=false;
    std::chrono::steady_clock::time_point deadline{};
    uint32_t jump_buffer=0;
};
std::mutex g_jump_mutex;
std::unordered_map<uint32_t,GuestJumpContext> g_jump_contexts;
std::mutex g_signal_mutex;
GuestSignalAction g_sigalrm_action;
thread_local GuestAlarm t_alarm;
thread_local uint32_t t_guest_signal_mask=0;
constexpr uint32_t kGuestJumpCookie = 0x4a4d5000;
constexpr uint32_t kGuestJumpMagic = 0x4a4d5032;
constexpr uint32_t kGuestSigjmpStoredBytes = 128;
constexpr uint32_t kGuestSigjmpMagicOffset = 124;
constexpr uint32_t kSigalrmMask = 1u << (SIGALRM - 1);

uint32_t ReadNativeLowSignalMask(const sigset_t& set) {
    uint32_t result = 0;
    for (int signal = 1; signal <= 32; ++signal)
        if (sigismember(&set, signal) == 1) result |= 1u << (signal - 1);
    return result;
}

// Bionic's legacy LP32 sigset_t has one 32-bit word. The emulated alarm
// retains its own mask; native masks are built by signal number, not by casts.
int GuestThreadSignalMask(int how, const uint32_t* next, uint32_t* previous) {
    sigset_t native_old{};
    int rc = pthread_sigmask(SIG_SETMASK, nullptr, &native_old);
    if (rc) return rc;
    uint32_t old = (ReadNativeLowSignalMask(native_old) & ~kSigalrmMask) |
                   (t_guest_signal_mask & kSigalrmMask);
    if (next) {
        if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) return EINVAL;
        sigset_t native_next{};
        sigemptyset(&native_next);
        for (int signal = 1; signal <= 32; ++signal)
            if ((*next & (1u << (signal - 1))) && signal != SIGALRM)
                sigaddset(&native_next, signal);
        if (how == SIG_SETMASK) {
            // A legacy32 operation cannot name the host's realtime signals.
            for (int signal = 33; signal < NSIG; ++signal)
                if (sigismember(&native_old, signal) == 1) sigaddset(&native_next, signal);
        }
        rc = pthread_sigmask(how, &native_next, nullptr);
        if (rc) return rc;
        if (how == SIG_BLOCK) t_guest_signal_mask = old | *next;
        else if (how == SIG_UNBLOCK) t_guest_signal_mask = old & ~*next;
        else t_guest_signal_mask = *next;
        t_guest_signal_mask &= ~((1u << (SIGKILL - 1)) | (1u << (SIGSTOP - 1)));
    }
    if (previous) *previous = old;
    return 0;
}

std::shared_ptr<Thread> GetThread(uint32_t id){
    std::lock_guard lock(g_threads_mutex);
    auto it=g_threads.find(id);return it==g_threads.end()?nullptr:it->second;
}
void ForgetThread(const std::shared_ptr<Thread>& thread){
    std::lock_guard lock(g_threads_mutex);
    auto it=g_threads.find(thread->id);
    if(it!=g_threads.end() && it->second==thread)g_threads.erase(it);
}
std::shared_ptr<Thread> NewThread(){
    std::lock_guard lock(g_threads_mutex);
    if(!g_next_thread)return {};
    auto thread=std::make_shared<Thread>();thread->id=g_next_thread++;
    g_threads.emplace(thread->id,thread);return thread;
}
uint32_t Self(){
    auto& current=t_thread; // Initialize before the cleanup destructor is registered.
    struct Cleanup {~Cleanup(){if(t_thread&&t_thread->external)ForgetThread(t_thread);}};
    static thread_local Cleanup cleanup;
    (void)current;(void)cleanup;
    if(!t_thread){
        t_thread=NewThread();if(!t_thread)Invalid("guest thread identifiers exhausted");
        t_thread->native=pthread_self();t_thread->external=true;t_thread->detached=true;
    }
    return t_thread->id;
}
void RunTlsDestructors(Host& host){
    for(unsigned pass=0;pass<4;++pass){
        std::vector<std::pair<uint32_t,uint32_t>> pending;
        {
            std::lock_guard lock(g_keys_mutex);
            for(auto& [key,value]:t_keys){
                auto it=g_keys.find(key);
                if(value && it!=g_keys.end() && it->second.destructor){
                    pending.emplace_back(it->second.destructor,value);value=0;
                }
            }
        }
        if(pending.empty())break;
        for(auto [fn,value]:pending)host.RunFunction(fn,{value});
    }
    t_keys.clear();
}

void WriteGuestSignalAction(Host& host,uint32_t address,const GuestSignalAction& action){
    if(!address)return;
    host.MemoryWrite32(address,action.handler);
    host.MemoryWrite32(address+4,action.mask);
    host.MemoryWrite32(address+8,action.flags);
    host.MemoryWrite32(address+12,action.restorer);
}
GuestSignalAction ReadGuestSignalAction(Host& host,uint32_t address){
    Span(host,address,16);
    return {host.MemoryRead32(address),host.MemoryRead32(address+4),
            host.MemoryRead32(address+8),host.MemoryRead32(address+12)};
}

// Deliver only the guest's observed SIGALRM path.  The jump target and buffer
// must belong to this thread and this JIT; no host signal or cross-thread entry.
bool GuestSignalPollImpl(Host& host,Jit& jit){
    if(!t_alarm.armed || (t_guest_signal_mask&kSigalrmMask) || std::chrono::steady_clock::now()<t_alarm.deadline)return false;
    GuestSignalAction action;
    {
        std::lock_guard lock(g_signal_mutex);
        action=g_sigalrm_action;
    }
    GuestJumpContext context;
    {
        std::lock_guard lock(g_jump_mutex);
        auto found=g_jump_contexts.find(t_alarm.jump_buffer);
        if(found==g_jump_contexts.end()){
            LOGE("SIGALRM expired without a guest sigjmp_buf");
            host.Fail("guest SIGALRM has no same-thread jump context");
            return false;
        }
        context=found->second;
    }
    if(!action.handler || !host.IsExecutableAddress(action.handler) ||
       context.owner!=std::this_thread::get_id() || context.jit!=&jit){
        LOGE("invalid guest SIGALRM delivery handler=0x%08x buffer=0x%08x",action.handler,t_alarm.jump_buffer);
        host.Fail("unsupported guest SIGALRM delivery context");
        return false;
    }
    t_alarm.armed=false;
    t_guest_signal_mask|=kSigalrmMask|action.mask;
    jit.Regs()[0]=SIGALRM;
    jit.Regs()[15]=action.handler&~1u;
    jit.SetCpsr((jit.Cpsr()&~0x20u)|(action.handler&1?0x20u:0));
    LOGI("guest SIGALRM delivered: handler=0x%08x buffer=0x%08x",action.handler,t_alarm.jump_buffer);
    return true;
}

struct ThreadStart {Host* host;uint32_t function,arg;std::shared_ptr<Thread> thread;};
void* ThreadEntry(void* opaque){
    std::unique_ptr<ThreadStart> start(static_cast<ThreadStart*>(opaque));
    auto thread=start->thread;t_thread=thread;
    {std::lock_guard lock(thread->mutex);thread->native=pthread_self();}
    uint32_t result=start->host->RunFunction(start->function,{start->arg});
    start->host->BeginThreadCleanup();
    RunTlsDestructors(*start->host);
    FakeJniEnv::Instance().ReleaseCurrentThread();
    start->host->ReleaseCurrentThread();
    bool detached;
    {std::lock_guard lock(thread->mutex);thread->retval=result;thread->finished=true;detached=thread->detached;}
    if(detached)ForgetThread(thread);
    t_thread.reset();
    return reinterpret_cast<void*>(static_cast<uintptr_t>(result));
}
int CreateThread(Host& host,uint32_t output,uint32_t attr_ptr,uint32_t function,uint32_t arg){
    if(!output || !function)return EINVAL;
    Span(host,output,4);
    Attr32 guest{0,0,1024*1024,4096,SCHED_OTHER,0};
    if(attr_ptr)memcpy(&guest,Span(host,attr_ptr,sizeof(guest)),sizeof(guest));
    // host stacks reserve 1 MiB per guest thread; support sized arenas before accepting another size.
    if(guest.base || (guest.size<16384 || guest.size>4*1024*1024-65536) || (guest.flags&~1u))return ENOTSUP;
    auto thread=NewThread();if(!thread)return EAGAIN;
    thread->detached=(guest.flags&1)!=0;
    auto start=std::make_unique<ThreadStart>(ThreadStart{&host,function,arg,thread});
    pthread_attr_t attr;
    int rc=pthread_attr_init(&attr);
    if(rc){ForgetThread(thread);return rc;}
    rc=pthread_attr_setstacksize(&attr,8*1024*1024);
    if(!rc)rc=pthread_attr_setdetachstate(&attr,thread->detached?PTHREAD_CREATE_DETACHED:PTHREAD_CREATE_JOINABLE);
    if(!rc)rc=pthread_attr_setschedpolicy(&attr,guest.policy);
    sched_param schedule{};schedule.sched_priority=guest.priority;
    if(!rc)rc=pthread_attr_setschedparam(&attr,&schedule);
    pthread_t native{};
    if(!rc)rc=pthread_create(&native,&attr,ThreadEntry,start.get());
    pthread_attr_destroy(&attr);
    if(rc){ForgetThread(thread);return rc;}
    start.release();
    {std::lock_guard lock(thread->mutex);thread->native=native;}
    host.MemoryWrite32(output,thread->id);
    return 0;
}
int JoinThread(Host& host,uint32_t id,uint32_t output){
    auto thread=GetThread(id);if(!thread)return ESRCH;
    if(id==Self())return EDEADLK;
    if(output)Span(host,output,4);
    pthread_t native;
    {std::lock_guard lock(thread->mutex);
        if(thread->detached || thread->external || thread->joining)return EINVAL;
        thread->joining=true;native=thread->native;
    }
    void* result=nullptr;int rc=pthread_join(native,&result);
    if(rc){std::lock_guard lock(thread->mutex);thread->joining=false;return rc;}
    if(output)host.MemoryWrite32(output,static_cast<uint32_t>(reinterpret_cast<uintptr_t>(result)));
    ForgetThread(thread);return 0;
}
int DetachThread(uint32_t id){
    auto thread=GetThread(id);if(!thread)return ESRCH;
    bool finished;
    {std::lock_guard lock(thread->mutex);
        if(thread->detached || thread->external || thread->joining)return EINVAL;
        int rc=pthread_detach(thread->native);if(rc)return rc;
        thread->detached=true;finished=thread->finished;
    }
    if(finished)ForgetThread(thread);return 0;
}

struct AtExit {uint32_t function,arg,dso;};
std::mutex g_atexit_mutex;
std::vector<AtExit> g_atexit;
void Finalize(Host& host,uint32_t dso){
    for(;;){
        AtExit entry{};
        {
            std::lock_guard lock(g_atexit_mutex);
            for(auto it=g_atexit.rbegin();it!=g_atexit.rend();++it){
                if(!dso || it->dso==dso){entry=*it;g_atexit.erase(std::next(it).base());break;}
            }
        }
        if(!entry.function)break;
        host.RunFunction(entry.function,{entry.arg});
        if(host.HasFailed()||host.IsCurrentGuestThreadExiting())return;
    }
}

class VarArgs {
    Jit& jit;
    Host& host;
    uint32_t word;
    uint64_t cursor;
    bool memory;
public:
    VarArgs(Jit& j,Host& h,uint32_t first,bool list=false):jit(j),host(h),word(first),cursor(first),memory(list){}
    uint32_t U32(){
        if(memory){if(cursor>UINT32_MAX)Invalid("va_list overflow");Span(host,static_cast<uint32_t>(cursor),4);
            uint32_t v=host.MemoryRead32(static_cast<uint32_t>(cursor));cursor+=4;return v;}
        if(word<4)return jit.Regs()[word++];
        return host.ReadStackWord(jit,word++-4);
    }
    uint64_t U64(){if(memory)cursor=(cursor+7)&~uint64_t(7);else word=(word+1)&~1u;
        uint64_t lo=U32();return lo|(uint64_t(U32())<<32);}
    double F64(){uint64_t raw=U64();double value;memcpy(&value,&raw,8);return value;}
};
template<class T> std::string PrintValue(const std::string& fmt,T value){
    int n=snprintf(nullptr,0,fmt.c_str(),value);
    if(n<0||n>1024*1024)Invalid("printf conversion exceeds bound");
    std::string text(static_cast<size_t>(n)+1,'\0');snprintf(text.data(),text.size(),fmt.c_str(),value);text.resize(n);return text;
}
void StoreCount(Host& host,uint32_t p,int64_t value,const std::string& length){
    if(length=="hh"){auto v=static_cast<int8_t>(value);memcpy(Span(host,p,1),&v,1);}
    else if(length=="h"){auto v=static_cast<int16_t>(value);memcpy(Span(host,p,2),&v,2);}
    else if(length=="ll"||length=="j"){memcpy(Span(host,p,8),&value,8);}
    else{auto v=static_cast<int32_t>(value);memcpy(Span(host,p,4),&v,4);}
}
std::string Format(Host& host,const char* fmt,VarArgs& args){
    if(!fmt)Invalid("null printf format");
    std::string result;
    for(const char* p=fmt;*p;){
        if(*p!='%'){if(result.size()>=1024*1024)Invalid("printf result exceeds bound");result+=*p++;continue;}++p;
        if(*p=='%'){result+='%';++p;continue;}
        std::string spec="%";
        while(*p&&strchr("-+ #0",*p))spec+=*p++;
        auto digits=[&]{unsigned value=0;while(isdigit(static_cast<unsigned char>(*p))){
            value=value*10+(*p-'0');if(value>1024*1024)Invalid("printf field width exceeds bound");spec+=*p++;}};
        if(*p=='*'){int32_t width=args.U32();++p;if(int64_t(width)>1024*1024||int64_t(width)<-1024*1024)Invalid("printf width exceeds bound");spec+=std::to_string(width);}
        else digits();
        if(*p=='.'){
            ++p;
            if(*p=='*'){int32_t precision=args.U32();++p;if(precision>1024*1024)Invalid("printf precision exceeds bound");if(precision>=0)spec+='.'+std::to_string(precision);}
            else {spec+='.';digits();}
        }
        std::string length;
        if(*p=='h'||*p=='l'){length+=*p++;if(*p==length[0])length+=*p++;}
        else if(*p&&strchr("jztL",*p))length+=*p++;
        char c=*p;if(!c)Invalid("incomplete printf format");++p;
        spec+=length;spec+=c;
        if(c=='n'){StoreCount(host,args.U32(),result.size(),length);continue;}
        if(c=='s'){
            if(!length.empty())Invalid("wide printf strings not supported");
            const char* s=String(host,args.U32());result+=PrintValue(spec,s?s:"(null)");
        }else if(c=='c'){
            if(!length.empty())Invalid("wide printf characters not supported");result+=PrintValue(spec,static_cast<int>(args.U32()));
        }else if(c=='p'){
            if(!length.empty())Invalid("printf pointer length");result+=PrintValue(spec,reinterpret_cast<void*>(static_cast<uintptr_t>(args.U32())));
        }else if(strchr("di",c)){
            int64_t v=(length=="ll"||length=="j")?static_cast<int64_t>(args.U64()):static_cast<int32_t>(args.U32());
            if(length=="ll")result+=PrintValue(spec,static_cast<long long>(v));
            else if(length=="j")result+=PrintValue(spec,static_cast<intmax_t>(v));
            else if(length=="l"||length=="z"||length=="t")result+=PrintValue(spec,static_cast<long>(v));
            else result+=PrintValue(spec,static_cast<int>(v));
        }else if(strchr("uoxX",c)){
            uint64_t v=(length=="ll"||length=="j")?args.U64():args.U32();
            if(length=="ll")result+=PrintValue(spec,static_cast<unsigned long long>(v));
            else if(length=="j")result+=PrintValue(spec,static_cast<uintmax_t>(v));
            else if(length=="l"||length=="z"||length=="t")result+=PrintValue(spec,static_cast<unsigned long>(v));
            else result+=PrintValue(spec,static_cast<unsigned>(v));
        }else if(strchr("aAeEfFgG",c)){
            double v=args.F64();result+=length=="L"?PrintValue(spec,static_cast<long double>(v)):PrintValue(spec,v);
        }else Invalid("unsupported printf conversion");
        if(result.size()>1024*1024)Invalid("printf result exceeds bound");
    }
    return result;
}
void PrintToBuffer(Jit& j,Host& h,bool bounded,bool list){
    uint32_t p=j.Regs()[0],size=bounded?j.Regs()[1]:UINT32_MAX;
    const char* fmt=String(h,j.Regs()[bounded?2:1]);
    VarArgs args(j,h,list?j.Regs()[bounded?3:2]:(bounded?3:2),list);
    std::string text=Format(h,fmt,args);
    size_t n=bounded?(size?std::min<size_t>(text.size(),size-1):0):text.size();
    if(!bounded||size){char* out=static_cast<char*>(Span(h,p,n+1));memcpy(out,text.data(),n);out[n]=0;}
    j.Regs()[0]=text.size();
}

// Each scanf conversion is parsed by the host, but values are stored using guest widths.
int Scan(Host& h,const char* input,const char* format,VarArgs& args){
    const char* start=input;int assigned=0;
    while(*format){
        if(isspace(static_cast<unsigned char>(*format))){
            while(isspace(static_cast<unsigned char>(*format)))++format;
            while(isspace(static_cast<unsigned char>(*input)))++input;continue;
        }
        if(*format!='%'){if(*input!=*format)return assigned?assigned:(*input?0:EOF);++input;++format;continue;}
        ++format;if(*format=='%'){if(*input!='%')return assigned?assigned:(*input?0:EOF);++input;++format;continue;}
        bool suppress=*format=='*';if(suppress)++format;
        std::string width;while(isdigit(static_cast<unsigned char>(*format)))width+=*format++;
        std::string length;
        if(*format=='h'||*format=='l'){length+=*format++;if(*format==length[0])length+=*format++;}
        else if(*format&&strchr("jztL",*format))length+=*format++;
        char conversion=*format;if(!conversion)Invalid("incomplete scanf format");++format;
        if(conversion=='n'){if(!suppress)StoreCount(h,args.U32(),input-start,length);continue;}
        if(conversion=='['){
            if(!length.empty())Invalid("wide scanf scansets not supported");
            const bool negate=*format=='^';if(negate)++format;
            std::array<bool,256> members{};
            bool have_previous=false;unsigned char previous=0;
            if(*format==']'){
                members[static_cast<unsigned char>(*format++)]=true;
                previous=']';have_previous=true;
            }
            while(*format&&*format!=']'){
                const auto current=static_cast<unsigned char>(*format);
                if(current=='-'&&have_previous&&format[1]&&format[1]!=']'&&
                   static_cast<unsigned char>(format[1])>=previous){
                    const auto last=static_cast<unsigned char>(format[1]);
                    for(unsigned value=previous;value<=last;++value)members[value]=true;
                    previous=last;format+=2;
                }else{
                    members[current]=true;previous=current;have_previous=true;++format;
                }
            }
            if(*format!=']')Invalid("unterminated scanf scanset");
            ++format;
            size_t limit=strlen(input);
            if(!width.empty()){
                char* end=nullptr;unsigned long long n=strtoull(width.c_str(),&end,10);
                if(!n||n>1024*1024||*end)Invalid("scanf width exceeds bound");
                limit=static_cast<size_t>(n);
            }
            size_t count=0;
            while(count<limit&&input[count]&&
                  (members[static_cast<unsigned char>(input[count])]!=negate))++count;
            if(!count)return assigned?assigned:(*input?0:EOF);
            if(!suppress){
                char* output=static_cast<char*>(Span(h,args.U32(),count+1));
                memcpy(output,input,count);output[count]=0;++assigned;
            }
            input+=count;continue;
        }
        std::string suffix(1,conversion);
        uint32_t destination=suppress?0:args.U32();int consumed=-1;
        if(suppress){std::string spec="%*"+width+length+suffix+"%n";sscanf(input,spec.c_str(),&consumed);}
        else if(conversion=='s'||conversion=='c'){
            if(!length.empty())Invalid("wide scanf strings not supported");
            size_t limit=conversion=='c'?1:strlen(input);
            if(!width.empty()){char* end=nullptr;unsigned long long n=strtoull(width.c_str(),&end,10);
                if(!n||n>1024*1024||*end)Invalid("scanf width exceeds bound");limit=static_cast<size_t>(n);}
            std::vector<char> temporary(limit+1);
            std::string spec="%"+std::to_string(limit)+suffix+"%n";
            sscanf(input,spec.c_str(),temporary.data(),&consumed);
            if(consumed>=0){size_t n=conversion=='c'?std::min<size_t>(limit,consumed):strlen(temporary.data())+1;
                memcpy(Span(h,destination,n),temporary.data(),n);}
        }else if(strchr("di",conversion)){
            long long value=0;std::string spec="%"+width+"ll"+suffix+"%n";
            sscanf(input,spec.c_str(),&value,&consumed);if(consumed>=0)StoreCount(h,destination,value,length);
        }else if(strchr("uoxX",conversion)){
            unsigned long long value=0;std::string spec="%"+width+"ll"+suffix+"%n";
            sscanf(input,spec.c_str(),&value,&consumed);if(consumed>=0)StoreCount(h,destination,static_cast<int64_t>(value),length);
        }else if(strchr("aAeEfFgG",conversion)){
            double value=0;std::string spec="%"+width+"l"+suffix+"%n";
            sscanf(input,spec.c_str(),&value,&consumed);
            if(consumed>=0){if(length=="l"||length=="L")memcpy(Span(h,destination,8),&value,8);
                else{float f=static_cast<float>(value);memcpy(Span(h,destination,4),&f,4);}}
        }else if(conversion=='p'){
            void* value=nullptr;std::string spec="%"+width+"p%n";sscanf(input,spec.c_str(),&value,&consumed);
            if(consumed>=0)StoreCount(h,destination,reinterpret_cast<uintptr_t>(value),"");
        }else Invalid("unsupported scanf conversion");
        if(consumed<0){const char* remaining=input;if(conversion!='c')while(isspace(static_cast<unsigned char>(*remaining)))++remaining;return assigned?assigned:(*remaining?0:EOF);}
        input+=consumed;if(!suppress)++assigned;
    }
    return assigned;
}

void SelfCheck(){
    Mutex recursive(PTHREAD_MUTEX_RECURSIVE),checked(PTHREAD_MUTEX_ERRORCHECK);
    if(pthread_mutex_lock(&recursive.value)||pthread_mutex_lock(&recursive.value)||
       pthread_mutex_unlock(&recursive.value)||pthread_mutex_unlock(&recursive.value))Invalid("recursive mutex self-check");
    if(pthread_mutex_lock(&checked.value)||pthread_mutex_lock(&checked.value)!=EDEADLK||
       pthread_mutex_destroy(&checked.value)!=EBUSY||pthread_mutex_unlock(&checked.value))Invalid("error-check/locked-destroy mutex self-check");
    Semaphore sem(0);
    if(sem_trywait(&sem.value)!=-1 || errno!=EAGAIN || sem_post(&sem.value)||sem_wait(&sem.value))Invalid("semaphore self-check");
    Once once;unsigned calls=0;once.Run([&]{++calls;return true;});once.Run([&]{++calls;return true;});
    if(calls!=1)Invalid("once self-check");
    Condition legacy(CLOCK_MONOTONIC);
    std::atomic<bool> legacy_woke=false;
    std::thread legacy_waiter([&]{legacy.WaitWithoutMutex();legacy_woke=true;});
    auto limit=std::chrono::steady_clock::now()+std::chrono::seconds(1);
    while(!legacy.LegacyWaiters()){
        if(std::chrono::steady_clock::now()>=limit)Invalid("legacy condition registration self-check");
        std::this_thread::yield();
    }
    if(legacy.Signal())Invalid("legacy condition signal self-check");
    legacy_waiter.join();
    if(!legacy_woke.load() || legacy.LegacyWaiters())Invalid("legacy condition wake self-check");
    LOGI("LibcSelfCheck OK: Bionic layouts, mutex types, condition modes, semaphore, once");
}
} // namespace

uint32_t AdoptHostFile(DynarmicHost& host, FILE* stream) {
    return AddFile(host, stream);
}

bool WriteHostStat32(DynarmicHost& host, uint32_t output, const struct stat& value) {
    Span(host, output, sizeof(Stat32));
    return WriteStat(host, output, value);
}

bool GuestSignalPoll(DynarmicHost& host,Dynarmic::A32::Jit& jit){
    return GuestSignalPollImpl(host,jit);
}

void GuestSyncForget(uint32_t addr,uint32_t size){
    const uint64_t end=uint64_t(addr)+size;
    std::lock_guard lock(g_sync_mutex);
    auto forget=[&](auto& table){
        for(auto it=table.begin();it!=table.end();){
            if(it->first>=addr && it->first<end){
                if(it->second.use_count()!=1)Invalid("free of synchronization object in use");
                it=table.erase(it);
            }else ++it;
        }
    };
    forget(g_mutexes);forget(g_conditions);forget(g_semaphores);forget(g_once);
}

void GuestLibcThreadExit(DynarmicHost& host){
    RunTlsDestructors(host);
    for(auto& [_,entry]:t_cache.strings)host.GuestFree(entry.first);
    host.GuestFree(t_cache.tm);host.GuestFree(t_cache.passwd);host.GuestFree(t_cache.hostent);t_cache={};
    if(t_thread && t_thread->external){ForgetThread(t_thread);t_thread.reset();}
}

void ThunkManager::RegisterPosixThunks(){
    m_host.MemoryWrite32(0x100,0x7bd48a31);
    RegisterSymbol("__stack_chk_guard",0x100);
    RegisterSymbol("__sF",0x200);
    memset(Span(m_host,0x200,3*84),0,3*84);
    for(unsigned i=0;i<3;++i){
        uint32_t p=0x200+i*84;
        m_host.MemoryWrite16(p+12,i==0?4:(i==1?8:10));
        m_host.MemoryWrite16(p+14,i);
        // Guest standard streams own duplicates; closing one cannot invalidate host FILEs.
        int fd=dup(static_cast<int>(i));if(fd<0)Invalid("host standard descriptor unavailable");
        FILE* stream=fdopen(fd,i==0?"r":"w");if(!stream){close(fd);Invalid("standard stream duplication");}
        if(setvbuf(stream,nullptr,_IONBF,0))Invalid("standard stream buffering");
        g_standard_fds[i]=fd;g_standard_streams[i]=stream;
        std::lock_guard lock(g_handles_mutex);
        g_files.emplace(p,std::make_shared<File>(stream));
    }
    // Legacy Bionic consumers load a pointer global, then table[unsigned_byte + 1].
    uint32_t ctype=m_host.GuestAlloc(257,4),lower=m_host.GuestAlloc(257*2,4);
    uint32_t ctype_pointer=m_host.GuestAlloc(4,4),lower_pointer=m_host.GuestAlloc(4,4);
    if(!ctype||!lower||!ctype_pointer||!lower_pointer)Invalid("ctype data allocation");
    m_host.MemoryWrite8(ctype,0);m_host.MemoryWrite16(lower,0xffff);
    for(unsigned c=0;c<256;++c){
        m_host.MemoryWrite8(ctype+c+1,CtypeByte(c));
        m_host.MemoryWrite16(lower+2*(c+1),(c>='A'&&c<='Z')?c+('a'-'A'):c);
    }
    m_host.MemoryWrite32(ctype_pointer,ctype);m_host.MemoryWrite32(lower_pointer,lower);
    RegisterSymbol("_ctype_",ctype_pointer);
    RegisterSymbol("_tolower_tab_",lower_pointer);
    uint32_t upper=m_host.GuestAlloc(257*2,4),upper_pointer=m_host.GuestAlloc(4,4);
    if(!upper||!upper_pointer)Invalid("toupper data allocation");
    m_host.MemoryWrite16(upper,0xffff);
    for(unsigned value=0;value<256;++value)m_host.MemoryWrite16(upper+2*(value+1),toupper(value));
    m_host.MemoryWrite32(upper_pointer,upper);RegisterSymbol("_toupper_tab_",upper_pointer);
    RegisterThunk("__errno",[](Jit& j,Host& h){j.Regs()[0]=h.GuestErrnoAddress();});

    RegisterThunk("pthread_create",[](Jit& j,Host& h){j.Regs()[0]=CreateThread(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],j.Regs()[3]);});
    RegisterThunk("pthread_self",[](Jit& j,Host&){j.Regs()[0]=Self();});
    RegisterThunk("pthread_join",[](Jit& j,Host& h){j.Regs()[0]=JoinThread(h,j.Regs()[0],j.Regs()[1]);});
    RegisterThunk("pthread_detach",[](Jit& j,Host&){j.Regs()[0]=DetachThread(j.Regs()[0]);});
    RegisterThunk("pthread_exit",[](Jit& j,Host& h){h.ExitCurrentGuestThread(j.Regs()[0]);});
    RegisterThunk("pthread_attr_init",[](Jit& j,Host& h){
        Attr32 a{0,0,1024*1024,4096,SCHED_OTHER,0};memcpy(Span(h,j.Regs()[0],sizeof(a)),&a,sizeof(a));j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],sizeof(Attr32));j.Regs()[0]=0;});
    RegisterThunk("pthread_attr_getstacksize",[](Jit& j,Host& h){
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->size);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_getschedparam",[](Jit& j,Host& h){
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->priority);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_setschedparam",[](Jit& j,Host& h){
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);int priority=static_cast<int32_t>(h.MemoryRead32(j.Regs()[1]));
        if(priority<sched_get_priority_min(a->policy)||priority>sched_get_priority_max(a->policy)){j.Regs()[0]=EINVAL;return;}
        a->priority=priority;j.Regs()[0]=0;
    });
    RegisterThunk("pthread_setschedparam",[](Jit& j,Host& h){
        auto t=GetThread(j.Regs()[0]);if(!t){j.Regs()[0]=ESRCH;return;}
        Span(h,j.Regs()[2],4);sched_param p{};p.sched_priority=static_cast<int32_t>(h.MemoryRead32(j.Regs()[2]));
        pthread_t native;{std::lock_guard lock(t->mutex);native=t->native;}
        j.Regs()[0]=pthread_setschedparam(native,static_cast<int>(j.Regs()[1]),&p);
    });
    RegisterThunk("pthread_setname_np",[](Jit& j,Host& h){
        auto t=GetThread(j.Regs()[0]);if(!t){j.Regs()[0]=ESRCH;return;}
        const char* name=String(h,j.Regs()[1]);if(!name){j.Regs()[0]=EINVAL;return;}
        pthread_t native;{std::lock_guard lock(t->mutex);native=t->native;}
        j.Regs()[0]=pthread_setname_np(native,name);
    });
    RegisterThunk("pthread_mutexattr_init",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);h.MemoryWrite32(j.Regs()[0],0);j.Regs()[0]=0;});
    RegisterThunk("pthread_mutexattr_destroy",[](Jit& j,Host& h){Span(h,j.Regs()[0],4);j.Regs()[0]=0;});
    RegisterThunk("pthread_mutexattr_settype",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);if(j.Regs()[1]>2){j.Regs()[0]=EINVAL;return;}
        h.MemoryWrite32(j.Regs()[0],j.Regs()[1]);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_mutex_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];Span(h,p,4);int type=0;
        if(j.Regs()[1]){Span(h,j.Regs()[1],4);type=h.MemoryRead32(j.Regs()[1]);}
        if(type<0||type>2){j.Regs()[0]=ENOTSUP;return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_mutexes.count(p)){j.Regs()[0]=EBUSY;return;}
        g_mutexes.emplace(p,std::make_shared<Mutex>(type));h.MemoryWrite32(p,type<<14);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_mutex_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto value=GetMutex(h,p);if(!value){j.Regs()[0]=errno;return;}
        std::lock_guard lock(g_sync_mutex);
        if(value.use_count()!=2){j.Regs()[0]=EBUSY;return;}
        int rc=pthread_mutex_destroy(&value->value);
        if(!rc){value->live=false;g_mutexes.erase(p);h.MemoryWrite32(p,0xdeadc0de);}
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_mutex_lock",[](Jit& j,Host& h){uint32_t p=j.Regs()[0];auto m=GetMutex(h,p);int result=m?pthread_mutex_lock(&m->value):errno;GrimFramePacing::GuestMutexLocked(p,result);j.Regs()[0]=result;});
    RegisterThunk("pthread_mutex_trylock",[](Jit& j,Host& h){uint32_t p=j.Regs()[0];auto m=GetMutex(h,p);int result=m?pthread_mutex_trylock(&m->value):errno;GrimFramePacing::GuestMutexLocked(p,result);j.Regs()[0]=result;});
    RegisterThunk("pthread_mutex_unlock",[](Jit& j,Host& h){uint32_t p=j.Regs()[0];auto m=GetMutex(h,p);int result=m?pthread_mutex_unlock(&m->value):errno;GrimFramePacing::GuestMutexUnlocked(p,result);j.Regs()[0]=result;});
    RegisterThunk("pthread_cond_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],word=0;Span(h,p,4);
        if(j.Regs()[1]){Span(h,j.Regs()[1],4);word=h.MemoryRead32(j.Regs()[1]);}
        if(word&~2u){j.Regs()[0]=ENOTSUP;return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_conditions.count(p)){j.Regs()[0]=EBUSY;return;}
        g_conditions.emplace(p,std::make_shared<Condition>((word&2)?CLOCK_MONOTONIC:CLOCK_REALTIME));
        h.MemoryWrite32(p,word);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_cond_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto value=GetCondition(h,p);if(!value){j.Regs()[0]=errno;return;}
        std::lock_guard lock(g_sync_mutex);
        if(value.use_count()!=2){j.Regs()[0]=EBUSY;return;}
        int rc=pthread_cond_destroy(&value->value);
        if(!rc){value->live=false;g_conditions.erase(p);h.MemoryWrite32(p,0xdeadc0de);}
        j.Regs()[0]=rc;
    });
    RegisterThunk("pthread_cond_wait",[](Jit& j,Host& h){j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],0,false);});
    RegisterThunk("pthread_cond_timedwait",[](Jit& j,Host& h){
        if(!j.Regs()[2]){j.Regs()[0]=EINVAL;return;}
        j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],false);
    });
    RegisterThunk("pthread_cond_timeout_np",[](Jit& j,Host& h){j.Regs()[0]=WaitCondition(h,j.Regs()[0],j.Regs()[1],j.Regs()[2],true);});
    RegisterThunk("pthread_cond_signal",[](Jit& j,Host& h){auto c=GetCondition(h,j.Regs()[0]);j.Regs()[0]=c?c->Signal():errno;});
    RegisterThunk("pthread_cond_broadcast",[](Jit& j,Host& h){auto c=GetCondition(h,j.Regs()[0]);j.Regs()[0]=c?c->Broadcast():errno;});
    RegisterThunk("pthread_once",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],fn=j.Regs()[1];Span(h,p,4);
        if(!fn){j.Regs()[0]=EINVAL;return;}
        std::shared_ptr<Once> once;
        {std::lock_guard lock(g_sync_mutex);auto& slot=g_once[p];
            if(!slot){slot=std::make_shared<Once>();uint32_t state=h.MemoryRead32(p);
                if(state!=0&&state!=2)Invalid("unknown pthread_once state");slot->state=state;}
            once=slot;
        }
        once->Run([&]{h.MemoryWrite32(p,1);h.CallGuestNested(fn,{});
            bool complete=!h.IsCurrentGuestThreadExiting();h.MemoryWrite32(p,complete?2:0);return complete;});
        j.Regs()[0]=0;
    });
    RegisterThunk("pthread_key_create",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);std::lock_guard lock(g_keys_mutex);
        if(g_keys.size()>=128||!g_next_key){j.Regs()[0]=EAGAIN;return;}
        uint32_t key=g_next_key++;g_keys.emplace(key,Key{j.Regs()[1]});h.MemoryWrite32(j.Regs()[0],key);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_key_delete",[](Jit& j,Host&){
        uint32_t key=j.Regs()[0];std::lock_guard lock(g_keys_mutex);
        if(!g_keys.erase(key)){j.Regs()[0]=EINVAL;return;}t_keys.erase(key);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_setspecific",[](Jit& j,Host&){
        std::lock_guard lock(g_keys_mutex);
        if(!g_keys.count(j.Regs()[0])){j.Regs()[0]=EINVAL;return;}
        for(auto it=t_keys.begin();it!=t_keys.end();)if(!g_keys.count(it->first))it=t_keys.erase(it);else ++it;
        t_keys[j.Regs()[0]]=j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_getspecific",[](Jit& j,Host&){
        std::lock_guard lock(g_keys_mutex);auto it=t_keys.find(j.Regs()[0]);
        j.Regs()[0]=g_keys.count(j.Regs()[0])&&it!=t_keys.end()?it->second:0;
    });
    RegisterThunk("sem_init",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];Span(h,p,4);
        if(j.Regs()[1]){Failure(j,h,ENOTSUP);return;}
        if(j.Regs()[2]>INT_MAX){Failure(j,h,EINVAL);return;}
        std::lock_guard lock(g_sync_mutex);
        if(g_semaphores.count(p)){Failure(j,h,EBUSY);return;}
        g_semaphores.emplace(p,std::make_shared<Semaphore>(j.Regs()[2]));h.MemoryWrite32(p,0);j.Regs()[0]=0;
    });
    RegisterThunk("sem_destroy",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto sem=GetSemaphore(p);if(!sem){Failure(j,h,EINVAL);return;}
        std::lock_guard lock(g_sync_mutex);
        if(sem.use_count()!=2){Failure(j,h,EBUSY);return;}
        int rc=sem_destroy(&sem->value);if(!rc){sem->live=false;g_semaphores.erase(p);h.MemoryWrite32(p,0xdeadc0de);}Result(j,h,rc);
    });
    RegisterThunk("sem_wait",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_wait(&s->value):-1);});
    RegisterThunk("sem_trywait",[](Jit& j,Host& h){auto s=GetSemaphore(j.Regs()[0]);Result(j,h,s?sem_trywait(&s->value):-1);});
    RegisterThunk("sem_post",[](Jit& j,Host& h){
        int result=-1,saved_errno=EINVAL;
        {
            // SDL may destroy/free its startup semaphore as soon as the wait
            // wakes. Finish publication before its registry lookup can retire
            // the object; a completed post must not leave a shared_ptr tail.
            std::lock_guard lock(g_sync_mutex);
            auto found=g_semaphores.find(j.Regs()[0]);
            if(found!=g_semaphores.end()){
                result=sem_post(&found->second->value);saved_errno=errno;
            }
        }
        errno=saved_errno;Result(j,h,result);
    });
    RegisterThunk("sem_getvalue",[](Jit& j,Host& h){
        auto s=GetSemaphore(j.Regs()[0]);if(!s){Failure(j,h,EINVAL);return;}
        Span(h,j.Regs()[1],4);int value=0;int rc=sem_getvalue(&s->value,&value);
        if(!rc)h.MemoryWrite32(j.Regs()[1],value);Result(j,h,rc);
    });
    RegisterThunk("malloc",[](Jit& j,Host& h){uint32_t p=h.GuestAlloc(j.Regs()[0],8);if(!p)Errno(h,ENOMEM);j.Regs()[0]=p;});
    RegisterThunk("calloc",[](Jit& j,Host& h){
        uint64_t bytes=uint64_t(j.Regs()[0])*j.Regs()[1];
        if(bytes>UINT32_MAX){Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        uint32_t p=h.GuestAlloc(bytes,8);if(p)memset(Span(h,p,bytes),0,bytes);else Errno(h,ENOMEM);j.Regs()[0]=p;
    });
    RegisterThunk("free",[](Jit& j,Host& h){h.GuestFree(j.Regs()[0]);});
    RegisterThunk("realloc",[](Jit& j,Host& h){
        uint32_t old=j.Regs()[0],size=j.Regs()[1];
        if(!size){h.GuestFree(old);j.Regs()[0]=0;return;}
        uint32_t next=h.GuestAlloc(size,8);
        if(!next){Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        if(old){size_t n=std::min(size,h.GuestAllocSize(old));if(n)memcpy(Span(h,next,n),Span(h,old,n),n);h.GuestFree(old);}
        j.Regs()[0]=next;
    });
    RegisterThunk("memcpy",[](Jit& j,Host& h){size_t n=j.Regs()[2];if(n)memcpy(Span(h,j.Regs()[0],n),Span(h,j.Regs()[1],n),n);});
    RegisterThunk("memmove",[](Jit& j,Host& h){size_t n=j.Regs()[2];if(n)memmove(Span(h,j.Regs()[0],n),Span(h,j.Regs()[1],n),n);});
    RegisterThunk("memset",[](Jit& j,Host& h){size_t n=j.Regs()[2];if(n)memset(Span(h,j.Regs()[0],n),j.Regs()[1],n);});
    RegisterThunk("memcmp",[](Jit& j,Host& h){size_t n=j.Regs()[2];j.Regs()[0]=n?memcmp(Span(h,j.Regs()[0],n),Span(h,j.Regs()[1],n),n):0;});
    RegisterThunk("memchr",[](Jit& j,Host& h){size_t n=j.Regs()[2];void* p=n?memchr(Span(h,j.Regs()[0],n),j.Regs()[1],n):nullptr;j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("memrchr",[](Jit& j,Host& h){size_t n=j.Regs()[2];void* p=n?memrchr(Span(h,j.Regs()[0],n),j.Regs()[1],n):nullptr;j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strlen",[](Jit& j,Host& h){const char* s=String(h,j.Regs()[0]);if(!s)Invalid("strlen null");j.Regs()[0]=strlen(s);});
    RegisterThunk("strcmp",[](Jit& j,Host& h){j.Regs()[0]=strcmp(String(h,j.Regs()[0]),String(h,j.Regs()[1]));});
    RegisterThunk("strncmp",[](Jit& j,Host& h){size_t n=j.Regs()[2];j.Regs()[0]=n?strncmp(BoundedString(h,j.Regs()[0],n),BoundedString(h,j.Regs()[1],n),n):0;});
    RegisterThunk("strcasecmp",[](Jit& j,Host& h){j.Regs()[0]=strcasecmp(String(h,j.Regs()[0]),String(h,j.Regs()[1]));});
    RegisterThunk("strncasecmp",[](Jit& j,Host& h){size_t n=j.Regs()[2];j.Regs()[0]=n?strncasecmp(BoundedString(h,j.Regs()[0],n),BoundedString(h,j.Regs()[1],n),n):0;});
    RegisterThunk("strcpy",[](Jit& j,Host& h){const char* s=String(h,j.Regs()[1]);size_t n=strlen(s)+1;memcpy(Span(h,j.Regs()[0],n),s,n);});
    RegisterThunk("strncpy",[](Jit& j,Host& h){size_t n=j.Regs()[2];if(n)strncpy(static_cast<char*>(Span(h,j.Regs()[0],n)),BoundedString(h,j.Regs()[1],n),n);});
    RegisterThunk("strcat",[](Jit& j,Host& h){const char* s=String(h,j.Regs()[1]);size_t n=strlen(String(h,j.Regs()[0]))+strlen(s)+1;strcat(static_cast<char*>(Span(h,j.Regs()[0],n)),s);});
    RegisterThunk("strncat",[](Jit& j,Host& h){size_t limit=j.Regs()[2];if(!limit)return;const char* s=BoundedString(h,j.Regs()[1],limit);size_t n=strlen(String(h,j.Regs()[0]))+strnlen(s,limit)+1;strncat(static_cast<char*>(Span(h,j.Regs()[0],n)),s,limit);});
    RegisterThunk("strlcat",[](Jit& j,Host& h){j.Regs()[0]=strlcat(static_cast<char*>(Span(h,j.Regs()[0],j.Regs()[2])),String(h,j.Regs()[1]),j.Regs()[2]);});
    RegisterThunk("strdup",[](Jit& j,Host& h){uint32_t p=CopyString(h,String(h,j.Regs()[0]));if(!p)Errno(h,ENOMEM);j.Regs()[0]=p;});
    RegisterThunk("strchr",[](Jit& j,Host& h){const char* p=strchr(String(h,j.Regs()[0]),j.Regs()[1]);j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strrchr",[](Jit& j,Host& h){const char* p=strrchr(String(h,j.Regs()[0]),j.Regs()[1]);j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strstr",[](Jit& j,Host& h){const char* p=strstr(String(h,j.Regs()[0]),String(h,j.Regs()[1]));j.Regs()[0]=p?Address(h,p):0;});
    RegisterThunk("strtok_r",[](Jit& j,Host& h){
        uint32_t save=j.Regs()[2];Span(h,save,4);char* next=const_cast<char*>(String(h,h.MemoryRead32(save)));
        char* token=strtok_r(const_cast<char*>(String(h,j.Regs()[0])),String(h,j.Regs()[1]),&next);
        h.MemoryWrite32(save,next?Address(h,next):0);j.Regs()[0]=token?Address(h,token):0;
    });
    RegisterThunk("strtok",[](Jit& j,Host& h){
        char* next=const_cast<char*>(String(h,t_cache.strtok_next));
        char* token=strtok_r(const_cast<char*>(String(h,j.Regs()[0])),String(h,j.Regs()[1]),&next);
        t_cache.strtok_next=next?Address(h,next):0;j.Regs()[0]=token?Address(h,token):0;
    });
    RegisterThunk("atoi",[](Jit& j,Host& h){j.Regs()[0]=atoi(String(h,j.Regs()[0]));});
    RegisterThunk("strtol",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],out=j.Regs()[1];char* end=nullptr;errno=0;
        long long value=strtoll(String(h,p),&end,static_cast<int>(j.Regs()[2]));
        if(value>INT32_MAX){value=INT32_MAX;errno=ERANGE;}else if(value<INT32_MIN){value=INT32_MIN;errno=ERANGE;}
        if(out){Span(h,out,4);h.MemoryWrite32(out,Address(h,end));}
        if(errno)Errno(h,errno);j.Regs()[0]=static_cast<uint32_t>(value);
    });
    RegisterThunk("strtoul",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],out=j.Regs()[1];const char* s=String(h,p);char* end=nullptr;errno=0;
        uint64_t value=strtoull(s,&end,static_cast<int>(j.Regs()[2]));while(isspace(static_cast<unsigned char>(*s)))++s;
        bool negative=*s=='-';uint64_t magnitude=negative?uint64_t(0)-value:value;
        if(errno==ERANGE||magnitude>UINT32_MAX){value=UINT32_MAX;errno=ERANGE;}
        if(out){Span(h,out,4);h.MemoryWrite32(out,Address(h,end));}
        if(errno)Errno(h,errno);j.Regs()[0]=static_cast<uint32_t>(value);
    });
    RegisterThunk("strtod",[](Jit& j,Host& h){
        uint32_t out=j.Regs()[1];char* end=nullptr;errno=0;double value=strtod(String(h,j.Regs()[0]),&end);
        if(out){Span(h,out,4);h.MemoryWrite32(out,Address(h,end));}
        if(errno)Errno(h,errno);WriteDF(j,0,value);
    });
    RegisterThunk("isspace",[](Jit& j,Host&){int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?isspace(c):0;});
    RegisterThunk("toupper",[](Jit& j,Host&){int c=static_cast<int32_t>(j.Regs()[0]);j.Regs()[0]=(c>=0&&c<=255)?toupper(c):c;});
    RegisterThunk("qsort",[](Jit& j,Host& h){
        uint32_t base=j.Regs()[0],count=j.Regs()[1],size=j.Regs()[2],compare=j.Regs()[3];
        if(count<2||!size)return;if(!compare)Invalid("qsort comparator");
        size_t bytes=uint64_t(count)*size;auto* data=static_cast<uint8_t*>(Span(h,base,bytes));
        std::vector<uint8_t> original(data,data+bytes);std::vector<uint32_t> order(count);
        for(uint32_t i=0;i<count;++i)order[i]=i;
        std::sort(order.begin(),order.end(),[&](uint32_t a,uint32_t b){return static_cast<int32_t>(h.CallGuestNested(compare,{base+a*size,base+b*size}))<0;});
        for(uint32_t i=0;i<count;++i)memcpy(data+size_t(i)*size,original.data()+size_t(order[i])*size,size);
    });
    RegisterThunk("bsearch",[](Jit& j,Host& h){
        uint32_t key=j.Regs()[0],base=j.Regs()[1],count=j.Regs()[2],size=j.Regs()[3];
        uint32_t compare=h.ReadStackWord(j,0);j.Regs()[0]=0;
        if(!count||!size)return;if(!compare)Invalid("bsearch comparator");Span(h,base,uint64_t(count)*size);
        uint32_t low=0,high=count;while(low<high){uint32_t mid=low+(high-low)/2,p=base+mid*size;
            int32_t value=h.CallGuestNested(compare,{key,p});if(!value){j.Regs()[0]=p;return;}if(value<0)high=mid;else low=mid+1;}
    });
    RegisterThunk("sin",[](Jit& j,Host&){WriteDF(j,0,sin(ReadDF(j,0)));});
    RegisterThunk("cos",[](Jit& j,Host&){WriteDF(j,0,cos(ReadDF(j,0)));});
    RegisterThunk("tan",[](Jit& j,Host&){WriteDF(j,0,tan(ReadDF(j,0)));});
    RegisterThunk("acos",[](Jit& j,Host&){WriteDF(j,0,acos(ReadDF(j,0)));});
    RegisterThunk("asin",[](Jit& j,Host&){WriteDF(j,0,asin(ReadDF(j,0)));});
    RegisterThunk("ceil",[](Jit& j,Host&){WriteDF(j,0,ceil(ReadDF(j,0)));});
    RegisterThunk("floor",[](Jit& j,Host&){WriteDF(j,0,floor(ReadDF(j,0)));});
    RegisterThunk("exp",[](Jit& j,Host&){WriteDF(j,0,exp(ReadDF(j,0)));});
    RegisterThunk("log",[](Jit& j,Host&){WriteDF(j,0,log(ReadDF(j,0)));});
    RegisterThunk("log10",[](Jit& j,Host&){WriteDF(j,0,log10(ReadDF(j,0)));});
    RegisterThunk("fmod",[](Jit& j,Host&){WriteDF(j,0,fmod(ReadDF(j,0),ReadDF(j,1)));});
    RegisterThunk("pow",[](Jit& j,Host&){WriteDF(j,0,pow(ReadDF(j,0),ReadDF(j,1)));});
    RegisterThunk("sinf",[](Jit& j,Host&){WriteSF(j,0,sinf(ReadSF(j,0)));});
    RegisterThunk("cosf",[](Jit& j,Host&){WriteSF(j,0,cosf(ReadSF(j,0)));});
    RegisterThunk("tanf",[](Jit& j,Host&){WriteSF(j,0,tanf(ReadSF(j,0)));});
    RegisterThunk("acosf",[](Jit& j,Host&){WriteSF(j,0,acosf(ReadSF(j,0)));});
    RegisterThunk("asinf",[](Jit& j,Host&){WriteSF(j,0,asinf(ReadSF(j,0)));});
    RegisterThunk("atanf",[](Jit& j,Host&){WriteSF(j,0,atanf(ReadSF(j,0)));});
    RegisterThunk("ceilf",[](Jit& j,Host&){WriteSF(j,0,ceilf(ReadSF(j,0)));});
    RegisterThunk("floorf",[](Jit& j,Host&){WriteSF(j,0,floorf(ReadSF(j,0)));});
    RegisterThunk("expf",[](Jit& j,Host&){WriteSF(j,0,expf(ReadSF(j,0)));});
    RegisterThunk("logf",[](Jit& j,Host&){WriteSF(j,0,logf(ReadSF(j,0)));});
    RegisterThunk("log10f",[](Jit& j,Host&){WriteSF(j,0,log10f(ReadSF(j,0)));});
    RegisterThunk("fmodf",[](Jit& j,Host&){WriteSF(j,0,fmodf(ReadSF(j,0),ReadSF(j,1)));});
    RegisterThunk("powf",[](Jit& j,Host&){WriteSF(j,0,powf(ReadSF(j,0),ReadSF(j,1)));});
    RegisterThunk("atan2f",[](Jit& j,Host&){WriteSF(j,0,atan2f(ReadSF(j,0),ReadSF(j,1)));});
    RegisterThunk("lrand48",[](Jit& j,Host&){j.Regs()[0]=static_cast<uint32_t>(lrand48());});
    RegisterThunk("__android_log_print",[](Jit& j,Host& h){
        int priority=j.Regs()[0];const char* tag=String(h,j.Regs()[1]);VarArgs args(j,h,3);
        std::string text=Format(h,String(h,j.Regs()[2]),args);j.Regs()[0]=__android_log_write(priority,tag?tag:"Arm32Guest",text.c_str());
    });
    RegisterThunk("__android_log_vprint",[](Jit& j,Host& h){
        int priority=j.Regs()[0];const char* tag=String(h,j.Regs()[1]);VarArgs args(j,h,j.Regs()[3],true);
        std::string text=Format(h,String(h,j.Regs()[2]),args);j.Regs()[0]=__android_log_write(priority,tag?tag:"Arm32Guest",text.c_str());
    });
    RegisterThunk("printf",[](Jit& j,Host& h){VarArgs args(j,h,1);std::string text=Format(h,String(h,j.Regs()[0]),args);Result(j,h,WithFile(0x254,-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));});
    RegisterThunk("fprintf",[](Jit& j,Host& h){
        uint32_t file=j.Regs()[0];VarArgs args(j,h,2);std::string text=Format(h,String(h,j.Regs()[1]),args);
        Result(j,h,WithFile(file,-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));
    });
    RegisterThunk("sprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,false,false);});
    RegisterThunk("snprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,true,false);});
    RegisterThunk("vsprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,false,true);});
    RegisterThunk("vsnprintf",[](Jit& j,Host& h){PrintToBuffer(j,h,true,true);});
    RegisterThunk("sscanf",[](Jit& j,Host& h){VarArgs args(j,h,2);j.Regs()[0]=Scan(h,String(h,j.Regs()[0]),String(h,j.Regs()[1]),args);});
    RegisterThunk("puts",[](Jit& j,Host& h){std::string text=String(h,j.Regs()[0]);text+='\n';Result(j,h,WithFile(0x254,-1,[&](FILE* f){return LogWrite(f,text.data(),text.size());}));});
    RegisterThunk("fputs",[](Jit& j,Host& h){const char* text=String(h,j.Regs()[0]);Result(j,h,WithFile(j.Regs()[1],-1,[&](FILE* f){return LogWrite(f,text,strlen(text));}));});
    RegisterThunk("putchar",[](Jit& j,Host& h){char c=j.Regs()[0];int rc=WithFile(0x254,-1,[&](FILE* f){return LogWrite(f,&c,1);});Result(j,h,rc<0?-1:static_cast<unsigned char>(c));});
    RegisterThunk("fputc",[](Jit& j,Host& h){char c=j.Regs()[0];int rc=WithFile(j.Regs()[1],-1,[&](FILE* f){return LogWrite(f,&c,1);});Result(j,h,rc<0?-1:static_cast<unsigned char>(c));});
    RegisterThunk("fgetc",[](Jit& j,Host& h){Result(j,h,WithFile(j.Regs()[0],EOF,[](FILE* f){return fgetc(f);}));});
    RegisterThunk("fgets",[](Jit& j,Host& h){
        uint32_t output=j.Regs()[0];int size=static_cast<int32_t>(j.Regs()[1]);if(size<=0){j.Regs()[0]=0;Errno(h,EINVAL);return;}
        char* p=static_cast<char*>(Span(h,output,size));char* result=WithFile(j.Regs()[2],static_cast<char*>(nullptr),[&](FILE* f){return fgets(p,size,f);});
        if(!result)Errno(h,errno);j.Regs()[0]=result?output:0;
    });
    RegisterThunk("perror",[](Jit& j,Host& h){
        int error=h.MemoryRead32(h.GuestErrnoAddress());const char* prefix=String(h,j.Regs()[0]);
        LOGE("%s%s%s",prefix?prefix:"",prefix&&*prefix?": ":"",strerror(error));
    });
    RegisterThunk("fopen",[](Jit& j,Host& h){
        const char* path=String(h,j.Regs()[0]);const char* mode=String(h,j.Regs()[1]);
        if(!path||!mode){Errno(h,EINVAL);j.Regs()[0]=0;return;}
        FILE* f=BridgeFopen(path,mode);uint32_t result=AddFile(h,f);if(!result)Errno(h,errno);j.Regs()[0]=result;
    });
    RegisterThunk("fclose",[](Jit& j,Host& h){Result(j,h,CloseFile(h,j.Regs()[0]));});
    RegisterThunk("fflush",[](Jit& j,Host& h){
        if(j.Regs()[0]){Result(j,h,WithFile(j.Regs()[0],EOF,[](FILE* f){return fflush(f);}));return;}
        std::vector<std::shared_ptr<File>> files;{std::lock_guard lock(g_handles_mutex);for(auto& [_,f]:g_files)files.push_back(f);}
        int error=0;for(auto& f:files){std::lock_guard lock(f->mutex);if(f->stream&&fflush(f->stream))error=errno;}
        if(error)Failure(j,h,error);else j.Regs()[0]=0;
    });
    RegisterThunk("fread",[](Jit& j,Host& h){
        size_t size=j.Regs()[1],count=j.Regs()[2];void* p=Span(h,j.Regs()[0],uint64_t(size)*count);
        size_t n=WithFile(j.Regs()[3],size_t(0),[&](FILE* f){return fread(p,size,count,f);});
        if(n<count)Errno(h,errno);j.Regs()[0]=n;
    });
    RegisterThunk("fwrite",[](Jit& j,Host& h){
        size_t size=j.Regs()[1],count=j.Regs()[2];const char* p=static_cast<const char*>(Span(h,j.Regs()[0],uint64_t(size)*count));
        if(!size||!count){j.Regs()[0]=0;return;}
        size_t n=WithFile(j.Regs()[3],size_t(0),[&](FILE* f){
            if((f==g_standard_streams[1]&&g_standard_fds[1]>=0)||(f==g_standard_streams[2]&&g_standard_fds[2]>=0))return LogWrite(f,p,size*count)<0?size_t(0):count;return fwrite(p,size,count,f);});
        if(n<count)Errno(h,errno);j.Regs()[0]=n;
    });
    RegisterThunk("fseek",[](Jit& j,Host& h){
        int32_t offset=j.Regs()[1];int whence=j.Regs()[2];Result(j,h,WithFile(j.Regs()[0],-1,[&](FILE* f){return fseeko(f,offset,whence);}));
    });
    RegisterThunk("ftell",[](Jit& j,Host& h){
        off_t value=WithFile(j.Regs()[0],off_t(-1),[](FILE* f){return ftello(f);});
        if(value>INT32_MAX){Failure(j,h,EOVERFLOW);return;}Result(j,h,value);
    });





    RegisterThunk("access",[](Jit& j,Host& h){Result(j,h,access(String(h,j.Regs()[0]),j.Regs()[1]));});
    RegisterThunk("mkdir",[](Jit& j,Host& h){Result(j,h,mkdir(String(h,j.Regs()[0]),j.Regs()[1]));});
    RegisterThunk("umask",[](Jit& j,Host&){j.Regs()[0]=umask(j.Regs()[0]);});
    RegisterThunk("flock",[](Jit& j,Host& h){Result(j,h,flock(NativeFd(static_cast<int>(j.Regs()[0])),static_cast<int>(j.Regs()[1])));});
    RegisterThunk("stat",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[1];Span(h,p,sizeof(Stat32));struct stat value{};
        int rc=stat(String(h,j.Regs()[0]),&value);if(!rc&&!WriteStat(h,p,value))rc=-1;Result(j,h,rc);
    });

    RegisterThunk("opendir",[](Jit& j,Host& h){
        DIR* directory=opendir(String(h,j.Regs()[0]));if(!directory){Errno(h,errno);j.Regs()[0]=0;return;}
        uint32_t p=h.GuestAlloc(sizeof(Dirent32),8);if(!p){closedir(directory);Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        {std::lock_guard lock(g_handles_mutex);g_dirs.emplace(p,std::make_shared<Directory>(directory,p));}j.Regs()[0]=p;
    });
    RegisterThunk("readdir",[](Jit& j,Host& h){
        auto d=Lookup(g_dirs,j.Regs()[0]);if(!d){Errno(h,EBADF);j.Regs()[0]=0;return;}
        std::lock_guard lock(d->mutex);if(!d->directory){Errno(h,EBADF);j.Regs()[0]=0;return;}
        errno=0;dirent* entry=readdir(d->directory);if(!entry){if(errno)Errno(h,errno);j.Regs()[0]=0;return;}
        Dirent32 g{};g.ino=entry->d_ino;g.off=entry->d_off;g.reclen=sizeof(g);g.type=entry->d_type;
        memcpy(g.name,entry->d_name,strnlen(entry->d_name,255));memcpy(Span(h,d->entry,sizeof(g)),&g,sizeof(g));j.Regs()[0]=d->entry;
    });
    RegisterThunk("closedir",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto d=Lookup(g_dirs,p);if(!d){Failure(j,h,EBADF);return;}
        int rc;{std::lock_guard lock(d->mutex);if(!d->directory){Failure(j,h,EBADF);return;}rc=closedir(d->directory);d->directory=nullptr;}
        int saved=errno;{std::lock_guard lock(g_handles_mutex);g_dirs.erase(p);}h.GuestFree(d->entry);errno=saved;Result(j,h,rc);
    });
    RegisterThunk("gzopen",[](Jit& j,Host& h){
        gzFile file=gzopen(String(h,j.Regs()[0]),String(h,j.Regs()[1]));if(!file){Errno(h,errno);j.Regs()[0]=0;return;}
        uint32_t p=h.GuestAlloc(4,4);if(!p){gzclose(file);Errno(h,ENOMEM);j.Regs()[0]=0;return;}
        {std::lock_guard lock(g_handles_mutex);g_gzip.emplace(p,std::make_shared<Gzip>(file));}j.Regs()[0]=p;
    });
    RegisterThunk("gzgets",[](Jit& j,Host& h){
        auto g=Lookup(g_gzip,j.Regs()[0]);uint32_t p=j.Regs()[1];int length=static_cast<int32_t>(j.Regs()[2]);
        if(!g||length<=0){Errno(h,EINVAL);j.Regs()[0]=0;return;}
        std::lock_guard lock(g->mutex);if(!g->file){Errno(h,EBADF);j.Regs()[0]=0;return;}
        char* result=gzgets(g->file,static_cast<char*>(Span(h,p,length)),length);if(!result)Errno(h,errno);j.Regs()[0]=result?p:0;
    });
    RegisterThunk("gzclose",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];auto g=Lookup(g_gzip,p);if(!g){j.Regs()[0]=Z_STREAM_ERROR;return;}
        int rc;{std::lock_guard lock(g->mutex);if(!g->file){j.Regs()[0]=Z_STREAM_ERROR;return;}rc=gzclose(g->file);g->file=nullptr;}
        {std::lock_guard lock(g_handles_mutex);g_gzip.erase(p);}h.GuestFree(p);j.Regs()[0]=rc;
    });
    RegisterThunk("clock_gettime",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[1];Span(h,p,8);timespec value{};int rc=clock_gettime(static_cast<clockid_t>(j.Regs()[0]),&value);
        if(!rc&&!WriteTime(h,p,value))rc=-1;Result(j,h,rc);
    });
    RegisterThunk("gettimeofday",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0],tzp=j.Regs()[1];if(p)Span(h,p,8);if(tzp)Span(h,tzp,8);
        timeval tv{};struct timezone tz{};int rc=gettimeofday(&tv,tzp?&tz:nullptr);
        if(!rc&&p){if(tv.tv_sec>INT32_MAX||tv.tv_sec<INT32_MIN){Failure(j,h,EOVERFLOW);return;}
            h.MemoryWrite32(p,static_cast<uint32_t>(tv.tv_sec));h.MemoryWrite32(p+4,static_cast<uint32_t>(tv.tv_usec));}
        if(!rc&&tzp){h.MemoryWrite32(tzp,tz.tz_minuteswest);h.MemoryWrite32(tzp+4,tz.tz_dsttime);}Result(j,h,rc);
    });
    RegisterThunk("nanosleep",[](Jit& j,Host& h){
        timespec request{},remaining{};uint32_t output=j.Regs()[1];if(output)Span(h,output,8);
        if(!ReadTime(h,j.Regs()[0],request)||request.tv_sec<0){Failure(j,h,EINVAL);return;}
        int rc=nanosleep(&request,output?&remaining:nullptr);int saved=errno;
        if(rc<0&&saved==EINTR&&output)WriteTime(h,output,remaining);errno=saved;Result(j,h,rc);
    });
    RegisterThunk("usleep",[](Jit& j,Host& h){Result(j,h,usleep(j.Regs()[0]));});
    RegisterThunk("sleep",[](Jit& j,Host& h){unsigned remaining=sleep(j.Regs()[0]);if(remaining)Errno(h,errno);j.Regs()[0]=remaining;});
    RegisterThunk("time",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];if(p)Span(h,p,4);time_t value=time(nullptr);
        if(value>INT32_MAX||value<INT32_MIN){Failure(j,h,EOVERFLOW);return;}
        if(p)h.MemoryWrite32(p,static_cast<uint32_t>(value));Result(j,h,value);
    });
    RegisterThunk("localtime",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm result{};
        if(!localtime_r(&value,&result)){Errno(h,errno);j.Regs()[0]=0;return;}
        if(!t_cache.tm)t_cache.tm=h.GuestAlloc(sizeof(Tm32),4);
        if(!t_cache.tm){Errno(h,ENOMEM);j.Regs()[0]=0;return;}WriteTm(h,t_cache.tm,result);j.Regs()[0]=t_cache.tm;
    });
    RegisterThunk("gmtime_r",[](Jit& j,Host& h){
        Span(h,j.Regs()[0],4);uint32_t p=j.Regs()[1];Span(h,p,sizeof(Tm32));time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm result{};
        if(!gmtime_r(&value,&result)){Errno(h,errno);j.Regs()[0]=0;return;}WriteTm(h,p,result);j.Regs()[0]=p;
    });
    RegisterThunk("getenv",[](Jit& j,Host& h){const char* name=String(h,j.Regs()[0]);const char* value=getenv(name);j.Regs()[0]=CachedString(h,std::string("env:")+name,value);});
    RegisterThunk("strerror",[](Jit& j,Host& h){int error=j.Regs()[0];j.Regs()[0]=CachedString(h,"strerror",strerror(error));});
    RegisterThunk("strerror_r",[](Jit& j,Host& h){
        char* p=static_cast<char*>(Span(h,j.Regs()[1],j.Regs()[2]));j.Regs()[0]=BionicStrerrorR(j.Regs()[0],p,j.Regs()[2]);
    });
    RegisterThunk("basename",[](Jit& j,Host& h){
        const char* path=String(h,j.Regs()[0]);char* value=basename(const_cast<char*>(path));
        uintptr_t address=reinterpret_cast<uintptr_t>(value),base=reinterpret_cast<uintptr_t>(h.GetGuestMemoryBase());
        j.Regs()[0]=(address>=base&&address-base<h.GetGuestMemorySize())?Address(h,value):CachedString(h,"basename",value);
    });
    RegisterThunk("getpwuid",[](Jit& j,Host& h){
        passwd* pw=getpwuid(static_cast<uid_t>(j.Regs()[0]));if(!pw){Errno(h,errno);j.Regs()[0]=0;return;}
        const char* strings[]={pw->pw_name,pw->pw_passwd,pw->pw_dir,pw->pw_shell};size_t size=24;
        for(auto s:strings)if(s)size+=strlen(s)+1;
        if(size>t_cache.passwd_capacity){uint32_t next=h.GuestAlloc(size,4);if(!next){Errno(h,ENOMEM);j.Regs()[0]=0;return;}
            h.GuestFree(t_cache.passwd);t_cache.passwd=next;t_cache.passwd_capacity=size;}
        uint32_t p=t_cache.passwd,cursor=p+24;uint32_t fields[]={0,0,pw->pw_uid,pw->pw_gid,0,0};
        const unsigned indexes[]={0,1,4,5};for(unsigned i=0;i<4;++i)if(strings[i]){
            size_t n=strlen(strings[i])+1;fields[indexes[i]]=cursor;memcpy(Span(h,cursor,n),strings[i],n);cursor+=n;}
        memcpy(Span(h,p,sizeof(fields)),fields,sizeof(fields));j.Regs()[0]=p;
    });
    RegisterThunk("getpid",[](Jit& j,Host&){j.Regs()[0]=getpid();});
    RegisterThunk("getppid",[](Jit& j,Host&){j.Regs()[0]=getppid();});
    RegisterThunk("geteuid",[](Jit& j,Host&){j.Regs()[0]=geteuid();});
    RegisterThunk("gettid",[](Jit& j,Host&){j.Regs()[0]=gettid();});
    RegisterThunk("sched_yield",[](Jit& j,Host& h){Result(j,h,sched_yield());});
    RegisterThunk("sched_get_priority_min",[](Jit& j,Host& h){Result(j,h,sched_get_priority_min(j.Regs()[0]));});
    RegisterThunk("sched_get_priority_max",[](Jit& j,Host& h){Result(j,h,sched_get_priority_max(j.Regs()[0]));});
    RegisterThunk("fcntl",[](Jit& j,Host& h){
        int fd=NativeFd(j.Regs()[0]),command=j.Regs()[1];uint32_t arg=j.Regs()[2];
        if(command==F_DUPFD||command==F_DUPFD_CLOEXEC||command==F_GETFD||command==F_SETFD||command==F_GETFL||command==F_SETFL){Result(j,h,fcntl(fd,command,arg));return;}
        bool wide=command>=12&&command<=14;
        if((command>=5&&command<=7)||wide){
            Span(h,arg,wide?32:16);struct flock value{};
            value.l_type=static_cast<int16_t>(h.MemoryRead16(arg));value.l_whence=static_cast<int16_t>(h.MemoryRead16(arg+2));
            value.l_start=wide?static_cast<int64_t>(h.MemoryRead64(arg+8)):static_cast<int32_t>(h.MemoryRead32(arg+4));
            value.l_len=wide?static_cast<int64_t>(h.MemoryRead64(arg+16)):static_cast<int32_t>(h.MemoryRead32(arg+8));
            value.l_pid=static_cast<int32_t>(h.MemoryRead32(arg+(wide?24:12)));
            int translated=wide?command-7:command;int rc=fcntl(fd,translated,&value);
            if(!rc&&translated==F_GETLK){
                if(!wide&&(value.l_start>INT32_MAX||value.l_start<INT32_MIN||value.l_len>INT32_MAX||value.l_len<INT32_MIN)){Failure(j,h,EOVERFLOW);return;}
                h.MemoryWrite16(arg,value.l_type);h.MemoryWrite16(arg+2,value.l_whence);
                if(wide){h.MemoryWrite64(arg+8,value.l_start);h.MemoryWrite64(arg+16,value.l_len);}else{h.MemoryWrite32(arg+4,value.l_start);h.MemoryWrite32(arg+8,value.l_len);}
                h.MemoryWrite32(arg+(wide?24:12),value.l_pid);
            }Result(j,h,rc);return;
        }
        LOGE("unsupported fcntl command %d",command);Failure(j,h,ENOTSUP);
    });
    RegisterThunk("ioctl",[](Jit& j,Host& h){
        int fd=NativeFd(j.Regs()[0]);unsigned request=j.Regs()[1];
        if(request==FIONREAD||request==FIONBIO){Result(j,h,ioctl(fd,request,Span(h,j.Regs()[2],4)));return;}
        if(fd<0){Failure(j,h,EBADF);return;}
        LOGE("unsupported device ioctl fd=%d request=0x%x",fd,request);Failure(j,h,ENOTTY);
    });
    RegisterThunk("syscall",[](Jit& j,Host& h){
        uint32_t number=j.Regs()[0];
        if(number==0x0f0005) { h.SetGuestTlsAddress(j.Regs()[1]);j.Regs()[0]=0;return; }
        if(number==0x0f0002) {
            uint32_t begin=j.Regs()[1],end=j.Regs()[2];
            if(end<begin) { Failure(j,h,EINVAL);return; }
            h.InvalidateGuestCode(begin,uint64_t(end)-begin);j.Regs()[0]=0;return;
        }
        if(number==224){j.Regs()[0]=gettid();return;}
        if(number==20){j.Regs()[0]=getpid();return;}
        if(number==240){
            uint32_t p=j.Regs()[1],operation=j.Regs()[2],value=j.Regs()[3];
            if(p&3){Failure(j,h,EINVAL);return;}void* address=Span(h,p,4);
            unsigned command=operation&0x7f;
            if(command!=0&&command!=1&&command!=9&&command!=10){LOGE("unsupported ARM futex operation %u",operation);Failure(j,h,ENOSYS);return;}
            timespec time{},*timeout=nullptr;uint32_t bitset=0xffffffffu;
            if(command==0||command==9){uint32_t time_ptr=h.ReadStackWord(j,0);if(time_ptr){if(!ReadTime(h,time_ptr,time)){Failure(j,h,EINVAL);return;}timeout=&time;}}
            if(command==9||command==10)bitset=h.ReadStackWord(j,2);
            Result(j,h,::syscall(SYS_futex,address,operation,value,timeout,nullptr,bitset));return;
        }
        if(number==241||number==242){
            // ARM32 syscall 241/242 are sched_set/getaffinity.  The guest
            // proves the four-byte ARM cpu_set_t ABI in AND_CurrentThreadAffinityMask.
            pid_t pid=static_cast<pid_t>(j.Regs()[1]);
            uint32_t set_size=j.Regs()[2],p=j.Regs()[3];
            if(set_size!=sizeof(uint32_t)||!p||(p&3)){
                g_affinity_before_guest_pin_valid=false;
                Failure(j,h,EINVAL);return;
            }
            if(number==242){
                // A failed refresh must not leave a snapshot from an older
                // getaffinity available to a later setaffinity on this thread.
                g_affinity_before_guest_pin_valid=false;
                cpu_set_t native{};
                if(sched_getaffinity(pid,sizeof(native),&native)!=0){Result(j,h,-1);return;}
                bool has_high=false;
                const uint32_t mask=Low32CpuMask(native,&has_high);
                if(AffinityWideEnabled()&&(pid==0||pid==gettid())&&mask&&!has_high){
                    cpu_set_t allowed=native;
                    uint32_t allowed_low=mask;
                    bool allowed_high=has_high;
                    if(ReadCurrentThreadAllowedCpuMask(allowed,allowed_low,allowed_high)&&
                       allowed_low&&!allowed_high&&(mask&~allowed_low)==0){
                        g_affinity_before_guest_pin=allowed;
                        g_affinity_before_guest_pin_low=allowed_low;
                        g_affinity_before_guest_pin_observed_low=mask;
                        g_affinity_before_guest_pin_valid=true;
                        LOGI("affinity-wide snapshot online=0x%08x allowed=0x%08x",
                             mask,allowed_low);
                    }
                }
                h.MemoryWrite32(p,mask);
                j.Regs()[0]=0;
                LOGI("guest syscall 242 sched_getaffinity pid=%d mask=0x%08x",static_cast<int>(pid),mask);
                return;
            }
            const uint32_t requested_mask=h.MemoryRead32(p);
            cpu_set_t requested{};CPU_ZERO(&requested);
            for(unsigned cpu=0;cpu<32;++cpu)if(requested_mask&(1u<<cpu))CPU_SET(cpu,&requested);
            const bool self=pid==0||pid==gettid();
            const bool singleton=requested_mask&&(requested_mask&(requested_mask-1u))==0;
            const bool widen=AffinityWideEnabled()&&self&&singleton&&
                              g_affinity_before_guest_pin_valid&&
                              !(requested_mask&~g_affinity_before_guest_pin_observed_low);
            const cpu_set_t effective=widen?g_affinity_before_guest_pin:requested;
            const uint32_t effective_request=widen?g_affinity_before_guest_pin_low:requested_mask;
            g_affinity_before_guest_pin_valid=false;
            const int rc=sched_setaffinity(pid,sizeof(effective),&effective);
            const int call_errno=errno;
            Result(j,h,rc);
            uint32_t actual_mask=0;int verify_ok=0;
            if(rc==0&&widen){
                cpu_set_t actual{};
                if(sched_getaffinity(pid,sizeof(actual),&actual)==0){
                    actual_mask=Low32CpuMask(actual);verify_ok=1;
                }
            }
            errno=call_errno;
            LOGI("guest syscall 241 sched_setaffinity pid=%d requested=0x%08x effective_request=0x%08x mode=%s result=%d errno=%d verify=%d actual_low32=0x%08x",
                 static_cast<int>(pid),requested_mask,effective_request,widen?"wide":"passthrough",
                 rc,rc<0?call_errno:0,verify_ok,actual_mask);
            return;
        }
        LOGE("unsupported ARM syscall %u",number);Failure(j,h,ENOSYS);
    });
    RegisterThunk("socket",[](Jit& j,Host& h){Result(j,h,socket(j.Regs()[0],j.Regs()[1],j.Regs()[2]));});
    RegisterThunk("bind",[](Jit& j,Host& h){Result(j,h,bind(NativeFd(j.Regs()[0]),static_cast<const sockaddr*>(Span(h,j.Regs()[1],j.Regs()[2])),j.Regs()[2]));});
    RegisterThunk("connect",[](Jit& j,Host& h){Result(j,h,connect(NativeFd(j.Regs()[0]),static_cast<const sockaddr*>(Span(h,j.Regs()[1],j.Regs()[2])),j.Regs()[2]));});
    RegisterThunk("send",[](Jit& j,Host& h){Result(j,h,send(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],j.Regs()[3]));});
    RegisterThunk("recv",[](Jit& j,Host& h){Result(j,h,recv(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],j.Regs()[3]));});
    RegisterThunk("poll",[](Jit& j,Host& h){
        static_assert(sizeof(pollfd)==8);uint32_t count=j.Regs()[1];
        auto* guest=static_cast<pollfd*>(Span(h,j.Regs()[0],uint64_t(count)*8));
        std::vector<pollfd> native(count);std::vector<bool> invalid(count);unsigned invalid_count=0;
        for(uint32_t i=0;i<count;++i){native[i]=guest[i];native[i].fd=NativeFd(guest[i].fd);
            invalid[i]=guest[i].fd>=0&&native[i].fd<0;if(invalid[i])++invalid_count;}
        int rc=poll(native.data(),count,invalid_count?0:static_cast<int32_t>(j.Regs()[2]));
        if(rc>=0){for(uint32_t i=0;i<count;++i)guest[i].revents=invalid[i]?POLLNVAL:native[i].revents;rc+=invalid_count;}Result(j,h,rc);
    });
    RegisterThunk("getsockname",[](Jit& j,Host& h){
        uint32_t size_ptr=j.Regs()[2];Span(h,size_ptr,4);socklen_t size=h.MemoryRead32(size_ptr);
        auto* p=static_cast<sockaddr*>(Span(h,j.Regs()[1],size));int rc=getsockname(NativeFd(j.Regs()[0]),p,&size);
        if(!rc)h.MemoryWrite32(size_ptr,size);Result(j,h,rc);
    });
    RegisterThunk("getpeername",[](Jit& j,Host& h){
        uint32_t size_ptr=j.Regs()[2];Span(h,size_ptr,4);socklen_t size=h.MemoryRead32(size_ptr);
        auto* p=static_cast<sockaddr*>(Span(h,j.Regs()[1],size));int rc=getpeername(NativeFd(j.Regs()[0]),p,&size);
        if(!rc)h.MemoryWrite32(size_ptr,size);Result(j,h,rc);
    });
    RegisterThunk("setsockopt",[](Jit& j,Host& h){
        uint32_t size=h.ReadStackWord(j,0);int level=j.Regs()[1],option=j.Regs()[2];
        const void* p=Span(h,j.Regs()[3],size);timeval tv{};
        if(level==SOL_SOCKET&&(option==SO_RCVTIMEO||option==SO_SNDTIMEO)){
            if(size<8){Failure(j,h,EINVAL);return;}tv.tv_sec=static_cast<int32_t>(h.MemoryRead32(j.Regs()[3]));tv.tv_usec=static_cast<int32_t>(h.MemoryRead32(j.Regs()[3]+4));p=&tv;size=sizeof(tv);
        }Result(j,h,setsockopt(NativeFd(j.Regs()[0]),level,option,p,size));
    });
    RegisterThunk("getsockopt",[](Jit& j,Host& h){
        uint32_t size_ptr=h.ReadStackWord(j,0);Span(h,size_ptr,4);socklen_t size=h.MemoryRead32(size_ptr);
        int level=j.Regs()[1],option=j.Regs()[2];uint32_t output=j.Regs()[3];void* p=Span(h,output,size);timeval tv{};bool timeout=level==SOL_SOCKET&&(option==SO_RCVTIMEO||option==SO_SNDTIMEO);
        if(timeout){if(size<8){Failure(j,h,EINVAL);return;}p=&tv;size=sizeof(tv);}
        int rc=getsockopt(NativeFd(j.Regs()[0]),level,option,p,&size);
        if(!rc){if(timeout){if(tv.tv_sec>INT32_MAX){Failure(j,h,EOVERFLOW);return;}h.MemoryWrite32(output,tv.tv_sec);h.MemoryWrite32(output+4,tv.tv_usec);size=8;}h.MemoryWrite32(size_ptr,size);}Result(j,h,rc);
    });
    RegisterThunk("inet_ntop",[](Jit& j,Host& h){
        int family=j.Regs()[0];uint32_t output=j.Regs()[2];size_t input_size=family==AF_INET?4:(family==AF_INET6?16:0);
        if(!input_size){Errno(h,EAFNOSUPPORT);j.Regs()[0]=0;return;}
        const char* result=inet_ntop(family,Span(h,j.Regs()[1],input_size),static_cast<char*>(Span(h,output,j.Regs()[3])),j.Regs()[3]);
        if(!result)Errno(h,errno);j.Regs()[0]=result?output:0;
    });
    RegisterThunk("inet_pton",[](Jit& j,Host& h){
        int family=j.Regs()[0];size_t size=family==AF_INET?4:(family==AF_INET6?16:0);if(!size){Failure(j,h,EAFNOSUPPORT);return;}
        Result(j,h,inet_pton(family,String(h,j.Regs()[1]),Span(h,j.Regs()[2],size)));
    });
    RegisterThunk("getaddrinfo",[](Jit& j,Host& h){
        uint32_t hints_ptr=j.Regs()[2],output=j.Regs()[3];Span(h,output,4);h.MemoryWrite32(output,0);addrinfo hints{},*result=nullptr;
        if(hints_ptr){Span(h,hints_ptr,32);hints.ai_flags=h.MemoryRead32(hints_ptr);hints.ai_family=h.MemoryRead32(hints_ptr+4);hints.ai_socktype=h.MemoryRead32(hints_ptr+8);hints.ai_protocol=h.MemoryRead32(hints_ptr+12);
            if(h.MemoryRead32(hints_ptr+16)||h.MemoryRead32(hints_ptr+20)||h.MemoryRead32(hints_ptr+24)||h.MemoryRead32(hints_ptr+28)){j.Regs()[0]=EAI_BADHINTS;return;}}
        int rc=getaddrinfo(String(h,j.Regs()[0]),String(h,j.Regs()[1]),hints_ptr?&hints:nullptr,&result);
        if(rc){if(rc==EAI_SYSTEM)Errno(h,errno);j.Regs()[0]=rc;return;}
        std::vector<uint32_t> allocations;uint32_t first=0,previous=0;
        auto allocate=[&](size_t n){uint32_t p=h.GuestAlloc(n,4);if(p)allocations.push_back(p);return p;};
        for(auto* item=result;item;item=item->ai_next){
            uint32_t p=allocate(32);if(!p){rc=EAI_MEMORY;break;}
            uint32_t address=0,name=0;
            if(item->ai_addrlen){address=allocate(item->ai_addrlen);if(!address){rc=EAI_MEMORY;break;}memcpy(Span(h,address,item->ai_addrlen),item->ai_addr,item->ai_addrlen);}
            if(item->ai_canonname){size_t n=strlen(item->ai_canonname)+1;name=allocate(n);if(!name){rc=EAI_MEMORY;break;}memcpy(Span(h,name,n),item->ai_canonname,n);}
            uint32_t fields[]={static_cast<uint32_t>(item->ai_flags),static_cast<uint32_t>(item->ai_family),static_cast<uint32_t>(item->ai_socktype),static_cast<uint32_t>(item->ai_protocol),static_cast<uint32_t>(item->ai_addrlen),name,address,0};
            memcpy(Span(h,p,32),fields,32);if(previous)h.MemoryWrite32(previous+28,p);else first=p;previous=p;
        }
        freeaddrinfo(result);
        if(rc){for(uint32_t p:allocations)h.GuestFree(p);j.Regs()[0]=rc;return;}
        {std::lock_guard lock(g_handles_mutex);g_addrinfo.emplace(first,std::move(allocations));}
        h.MemoryWrite32(output,first);j.Regs()[0]=0;
    });
    RegisterThunk("freeaddrinfo",[](Jit& j,Host& h){
        uint32_t p=j.Regs()[0];if(!p)return;std::vector<uint32_t> allocations;
        {std::lock_guard lock(g_handles_mutex);auto it=g_addrinfo.find(p);if(it==g_addrinfo.end())Invalid("freeaddrinfo unknown allocation");allocations=std::move(it->second);g_addrinfo.erase(it);}
        for(uint32_t address:allocations)h.GuestFree(address);
    });
    RegisterThunk("__cxa_atexit",[](Jit& j,Host&){
        std::lock_guard lock(g_atexit_mutex);g_atexit.push_back({j.Regs()[0],j.Regs()[1],j.Regs()[2]});j.Regs()[0]=0;
    });
    RegisterThunk("__aeabi_atexit",[](Jit& j,Host&){
        std::lock_guard lock(g_atexit_mutex);g_atexit.push_back({j.Regs()[1],j.Regs()[0],j.Regs()[2]});j.Regs()[0]=0;
    });
    RegisterThunk("__cxa_finalize",[](Jit& j,Host& h){Finalize(h,j.Regs()[0]);});
    RegisterThunk("__stack_chk_fail",[](Jit&,Host&){Invalid("guest stack canary failed");});
    RegisterThunk("abort",[](Jit&,Host&){Invalid("guest abort");});
    RegisterThunk("__assert2",[](Jit& j,Host& h){
        LOGE("guest assertion: %s:%d %s: %s",String(h,j.Regs()[0]),static_cast<int>(j.Regs()[1]),String(h,j.Regs()[2]),String(h,j.Regs()[3]));
        Invalid("guest assertion");
    });
    RegisterThunk("exit",[](Jit& j,Host& h){
        int status=j.Regs()[0];Finalize(h,0);if(h.HasFailed())Invalid("guest exit finalization failed");
        fflush(nullptr);::_exit(status);
    });
    RegisterThunk("_exit",[](Jit& j,Host&){::_exit(static_cast<int>(j.Regs()[0]));});
    RegisterThunk("raise",[](Jit& j,Host& h){
        LOGE("unsupported guest raise signal=%u; host signal delivery is disabled",j.Regs()[0]);
        Failure(j,h,ENOTSUP);
    });

    // The bundled CUHLwd executable is ARM32, not an arm64-compatible child process.
    RegisterThunk("vfork",[](Jit& j,Host& h){LOGE("unsupported ARM32 watchdog vfork; no child launched");Failure(j,h,ENOTSUP);});
    RegisterThunk("execl",[](Jit& j,Host& h){LOGE("unsupported guest execl; no binary executed");Failure(j,h,ENOTSUP);});
    RegisterThunk("mknod",[](Jit& j,Host& h){LOGE("unsupported guest device/daemon node creation");Failure(j,h,ENOTSUP);});

    // The guest uses the ARM32 Bionic signal path only for SIGALRM around DNS.
    // Other signal numbers remain explicit capability failures.
    RegisterThunk("sigaction",[](Jit& j,Host& h){
        const int signal=static_cast<int>(j.Regs()[0]);
        const uint32_t new_action=j.Regs()[1],old_action=j.Regs()[2];
        if(signal!=SIGALRM){
            LOGE("unsupported ARM32 signal handler ABI (signal=%d)",signal);
            Failure(j,h,ENOTSUP);return;
        }
        if((new_action&&((new_action&3)||!GuestRangeValid(h.GetGuestMemorySize(),new_action,16)))||
           (old_action&&((old_action&3)||!GuestRangeValid(h.GetGuestMemorySize(),old_action,16)))){
            Failure(j,h,EFAULT);return;
        }
        GuestSignalAction current{},next{};
        {std::lock_guard lock(g_signal_mutex);current=g_sigalrm_action;}
        if(old_action)WriteGuestSignalAction(h,old_action,current);
        if(new_action){
            next=ReadGuestSignalAction(h,new_action);
            if(next.handler!=0&&next.handler!=1&&!h.IsExecutableAddress(next.handler)){
                LOGE("invalid SIGALRM handler 0x%08x",next.handler);Failure(j,h,EINVAL);return;
            }
            std::lock_guard lock(g_signal_mutex);g_sigalrm_action=next;
        }
        LOGI("guest sigaction SIGALRM handler=0x%08x new=%u old=%u",next.handler,new_action?1:0,old_action?1:0);
        j.Regs()[0]=0;
    });
    RegisterThunk("alarm",[](Jit& j,Host&){
        const uint32_t seconds=j.Regs()[0];
        uint32_t remaining=0;
        if(t_alarm.armed){
            const auto now=std::chrono::steady_clock::now();
            const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(t_alarm.deadline-now).count();
            if(left>0)remaining=static_cast<uint32_t>((left+999)/1000);
        }
        t_alarm.armed=seconds!=0;
        if(t_alarm.armed)t_alarm.deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
        else t_alarm.jump_buffer=0;
        LOGI("guest alarm seconds=%u remaining=%u",seconds,remaining);
        j.Regs()[0]=remaining;
    });
    RegisterThunk("sigsetjmp",[](Jit& j,Host& h){
        const uint32_t buffer=j.Regs()[0];
        const bool saves_mask=j.Regs()[1]!=0;
        if((buffer&3)||!GuestRangeValid(h.GetGuestMemorySize(),buffer,kGuestSigjmpStoredBytes)){
            LOGE("invalid guest sigjmp_buf 0x%08x",buffer);
            h.Fail("invalid ARM32 sigjmp_buf");return;
        }
        GuestJumpContext context;
        context.owner=std::this_thread::get_id();context.jit=&j;
        context.fpscr=j.Fpscr();context.sp=j.Regs()[13];context.lr=j.Regs()[14];
        if(saves_mask) {
            uint32_t current_mask=0;
            if(GuestThreadSignalMask(SIG_SETMASK,nullptr,&current_mask)) {
                h.Fail("cannot save ARM32 signal mask");return;
            }
            t_guest_signal_mask=current_mask;
        }
        context.cpsr=j.Cpsr();context.signal_mask=t_guest_signal_mask;context.saves_signal_mask=saves_mask;
        h.MemoryWrite32(buffer,kGuestJumpCookie|(saves_mask?1u:0u));
        h.MemoryWrite32(buffer+4,saves_mask?t_guest_signal_mask:0);
        for(unsigned i=0;i<context.ext_regs.size();++i){
            context.ext_regs[i]=j.ExtRegs()[16+i];h.MemoryWrite32(buffer+16+i*4,context.ext_regs[i]);
        }
        h.MemoryWrite32(buffer+80,context.fpscr);
        for(unsigned i=0;i<context.callee_saved.size();++i){
            context.callee_saved[i]=j.Regs()[4+i];h.MemoryWrite32(buffer+84+i*4,context.callee_saved[i]);
        }
        h.MemoryWrite32(buffer+116,context.lr);h.MemoryWrite32(buffer+120,context.sp);
        h.MemoryWrite32(buffer+kGuestSigjmpMagicOffset,kGuestJumpMagic);
        {std::lock_guard lock(g_jump_mutex);g_jump_contexts[buffer]=context;}
        if(t_alarm.armed)t_alarm.jump_buffer=buffer;
        LOGI("guest sigsetjmp buffer=0x%08x save_mask=%u",buffer,saves_mask?1:0);
        j.Regs()[0]=0;
    });
    RegisterThunk("siglongjmp",[](Jit& j,Host& h){
        const uint32_t buffer=j.Regs()[0],value=j.Regs()[1];
        GuestJumpContext context{};
        {std::lock_guard lock(g_jump_mutex);
            auto found=g_jump_contexts.find(buffer);
            if(found==g_jump_contexts.end()){h.Fail("unknown ARM32 sigjmp_buf");return;}
            context=found->second;
        }
        const uint32_t cookie=buffer&&GuestRangeValid(h.GetGuestMemorySize(),buffer,kGuestSigjmpStoredBytes)?h.MemoryRead32(buffer):0;
        if((buffer&3)||cookie==0||((cookie&~1u)!=kGuestJumpCookie)||
           h.MemoryRead32(buffer+kGuestSigjmpMagicOffset)!=kGuestJumpMagic||
           context.owner!=std::this_thread::get_id()||context.jit!=&j||
           bool(cookie&1)!=context.saves_signal_mask){
            LOGE("invalid or cross-context guest siglongjmp 0x%08x",buffer);
            h.Fail("unsupported ARM32 sigjmp_buf restore context");return;
        }
        for(unsigned i=0;i<context.ext_regs.size();++i)j.ExtRegs()[16+i]=h.MemoryRead32(buffer+16+i*4);
        j.SetFpscr(h.MemoryRead32(buffer+80));
        for(unsigned i=0;i<context.callee_saved.size();++i)j.Regs()[4+i]=h.MemoryRead32(buffer+84+i*4);
        const uint32_t lr=h.MemoryRead32(buffer+116);
        j.Regs()[13]=h.MemoryRead32(buffer+120);j.Regs()[14]=lr;
        j.SetCpsr((context.cpsr&~0x20u)|(lr&1?0x20u:0));
        if(context.saves_signal_mask) {
            uint32_t restore_mask=h.MemoryRead32(buffer+4);
            if(GuestThreadSignalMask(SIG_SETMASK,&restore_mask,nullptr)) {
                h.Fail("cannot restore ARM32 signal mask");return;
            }
        }
        t_alarm.jump_buffer=0;t_alarm.armed=false;
        j.Regs()[0]=value?value:1;j.Regs()[15]=lr&~1u;
        LOGI("guest siglongjmp restored ARM32 Bionic state buffer=0x%08x",buffer);
    });
    RegisterPosixComplements();
}

namespace {
std::shared_ptr<Once> GetOnce(Host& h,uint32_t p) {
    Span(h,p,4);
    std::lock_guard lock(g_sync_mutex);
    auto& value=g_once[p];if(!value)value=std::make_shared<Once>();return value;
}
}
void ThunkManager::RegisterPosixComplements() {
    // The legacy APK virtual descriptors keep their read/seek/mmap adapters.
    // Bring their failure result into the per-thread Bionic errno cell.
    for(const char* name : {"open","close","read","write","lseek","lseek64","mmap","munmap","unlink","remove","rename"}) {
        const uint32_t address=FindRegisteredSymbol(name);
        if(!address)continue;
        const uint32_t id=m_host.MemoryRead32(address)&0xffffff;
        ThunkHandler original=m_dispatch[id-1].load()->handler;
        RegisterThunk(name,[original](Jit& j,Host& h) { original(j,h);if(j.Regs()[0]==UINT32_MAX)Errno(h,errno); });
    }
    RegisterThunk("fstat",[](Jit& j,Host& h) { struct stat s{};const uint32_t out=j.Regs()[1];Span(h,out,sizeof(Stat32));int rc=BridgeFstat(NativeFd(j.Regs()[0]),&s);if(!rc&&!WriteStat(h,out,s))rc=-1;Result(j,h,rc); });
    RegisterThunk("mprotect",[](Jit& j,Host& h) {
        const uint32_t address=j.Regs()[0],size=j.Regs()[1],prot=j.Regs()[2];
        if(!GuestRangeValid(h.GetGuestMemorySize(),address,size)||(address&4095)) { Failure(j,h,EINVAL);return; }
        if(prot&PROT_EXEC) { h.AddExecutableRange(address,size);h.InvalidateGuestCode(address,size); }
        j.Regs()[0]=0;
    });
    auto alias = [this](const char* name, const char* target) {
        const uint32_t address = FindRegisteredSymbol(target);
        if (!address) throw std::logic_error(std::string("Missing alias target: ") + target);
        const uint32_t id = m_host.MemoryRead32(address) & 0xffffff;
        RegisterThunk(name,[id](Jit& j,Host& h) { h.GetThunkManager().DispatchThunk(id,j); });
    };
    alias("getc","fgetc"); alias("putc","fputc"); alias("__swbuf","fputc");
    alias("fseeko","fseek"); alias("ftello","ftell");
    // Android setjmp saves the signal mask, matching sigsetjmp(env, 1).
    const uint32_t sigsetjmp_id=m_host.MemoryRead32(FindRegisteredSymbol("sigsetjmp"))&0xffffff;
    RegisterThunk("setjmp",[sigsetjmp_id](Jit& j,Host& h) {
        j.Regs()[1]=1;h.GetThunkManager().DispatchThunk(sigsetjmp_id,j);
    });
    alias("longjmp","siglongjmp");
    RegisterThunk("pthread_sigmask",[](Jit& j,Host& h) {
        const uint32_t input=j.Regs()[1],output=j.Regs()[2];
        if((input && ((input&3)||!GuestRangeValid(h.GetGuestMemorySize(),input,4))) ||
           (output && ((output&3)||!GuestRangeValid(h.GetGuestMemorySize(),output,4)))) {
            j.Regs()[0]=EFAULT;return;
        }
        uint32_t next=input?h.MemoryRead32(input):0,previous=0;
        int rc=GuestThreadSignalMask(static_cast<int>(j.Regs()[0]),input?&next:nullptr,output?&previous:nullptr);
        if(!rc&&output)h.MemoryWrite32(output,previous);
        j.Regs()[0]=rc;
    });
    RegisterThunk("bsd_signal",[](Jit& j,Host& h) {
        const int number=static_cast<int>(j.Regs()[0]);const uint32_t handler=j.Regs()[1];
        if(number<=0||number>32||number==SIGKILL||number==SIGSTOP) { Failure(j,h,EINVAL);return; }
        if(number==SIGALRM) {
            if(handler>1&&!h.IsExecutableAddress(handler)) { Failure(j,h,EINVAL);return; }
            std::lock_guard lock(g_signal_mutex);uint32_t previous=g_sigalrm_action.handler;
            g_sigalrm_action={handler,1u<<(SIGALRM-1),SA_RESTART,0};j.Regs()[0]=previous;return;
        }
        // A64 asynchronous handlers cannot jump straight into an A32 JIT.
        // DFL/IGN are representable; a requested ARM callback reports SIG_ERR.
        if(handler>1) {
            LOGE("unsupported asynchronous ARM32 bsd_signal handler signal=%d",number);
            Failure(j,h,ENOTSUP);return;
        }
        struct sigaction current{},next{};
        if(sigaction(number,nullptr,&current)) { Failure(j,h,errno);return; }
        if(current.sa_handler!=SIG_DFL&&current.sa_handler!=SIG_IGN) {
            Failure(j,h,ENOTSUP);return;
        }
        next.sa_handler=handler?SIG_IGN:SIG_DFL;next.sa_flags=SA_RESTART;
        sigemptyset(&next.sa_mask);sigaddset(&next.sa_mask,number);
        if(sigaction(number,&next,nullptr)) { Failure(j,h,errno);return; }
        j.Regs()[0]=current.sa_handler==SIG_IGN?1:0;
    });
    RegisterThunk("fgetws",[](Jit& j,Host& h) {
        static_assert(sizeof(wchar_t)==4);
        const uint32_t output=j.Regs()[0];const int count=static_cast<int32_t>(j.Regs()[1]);
        if(count<=0) { Errno(h,EINVAL);j.Regs()[0]=0;return; }
        if(output&3) { Errno(h,EFAULT);j.Regs()[0]=0;return; }
        auto* data=static_cast<wchar_t*>(Span(h,output,uint64_t(count)*4));
        wchar_t* result=WithFile(j.Regs()[2],static_cast<wchar_t*>(nullptr),[&](FILE* file) {
            return fgetws(data,count,file);
        });
        if(!result&&errno)Errno(h,errno);
        j.Regs()[0]=result?output:0;
    });
    RegisterThunk("fdopen",[](Jit& j,Host& h) {
        FILE* file=fdopen(NativeFd(j.Regs()[0]),String(h,j.Regs()[1]));
        j.Regs()[0]=AddFile(h,file);if(!j.Regs()[0])Errno(h,errno);
    });
    RegisterThunk("fileno",[](Jit& j,Host& h) { Result(j,h,WithFile(j.Regs()[0],-1,[](FILE* f) { return fileno(f); })); });
    RegisterThunk("clearerr",[](Jit& j,Host&) { WithFile(j.Regs()[0],-1,[](FILE* f) { clearerr(f);return 0; }); });
    RegisterThunk("feof",[](Jit& j,Host&) { j.Regs()[0]=WithFile(j.Regs()[0],0,[](FILE* f) { return feof(f); }); });
    RegisterThunk("ferror",[](Jit& j,Host&) { j.Regs()[0]=WithFile(j.Regs()[0],0,[](FILE* f) { return ferror(f); }); });
    RegisterThunk("rewind",[](Jit& j,Host&) { WithFile(j.Regs()[0],-1,[](FILE* f) { rewind(f);return 0; }); });
    RegisterThunk("ungetc",[](Jit& j,Host& h) { const int c=j.Regs()[0];Result(j,h,WithFile(j.Regs()[1],EOF,[&](FILE* f) { return ungetc(c,f); })); });
    RegisterThunk("setvbuf",[](Jit& j,Host& h) {
        const uint32_t size=j.Regs()[3];char* buffer=j.Regs()[1]?static_cast<char*>(Span(h,j.Regs()[1],size)):nullptr;
        const int mode=j.Regs()[2];Result(j,h,WithFile(j.Regs()[0],-1,[&](FILE* f) { return setvbuf(f,buffer,mode,size); }));
    });
    RegisterThunk("setbuf",[](Jit& j,Host& h) {
        // ARM32 Bionic BUFSIZ is 1024. Do not let the host choose a larger buffer.
        char* buffer=j.Regs()[1]?static_cast<char*>(Span(h,j.Regs()[1],1024)):nullptr;
        WithFile(j.Regs()[0],-1,[&](FILE* f) { return setvbuf(f,buffer,buffer?_IOFBF:_IONBF,buffer?1024:0); });
    });
    RegisterThunk("tmpfile",[](Jit& j,Host& h) { j.Regs()[0]=AddFile(h,tmpfile());if(!j.Regs()[0])Errno(h,errno); });
    RegisterThunk("vfprintf",[](Jit& j,Host& h) {
        const uint32_t file=j.Regs()[0];VarArgs args(j,h,j.Regs()[2],true);
        std::string text=Format(h,String(h,j.Regs()[1]),args);
        Result(j,h,WithFile(file,-1,[&](FILE* f) { return LogWrite(f,text.data(),text.size()); }));
    });
    RegisterThunk("vprintf",[](Jit& j,Host& h) {
        VarArgs args(j,h,j.Regs()[1],true);std::string text=Format(h,String(h,j.Regs()[0]),args);
        Result(j,h,WithFile(0x254,-1,[&](FILE* f) { return LogWrite(f,text.data(),text.size()); }));
    });
    auto allocated_print=[](Jit& j,Host& h,bool list) {
        const uint32_t out=j.Regs()[0];Span(h,out,4);h.MemoryWrite32(out,0);
        VarArgs args(j,h,list?j.Regs()[2]:2,list);std::string text=Format(h,String(h,j.Regs()[1]),args);
        uint32_t buffer=h.GuestAlloc(text.size()+1);if(!buffer) { Failure(j,h,ENOMEM);return; }
        memcpy(Span(h,buffer,text.size()+1),text.c_str(),text.size()+1);h.MemoryWrite32(out,buffer);j.Regs()[0]=text.size();
    };
    RegisterThunk("asprintf",[allocated_print](Jit& j,Host& h) { allocated_print(j,h,false); });
    RegisterThunk("vasprintf",[allocated_print](Jit& j,Host& h) { allocated_print(j,h,true); });
    RegisterThunk("vsscanf",[](Jit& j,Host& h) { VarArgs args(j,h,j.Regs()[2],true);j.Regs()[0]=Scan(h,String(h,j.Regs()[0]),String(h,j.Regs()[1]),args); });
    RegisterThunk("__android_log_assert",[](Jit& j,Host& h) {
        VarArgs args(j,h,3);std::string text=j.Regs()[2]?Format(h,String(h,j.Regs()[2]),args):String(h,j.Regs()[0]);
        LOGE("Guest assertion: %s",text.c_str());h.Fail("Guest Android assertion");
    });
    RegisterThunk("__cxa_guard_acquire",[](Jit& j,Host& h) {
        auto once=GetOnce(h,j.Regs()[0]);
        std::unique_lock lock(once->mutex);
        while(once->state==1) {
            if(once->owner==std::this_thread::get_id()) { h.Fail("Recursive C++ static initialization");j.Regs()[0]=0;return; }
            once->cv.wait(lock);
        }
        if(once->state==2 || (h.MemoryRead32(j.Regs()[0])&1)) { j.Regs()[0]=0;return; }
        once->state=1;once->owner=std::this_thread::get_id();j.Regs()[0]=1;
    });
    auto finish_guard=[](Jit& j,Host& h,bool release) {
        auto once=GetOnce(h,j.Regs()[0]);std::lock_guard lock(once->mutex);
        if(release) { once->state=2;h.MemoryWrite32(j.Regs()[0],1); }
        if(!release)once->state=0;once->owner={};once->cv.notify_all();
    };
    RegisterThunk("__cxa_guard_release",[finish_guard](Jit& j,Host& h) { finish_guard(j,h,true); });
    RegisterThunk("__cxa_guard_abort",[finish_guard](Jit& j,Host& h) { finish_guard(j,h,false); });
    RegisterThunk("pthread_equal",[](Jit& j,Host&) { j.Regs()[0]=j.Regs()[0]==j.Regs()[1]; });
    RegisterThunk("pthread_attr_setdetachstate",[](Jit& j,Host& h) {
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        if(j.Regs()[1]>1) { j.Regs()[0]=EINVAL;return; }a->flags=(a->flags&~1u)|j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_setstacksize",[](Jit& j,Host& h) {
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        // A reserved 4-MiB guest stack safely covers requests through this size.
        if(j.Regs()[1]<16384 || j.Regs()[1]>4*1024*1024-65536) { j.Regs()[0]=EINVAL;return; }
        a->size=j.Regs()[1];j.Regs()[0]=0;
    });
    RegisterThunk("pthread_attr_getguardsize",[](Jit& j,Host& h) {
        auto* a=static_cast<Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));Span(h,j.Regs()[1],4);h.MemoryWrite32(j.Regs()[1],a->guard);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_condattr_init",[](Jit& j,Host& h) { Span(h,j.Regs()[0],4);h.MemoryWrite32(j.Regs()[0],0);j.Regs()[0]=0; });
    RegisterThunk("pthread_condattr_destroy",[](Jit& j,Host&) { j.Regs()[0]=0; });
    RegisterThunk("pthread_condattr_setclock",[](Jit& j,Host& h) {
        const int clock=j.Regs()[1];if(clock!=CLOCK_REALTIME&&clock!=CLOCK_MONOTONIC) { j.Regs()[0]=EINVAL;return; }
        Span(h,j.Regs()[0],4);h.MemoryWrite32(j.Regs()[0],clock==CLOCK_MONOTONIC?2:0);j.Regs()[0]=0;
    });
    RegisterThunk("getcwd",[](Jit& j,Host& h) {
        uint32_t out=j.Regs()[0];size_t size=j.Regs()[1];
        if(!out) { char* text=getcwd(nullptr,size);j.Regs()[0]=text?CopyString(h,text):0;free(text); }
        else j.Regs()[0]=getcwd(static_cast<char*>(Span(h,out,size)),size)?out:0;
        if(!j.Regs()[0])Errno(h,errno);
    });
    RegisterThunk("chdir",[](Jit& j,Host& h) { Result(j,h,chdir(String(h,j.Regs()[0]))); });
    RegisterThunk("rmdir",[](Jit& j,Host& h) { Result(j,h,rmdir(String(h,j.Regs()[0]))); });
    RegisterThunk("chmod",[](Jit& j,Host& h) { Result(j,h,chmod(String(h,j.Regs()[0]),j.Regs()[1])); });
    RegisterThunk("chown",[](Jit& j,Host& h) { Result(j,h,chown(String(h,j.Regs()[0]),j.Regs()[1],j.Regs()[2])); });
    RegisterThunk("mkstemp",[](Jit& j,Host& h) { Result(j,h,mkstemp(const_cast<char*>(String(h,j.Regs()[0])))); });
    RegisterThunk("fsync",[](Jit& j,Host& h) { Result(j,h,fsync(NativeFd(j.Regs()[0]))); });
    RegisterThunk("ftruncate",[](Jit& j,Host& h) { Result(j,h,ftruncate(NativeFd(j.Regs()[0]),static_cast<int32_t>(j.Regs()[1]))); });
    RegisterThunk("pread",[](Jit& j,Host& h) { Result(j,h,pread(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],static_cast<int32_t>(j.Regs()[3]))); });
    RegisterThunk("pwrite",[](Jit& j,Host& h) { Result(j,h,pwrite(NativeFd(j.Regs()[0]),Span(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2],static_cast<int32_t>(j.Regs()[3]))); });
    RegisterThunk("pread64",[](Jit& j,Host& h) { Arm32CallArgs a(j,h);int fd=a.I32();uint32_t p=a.Ptr(),n=a.U32();int64_t offset=a.I64();Result(j,h,pread64(NativeFd(fd),Span(h,p,n),n,offset)); });
    RegisterThunk("pwrite64",[](Jit& j,Host& h) { Arm32CallArgs a(j,h);int fd=a.I32();uint32_t p=a.Ptr(),n=a.U32();int64_t offset=a.I64();Result(j,h,pwrite64(NativeFd(fd),Span(h,p,n),n,offset)); });
    RegisterThunk("readlink",[](Jit& j,Host& h) { Result(j,h,readlink(String(h,j.Regs()[0]),static_cast<char*>(Span(h,j.Regs()[1],j.Regs()[2])),j.Regs()[2])); });
    RegisterThunk("lstat",[](Jit& j,Host& h) { struct stat s{};const uint32_t out=j.Regs()[1];Span(h,out,sizeof(Stat32));int rc=lstat(String(h,j.Regs()[0]),&s);if(!rc&&!WriteStat(h,out,s))rc=-1;Result(j,h,rc); });
    RegisterThunk("getuid",[](Jit& j,Host&) { j.Regs()[0]=getuid(); });
    RegisterThunk("getgid",[](Jit& j,Host&) { j.Regs()[0]=getgid(); });
    RegisterThunk("getegid",[](Jit& j,Host&) { j.Regs()[0]=getegid(); });
    RegisterThunk("getdtablesize",[](Jit& j,Host&) { j.Regs()[0]=sysconf(_SC_OPEN_MAX); });
    RegisterThunk("isatty",[](Jit& j,Host& h) { j.Regs()[0]=isatty(NativeFd(j.Regs()[0]));if(!j.Regs()[0])Errno(h,errno); });
    RegisterThunk("setenv",[](Jit& j,Host& h) { Result(j,h,setenv(String(h,j.Regs()[0]),String(h,j.Regs()[1]),j.Regs()[2])); });
    RegisterThunk("unsetenv",[](Jit& j,Host& h) { Result(j,h,unsetenv(String(h,j.Regs()[0]))); });
    RegisterThunk("setlocale",[](Jit& j,Host& h) { j.Regs()[0]=CachedString(h,"locale",setlocale(j.Regs()[0],String(h,j.Regs()[1]))); });
    RegisterThunk("clock",[](Jit& j,Host&) { j.Regs()[0]=static_cast<uint32_t>(clock()); });
    RegisterThunk("clock_getres",[](Jit& j,Host& h) { timespec t{};const uint32_t p=j.Regs()[1];int rc=clock_getres(j.Regs()[0],&t);if(!rc&&p&&!WriteTime(h,p,t))rc=-1;Result(j,h,rc); });
    RegisterThunk("difftime",[](Jit& j,Host&) { WriteDF(j,0,difftime(static_cast<int32_t>(j.Regs()[0]),static_cast<int32_t>(j.Regs()[1]))); });
    auto read_tm=[](Host& h,uint32_t p) {
        const auto& g=*static_cast<const Tm32*>(Span(h,p,sizeof(Tm32)));
        tm t{};t.tm_sec=g.sec;t.tm_min=g.min;t.tm_hour=g.hour;t.tm_mday=g.mday;t.tm_mon=g.mon;t.tm_year=g.year;
        t.tm_wday=g.wday;t.tm_yday=g.yday;t.tm_isdst=g.isdst;t.tm_gmtoff=g.gmtoff;t.tm_zone=String(h,g.zone);return t;
    };
    RegisterThunk("mktime",[read_tm](Jit& j,Host& h) { uint32_t p=j.Regs()[0];tm t=read_tm(h,p);time_t result=mktime(&t);if(result<INT32_MIN||result>INT32_MAX) { Failure(j,h,EOVERFLOW);return; }WriteTm(h,p,t);Result(j,h,result); });
    RegisterThunk("strftime",[read_tm](Jit& j,Host& h) { tm t=read_tm(h,j.Regs()[3]);j.Regs()[0]=strftime(static_cast<char*>(Span(h,j.Regs()[0],j.Regs()[1])),j.Regs()[1],String(h,j.Regs()[2]),&t); });
    RegisterThunk("localtime_r",[](Jit& j,Host& h) { Span(h,j.Regs()[0],4);time_t time=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));const uint32_t p=j.Regs()[1];tm t{};if(localtime_r(&time,&t)) { WriteTm(h,p,t);j.Regs()[0]=p; }else { Errno(h,errno);j.Regs()[0]=0; } });
    RegisterThunk("select",[](Jit& j,Host& h) {
        const int nfds=static_cast<int32_t>(j.Regs()[0]);
        if(nfds<0 || nfds>FD_SETSIZE) { Failure(j,h,EINVAL);return; }
        std::array<uint32_t,3> ptr{j.Regs()[1],j.Regs()[2],j.Regs()[3]};
        fd_set sets[3]{};
        for(size_t i=0;i<3;++i)if(ptr[i])memcpy(&sets[i],Span(h,ptr[i],128),128);
        const uint32_t timeout=h.ReadStackWord(j,0);timeval native{};
        if(timeout) { auto* words=static_cast<int32_t*>(Span(h,timeout,8));native.tv_sec=words[0];native.tv_usec=words[1]; }
        int result=select(nfds,ptr[0]?&sets[0]:nullptr,ptr[1]?&sets[1]:nullptr,ptr[2]?&sets[2]:nullptr,timeout?&native:nullptr);
        if(result>=0)for(size_t i=0;i<3;++i)if(ptr[i])memcpy(Span(h,ptr[i],128),&sets[i],128);
        if(timeout) { h.MemoryWrite32(timeout,native.tv_sec);h.MemoryWrite32(timeout+4,native.tv_usec); }
        Result(j,h,result);
    });
    RegisterThunk("gethostbyname",[](Jit& j,Host& h) {
        const char* name=String(h,j.Regs()[0]);addrinfo hints{},*info=nullptr;
        hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;hints.ai_flags=AI_CANONNAME;
        int rc=getaddrinfo(name,nullptr,&hints,&info);
        if(rc || !info) { h.MemoryWrite32(h.GuestTlsAddress()+12,rc==EAI_AGAIN?TRY_AGAIN:HOST_NOT_FOUND);j.Regs()[0]=0;return; }
        size_t count=0;for(auto* it=info;it;it=it->ai_next)++count;
        const char* canonical=info->ai_canonname?info->ai_canonname:name;
        const size_t name_size=strlen(canonical)+1;
        // hostent32 + empty aliases + address-pointer vector + IPv4 bytes + name.
        uint32_t block=h.GuestAlloc(28+count*8+name_size,4);
        if(!block) { freeaddrinfo(info);j.Regs()[0]=0;Errno(h,ENOMEM);return; }
        h.GuestFree(t_cache.hostent);t_cache.hostent=block;
        uint32_t addresses=block+24,bytes=addresses+(count+1)*4,text=bytes+count*4;
        h.MemoryWrite32(block,text);h.MemoryWrite32(block+4,block+20);h.MemoryWrite32(block+8,AF_INET);
        h.MemoryWrite32(block+12,4);h.MemoryWrite32(block+16,addresses);h.MemoryWrite32(block+20,0);
        size_t i=0;for(auto* it=info;it;it=it->ai_next,++i) {
            h.MemoryWrite32(addresses+i*4,bytes+i*4);
            memcpy(Span(h,bytes+i*4,4),&reinterpret_cast<sockaddr_in*>(it->ai_addr)->sin_addr,4);
        }
        h.MemoryWrite32(addresses+count*4,0);memcpy(Span(h,text,name_size),canonical,name_size);
        freeaddrinfo(info);j.Regs()[0]=block;
    });
    RegisterThunk("__get_h_errno",[](Jit& j,Host& h) { j.Regs()[0]=h.GuestTlsAddress()+12; });
    struct DlHandles { std::mutex mutex;uint32_t next=0xd1000000;std::unordered_map<uint32_t,std::string> values; };
    auto libraries=std::make_shared<DlHandles>();
    auto dl_fail=[](const std::string& error) { t_cache.dl_error=error;t_cache.dl_error_pending=true; };
    RegisterThunk("dlopen",[libraries,dl_fail](Jit& j,Host& h) {
        if(!j.Regs()[0]) { j.Regs()[0]=0xd1ffffff;return; }
        std::string name=String(h,j.Regs()[0]);const size_t slash=name.find_last_of('/');
        if(slash!=std::string::npos)name.erase(0,slash+1);
        const bool system=name=="libc.so"||name=="libm.so"||name=="libdl.so"||name=="liblog.so"||name=="libz.so"||
            name=="libandroid.so"||name=="libEGL.so"||name=="libGLESv2.so"||name=="libGLESv3.so"||name=="libOpenSLES.so";
        if(!system&&!h.FindModule(name)) { dl_fail("Guest module is not preloaded: "+name);j.Regs()[0]=0;return; }
        std::lock_guard lock(libraries->mutex);uint32_t handle=libraries->next++;
        libraries->values.emplace(handle,system?std::string{}:name);j.Regs()[0]=handle;
    });
    RegisterThunk("dlsym",[libraries,dl_fail](Jit& j,Host& h) {
        const uint32_t handle=j.Regs()[0];const std::string symbol=String(h,j.Regs()[1]);uint32_t value=0;
        if(!handle||handle==0xd1ffffff||handle==UINT32_MAX)value=h.FindSymbol(symbol);
        else {
            std::lock_guard lock(libraries->mutex);auto found=libraries->values.find(handle);
            if(found==libraries->values.end()) { dl_fail("Invalid guest dlopen handle");j.Regs()[0]=0;return; }
            value=found->second.empty()?h.GetThunkManager().FindRegisteredSymbol(symbol):h.FindLibrarySymbol(found->second,symbol);
        }
        if(!value)dl_fail("Guest symbol is not available: "+symbol);j.Regs()[0]=value;
    });
    RegisterThunk("dlclose",[libraries,dl_fail](Jit& j,Host&) {
        if(j.Regs()[0]==0xd1ffffff) { j.Regs()[0]=0;return; }
        std::lock_guard lock(libraries->mutex);
        if(libraries->values.erase(j.Regs()[0]))j.Regs()[0]=0;
        else { dl_fail("Invalid guest dlopen handle");j.Regs()[0]=-1; }
    });
    RegisterThunk("dlerror",[](Jit& j,Host& h) {
        j.Regs()[0]=t_cache.dl_error_pending?CachedString(h,"dlerror",t_cache.dl_error.c_str()):0;
        t_cache.dl_error_pending=false;
    });

    RegisterThunk("sysconf",[](Jit& j,Host& h) {
        const int name=j.Regs()[0];errno=0;long result=sysconf(name);
        if(name==_SC_PAGESIZE)result=4096;
        else if((name==_SC_PHYS_PAGES||name==_SC_AVPHYS_PAGES)&&result>0)result*=sysconf(_SC_PAGESIZE)/4096;
        if(result>INT32_MAX)result=INT32_MAX;
        j.Regs()[0]=static_cast<uint32_t>(result);if(result==-1&&errno)Errno(h,errno);
    });
    RegisterThunk("getpagesize",[](Jit& j,Host&) { j.Regs()[0]=4096; });
    RegisterThunk("getauxval",[](Jit& j,Host& h) {
        // ARMv7/A32 capabilities implemented by Dynarmic, never host AArch64 bits.
        constexpr uint32_t hwcap=(1u<<0)|(1u<<1)|(1u<<2)|(1u<<4)|(1u<<6)|(1u<<7)|
            (1u<<12)|(1u<<13)|(1u<<15)|(1u<<16)|(1u<<17)|(1u<<18)|(1u<<19);
        switch(j.Regs()[0]) {
            case 6:j.Regs()[0]=4096;break;
            case 16:j.Regs()[0]=hwcap;break;
            case 26:j.Regs()[0]=0;break;
            case 11:j.Regs()[0]=getuid();break;case 12:j.Regs()[0]=geteuid();break;
            case 13:j.Regs()[0]=getgid();break;case 14:j.Regs()[0]=getegid();break;
            default:j.Regs()[0]=0;Errno(h,ENOENT);break;
        }
    });
    RegisterThunk("uname",[](Jit& j,Host& h) {
        auto* output=static_cast<utsname*>(Span(h,j.Regs()[0],sizeof(utsname)));int rc=uname(output);
        if(!rc)strcpy(output->machine,"armv7l");Result(j,h,rc);
    });
    RegisterThunk("gethostname",[](Jit& j,Host& h) { Result(j,h,gethostname(static_cast<char*>(Span(h,j.Regs()[0],j.Regs()[1])),j.Regs()[1])); });
    RegisterThunk("getpriority",[](Jit& j,Host& h) { errno=0;int result=getpriority(j.Regs()[0],j.Regs()[1]);j.Regs()[0]=result;if(errno)Errno(h,errno); });
    RegisterThunk("setpriority",[](Jit& j,Host& h) { Result(j,h,setpriority(j.Regs()[0],j.Regs()[1],static_cast<int32_t>(j.Regs()[2]))); });
    RegisterThunk("pipe",[](Jit& j,Host& h) { Result(j,h,pipe(static_cast<int*>(Span(h,j.Regs()[0],8)))); });
    RegisterThunk("writev",[](Jit& j,Host& h) {
        const int count=static_cast<int32_t>(j.Regs()[2]);if(count<0||count>IOV_MAX) { Failure(j,h,EINVAL);return; }
        auto* guest=count?static_cast<const uint32_t*>(Span(h,j.Regs()[1],count*8)):nullptr;
        std::vector<iovec> vectors(count);uint64_t total=0;
        for(int i=0;i<count;++i) {
            total+=guest[i*2+1];if(total>INT32_MAX) { Failure(j,h,EINVAL);return; }
            vectors[i]={guest[i*2+1]?Span(h,guest[i*2],guest[i*2+1]):nullptr,guest[i*2+1]};
        }
        Result(j,h,writev(NativeFd(j.Regs()[0]),vectors.data(),count));
    });
    RegisterThunk("sem_timedwait",[](Jit& j,Host& h) {
        auto s=GetSemaphore(j.Regs()[0]);timespec deadline{};
        if(!s) { Failure(j,h,EINVAL);return; }
        if(!ReadTime(h,j.Regs()[1],deadline)) { Failure(j,h,EINVAL);return; }
        Result(j,h,sem_timedwait(&s->value,&deadline));
    });
    RegisterThunk("pthread_cond_timedwait_relative_np",[](Jit& j,Host& h) {
        auto c=GetCondition(h,j.Regs()[0]);auto m=GetMutex(h,j.Regs()[1]);timespec duration{},deadline{};
        if(!c||!m||!ReadTime(h,j.Regs()[2],duration)||duration.tv_sec<0) { j.Regs()[0]=EINVAL;return; }
        if(clock_gettime(c->clock,&deadline)) { j.Regs()[0]=errno;return; }
        deadline.tv_sec+=duration.tv_sec;deadline.tv_nsec+=duration.tv_nsec;
        deadline.tv_sec+=deadline.tv_nsec/1000000000;deadline.tv_nsec%=1000000000;
        j.Regs()[0]=pthread_cond_timedwait(&c->value,&m->value,&deadline);
    });
    RegisterThunk("pthread_cond_timedwait_monotonic_np",[](Jit& j,Host& h) {
        auto c=GetCondition(h,j.Regs()[0]);auto m=GetMutex(h,j.Regs()[1]);timespec deadline{};
        if(!c||!m||!ReadTime(h,j.Regs()[2],deadline)) { j.Regs()[0]=EINVAL;return; }
        using ClockWait=int(*)(pthread_cond_t*,pthread_mutex_t*,clockid_t,const timespec*);
        static const auto clock_wait=reinterpret_cast<ClockWait>(dlsym(RTLD_DEFAULT,"pthread_cond_clockwait"));
        if(clock_wait)j.Regs()[0]=clock_wait(&c->value,&m->value,CLOCK_MONOTONIC,&deadline);
        else if(c->clock==CLOCK_MONOTONIC)j.Regs()[0]=pthread_cond_timedwait(&c->value,&m->value,&deadline);
        else j.Regs()[0]=ENOTSUP;
    });
    RegisterThunk("pthread_attr_getstack",[](Jit& j,Host& h) {
        auto* a=static_cast<const Attr32*>(Span(h,j.Regs()[0],sizeof(Attr32)));
        Span(h,j.Regs()[1],4);Span(h,j.Regs()[2],4);h.MemoryWrite32(j.Regs()[1],a->base);h.MemoryWrite32(j.Regs()[2],a->size);j.Regs()[0]=0;
    });
    RegisterThunk("pthread_getschedparam",[](Jit& j,Host& h) {
        auto thread=GetThread(j.Regs()[0]);if(!thread) { j.Regs()[0]=ESRCH;return; }
        Span(h,j.Regs()[1],4);Span(h,j.Regs()[2],4);pthread_t native;
        { std::lock_guard lock(thread->mutex);native=thread->native; }
        int policy;sched_param parameter{};int rc=pthread_getschedparam(native,&policy,&parameter);
        if(!rc) { h.MemoryWrite32(j.Regs()[1],policy);h.MemoryWrite32(j.Regs()[2],parameter.sched_priority); }j.Regs()[0]=rc;
    });
    RegisterThunk("gmtime",[](Jit& j,Host& h) {
        Span(h,j.Regs()[0],4);time_t value=static_cast<int32_t>(h.MemoryRead32(j.Regs()[0]));tm time{};
        if(!gmtime_r(&value,&time)) { j.Regs()[0]=0;Errno(h,errno);return; }
        if(!t_cache.tm)t_cache.tm=h.GuestAlloc(sizeof(Tm32),4);
        if(t_cache.tm)WriteTm(h,t_cache.tm,time);j.Regs()[0]=t_cache.tm;
    });

}
