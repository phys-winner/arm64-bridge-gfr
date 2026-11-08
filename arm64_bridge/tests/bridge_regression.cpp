#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "elf_loader.h"
#include "bridge_io.h"
#include <signal.h>
#include <semaphore.h>
#include <limits.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <zlib.h>
#include <algorithm>
#include <atomic>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

// Link wrapping is enabled only for this standalone target. Ordinary calls
// bypass the probe; no production thunk or shared-library seam is changed.
namespace {
enum SemProbePhase : unsigned { WaitEntered=1, WaitReturned=2, DestroyAttempt=4,
                               NativePosted=8, PostTailEnded=16 };
enum class SemProbeRole { None, Parent, Child };
thread_local SemProbeRole sem_probe_role=SemProbeRole::None;
std::atomic<bool> sem_probe_armed{false};
std::atomic<sem_t*> sem_probe_native{nullptr};
std::atomic<unsigned> sem_probe_phase{0};
std::atomic<int> sem_probe_post_errno{0};
using SemProbeClock=std::chrono::steady_clock;
[[noreturn]] void SemProbeTimeout(const char* phase) {
    fprintf(stderr,"FAIL semaphore probe timeout: %s phase=0x%x\n",phase,sem_probe_phase.load());
    std::abort();
}
void SemProbeWait(unsigned bits,const char* label) {
    const auto deadline=SemProbeClock::now()+std::chrono::milliseconds(500);
    while((sem_probe_phase.load(std::memory_order_acquire)&bits)!=bits) {
        if(SemProbeClock::now()>=deadline)SemProbeTimeout(label);
        std::this_thread::yield();
    }
}
void SemProbeArm() {
    sem_probe_native.store(nullptr);sem_probe_phase.store(0);sem_probe_post_errno.store(0);
    sem_probe_armed.store(true,std::memory_order_release);
}
}
extern "C" int __real_sem_wait(sem_t*);
extern "C" int __real_sem_post(sem_t*);
extern "C" int __wrap_sem_wait(sem_t* sem) {
    const bool selected=sem_probe_armed.load(std::memory_order_acquire)&&sem_probe_role==SemProbeRole::Parent;
    if(selected) {
        // The thunk already looked up and retained its host Semaphore.
        sem_probe_native.store(sem,std::memory_order_release);
        sem_probe_phase.fetch_or(WaitEntered,std::memory_order_release);
    }
    const int result=__real_sem_wait(sem),saved=errno;
    if(selected)sem_probe_phase.fetch_or(WaitReturned,std::memory_order_release);
    errno=saved;return result;
}
extern "C" int __wrap_sem_post(sem_t* sem) {
    const bool selected=sem_probe_armed.load(std::memory_order_acquire)&&sem_probe_role==SemProbeRole::Child
        &&sem==sem_probe_native.load(std::memory_order_acquire);
    const int result=__real_sem_post(sem),saved=errno;
    if(selected&&result==0) {
        sem_probe_post_errno.store(saved);
        sem_probe_phase.fetch_or(NativePosted,std::memory_order_release);
        SemProbeWait(WaitReturned|DestroyAttempt,"parent destruction attempt");
        // Parent has consumed the publication. Keep the old post's shared_ptr
        // tail alive, or the repaired post's registry lock, for this interval.
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        sem_probe_phase.fetch_or(PostTailEnded,std::memory_order_release);
    }
    errno=saved;return result;
}

namespace {
unsigned checks=0;
#define CHECK(expr) do { ++checks; if(!(expr)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#expr);std::abort(); } } while(0)
uint32_t Text(DynarmicHost& h,const char* text) {
    uint32_t p=h.GuestAlloc(strlen(text)+1);CHECK(p);memcpy(h.GetGuestMemoryBase()+p,text,strlen(text)+1);return p;
}
uint32_t Call(DynarmicHost& h,const char* name,const std::vector<uint32_t>& args={}) {
    uint32_t fn=h.GetThunkManager().FindRegisteredSymbol(name);
    CHECK(fn);uint32_t value=h.RunFunction(fn,args);CHECK(!h.HasFailed());return value;
}
void AbiAndDispatch(DynarmicHost& h) {
    CHECK(h.RunSelfChecks());
    CHECK(!GuestRangeValid(h.GetGuestMemorySize(),UINT32_MAX,SIZE_MAX));
    auto& m=h.GetThunkManager();
    CHECK(m.GetOrCreateThunkAddress("missing_symbol_must_not_succeed")==0);
    CHECK(m.ResolveSymbol("malloc",1)==0);
    CHECK(m.ResolveSymbol("__stack_chk_guard",2)==0);
    uint32_t p=m.RegisterThunk("test_replace",[](auto& j,auto&) { j.Regs()[0]=17; });
    CHECK(h.RunFunction(p)==17);
    CHECK(m.RegisterThunk("test_replace",[](auto& j,auto&) { j.Regs()[0]=42; })==p);
    CHECK(h.RunFunction(p)==42);
    // MRC TPIDRURO and TPIDRURW, independently mutable, bound to current thread.
    uint32_t code=h.GuestAlloc(16);h.AddExecutableRange(code,16);
    h.MemoryWrite32(code,0xee1d0f70);h.MemoryWrite32(code+4,0xe12fff1e);
    h.MemoryWrite32(code+8,0xee1d0f50);h.MemoryWrite32(code+12,0xe12fff1e);
    CHECK(h.RunFunction(code)==h.GuestTlsAddress());h.SetGuestTlsWritable(0x12345678);
    CHECK(h.RunFunction(code+8)==0x12345678);
    CHECK(h.RunFunction(code)==h.GuestTlsAddress());
    // Real ARM SVC 0 getpid path: PUSH preserves r7, POP returns to exit trap.
    uint32_t svc=h.GuestAlloc(16);h.AddExecutableRange(svc,16);
    uint32_t words[]={0xe92d4080,0xe3a07014,0xef000000,0xe8bd8080};
    memcpy(h.GetGuestMemoryBase()+svc,words,sizeof(words));
    CHECK(h.RunFunction(svc)==static_cast<uint32_t>(getpid()));
    uint32_t atomic=h.GuestAlloc(4);h.MemoryWrite32(atomic,5);
    CHECK(Call(h,"__atomic_inc",{atomic})==5&&h.MemoryRead32(atomic)==6);
    CHECK(Call(h,"__atomic_dec",{atomic})==6&&h.MemoryRead32(atomic)==5);
    CHECK(Call(h,"__atomic_cmpxchg",{5,9,atomic})==0&&h.MemoryRead32(atomic)==9);
    CHECK(Call(h,"__atomic_cmpxchg",{5,7,atomic})!=0&&h.MemoryRead32(atomic)==9);
    printf("PASS ABI, nested calls, thread contexts, dispatch, CP15, ARM syscalls\n");
}
void StringsAndStdio(DynarmicHost& h) {
    const uint32_t text=Text(h,"beta:alpha:gamma"),delim=Text(h,":"),save=h.GuestAlloc(4);
    CHECK(Call(h,"strtok_r",{text,delim,save})==text);
    CHECK(Call(h,"strtok_r",{0,delim,save})==text+5);
    uint32_t input=Text(h,"4294967296!"),end=h.GuestAlloc(8);
    h.MemoryWrite32(end+4,0xfeedbeef);
    CHECK(Call(h,"strtoul",{input,end,10})==UINT32_MAX);
    CHECK(h.MemoryRead32(h.GuestErrnoAddress())==ERANGE);
    CHECK(h.MemoryRead32(end)==input+10&&h.MemoryRead32(end+4)==0xfeedbeef);
    CHECK(Call(h,"strtoull",{input,end,10})==0&&h.GetResultHigh()==1);
    uint32_t format=Text(h,"%s %lld %.2f"),out=h.GuestAlloc(80),str=Text(h,"ok");
    // snprintf: r3 is %s; long long and double begin at even spilled words.
    const uint64_t bits=std::bit_cast<uint64_t>(1.25);
    CHECK(Call(h,"snprintf",{out,80,format,str,0x55667788,0x11223344,uint32_t(bits),uint32_t(bits>>32)})>0);
    CHECK(std::string(reinterpret_cast<char*>(h.GetGuestMemoryBase()+out))=="ok 1234605616436508552 1.25");
    uint32_t file=Call(h,"tmpfile");CHECK(file);
    uint32_t line=Text(h,"hello bridge\n");
    CHECK(Call(h,"fwrite",{line,1,13,file})==13);
    CHECK(Call(h,"fseeko",{file,0,SEEK_SET})==0);
    CHECK(Call(h,"fgets",{out,80,file})==out);
    CHECK(strcmp(reinterpret_cast<char*>(h.GetGuestMemoryBase()+out),"hello bridge\n")==0);
    CHECK(Call(h,"ftello",{file})==13);
    uint32_t stat=h.GuestAlloc(112);h.MemoryWrite64(stat+104,0x123456789abcdef0ULL);
    uint32_t fd=Call(h,"fileno",{file});CHECK(fd!=UINT32_MAX);
    CHECK(Call(h,"fstat",{fd,stat})==0);CHECK(h.MemoryRead64(stat+48)==13);
    CHECK(h.MemoryRead64(stat+104)==0x123456789abcdef0ULL);
    CHECK(Call(h,"fclose",{file})==0);
    // UTF-8 state is exactly four guest bytes, even though host mbstate_t is eight.
    uint32_t utf=Text(h,"\xe2\x82\xac"),state=h.GuestAlloc(8),wide=h.GuestAlloc(8);
    h.MemoryWrite32(state+4,0xdeadbeef);
    CHECK(Call(h,"mbrtowc",{wide,utf,1,state})==UINT32_MAX-1);
    CHECK(Call(h,"mbrtowc",{wide,utf+1,2,state})==2);
    CHECK(h.MemoryRead32(wide)==0x20ac&&h.MemoryRead32(state+4)==0xdeadbeef);
    uint32_t wc=Call(h,"wctype",{Text(h,"alpha")});CHECK(wc&&Call(h,"iswctype",{'A',wc}));
    uint32_t time=h.GuestAlloc(4),tm=h.GuestAlloc(52);h.MemoryWrite32(time,0);h.MemoryWrite64(tm+44,0x123456789abcdef0ULL);
    CHECK(Call(h,"gmtime_r",{time,tm})==tm);CHECK(h.MemoryRead32(tm+20)==70);
    CHECK(h.MemoryRead64(tm+44)==0x123456789abcdef0ULL);
    printf("PASS libc strings, varargs, FILE handles, stat32, UTF-8 state, tm32\n");
}
void ScansetParsing(DynarmicHost& h) {
    const uint32_t output=h.GuestAlloc(32),count=h.GuestAlloc(4);
    const uint32_t tag_format=Text(h,"<%[^>]>");
    auto result=[&]{return reinterpret_cast<const char*>(h.GetGuestMemoryBase()+output);};
    CHECK(Call(h,"sscanf",{Text(h,"<mass>"),tag_format,output})==1);
    CHECK(strcmp(result(),"mass")==0);
    CHECK(Call(h,"sscanf",{Text(h,"<shape>"),tag_format,output})==1);
    CHECK(strcmp(result(),"shape")==0);
    CHECK(Call(h,"sscanf",{Text(h,"abcdef"),Text(h,"%3[a-z]"),output})==1);
    CHECK(strcmp(result(),"abc")==0);
    CHECK(Call(h,"sscanf",{Text(h,"]abcz"),Text(h,"%[]a-c]"),output})==1);
    CHECK(strcmp(result(),"]abc")==0);
    CHECK(Call(h,"sscanf",{Text(h,"12 abc"),Text(h,"%[^a-z]"),output})==1);
    CHECK(strcmp(result(),"12 ")==0);
    CHECK(Call(h,"sscanf",{Text(h,"<solid>17"),Text(h,"<%*[^>]>%d"),count})==1);
    CHECK(h.MemoryRead32(count)==17);
    h.MemoryWrite32(count,UINT32_MAX);
    CHECK(Call(h,"sscanf",{Text(h,"<mass>"),Text(h,"<%[^>]>%n"),output,count})==1);
    CHECK(strcmp(result(),"mass")==0&&h.MemoryRead32(count)==6);
    CHECK(Call(h,"sscanf",{Text(h,">"),Text(h,"%[^>]"),output})==0);
    CHECK(Call(h,"sscanf",{Text(h,""),Text(h,"%[^>]"),output})==static_cast<uint32_t>(EOF));
    const uint32_t list=h.GuestAlloc(4);h.MemoryWrite32(list,output);
    CHECK(Call(h,"vsscanf",{Text(h,"<solid>"),tag_format,list})==1);
    CHECK(strcmp(result(),"solid")==0);
    printf("PASS ARM32 sscanf/vsscanf scansets, width, ranges, suppression, EOF\n");
}
void CallbacksAndThreads(DynarmicHost& h) {
    uint32_t values=h.GuestAlloc(32),cmp=h.GuestAlloc(16);
    int32_t data[]={8,1,7,2,6,3,5,4};memcpy(h.GetGuestMemoryBase()+values,data,sizeof(data));
    uint32_t instructions[]={0xe5900000,0xe5911000,0xe0400001,0xe12fff1e};
    memcpy(h.GetGuestMemoryBase()+cmp,instructions,sizeof(instructions));h.AddExecutableRange(cmp,16);
    Call(h,"qsort",{values,8,4,cmp});
    for(uint32_t i=0;i<8;++i)CHECK(h.MemoryRead32(values+i*4)==i+1);
    // Carmageddon's checkpoints are 0xA4-byte records ordered by the value at
    // offset 52. Exercise guest callbacks and movement of the complete record.
    constexpr uint32_t gate_size=0xA4;
    const uint32_t gates=h.GuestAlloc(gate_size*3),gate_cmp=h.GuestAlloc(16);
    const uint32_t gate_code[]={0xe5900034,0xe5911034,0xe0400001,0xe12fff1e};
    memcpy(h.GetGuestMemoryBase()+gate_cmp,gate_code,sizeof(gate_code));
    h.AddExecutableRange(gate_cmp,sizeof(gate_code));
    const float gate_distances[]={30.0f,10.0f,20.0f};
    for(uint32_t i=0;i<3;++i) {
        memset(h.GetGuestMemoryBase()+gates+i*gate_size,0x40+i,gate_size);
        h.MemoryWrite32(gates+i*gate_size+52,std::bit_cast<uint32_t>(gate_distances[i]));
    }
    Call(h,"qsort",{gates,3,gate_size,gate_cmp});
    for(uint32_t i=0;i<3;++i) {
        CHECK(h.MemoryRead32(gates+i*gate_size+52)==std::bit_cast<uint32_t>(gate_distances[i==0?1:i==1?2:0]));
        CHECK(h.GetGuestMemoryBase()[gates+i*gate_size]==0x40+(i==0?1:i==1?2:0));
        CHECK(h.GetGuestMemoryBase()[gates+(i+1)*gate_size-1]==0x40+(i==0?1:i==1?2:0));
    }
    uint32_t key=h.GuestAlloc(4);h.MemoryWrite32(key,5);
    CHECK(Call(h,"bsearch",{key,values,8,4,cmp})==values+16);
    const uint32_t mutex=h.GuestAlloc(4),counter=h.GuestAlloc(4),ids=h.GuestAlloc(16),result=h.GuestAlloc(4);
    CHECK(Call(h,"pthread_mutex_init",{mutex,0})==0);
    const uint32_t lock=h.FindSymbol("pthread_mutex_lock"),unlock=h.FindSymbol("pthread_mutex_unlock");
    auto worker=h.GetThunkManager().RegisterThunk("test_thread_worker",[=](auto& j,auto& host) {
        for(unsigned i=0;i<200;++i) {
            if(host.RunFunction(lock,{mutex})) { host.Fail("Worker mutex lock");return; }
            host.MemoryWrite32(counter,host.MemoryRead32(counter)+1);
            if(host.RunFunction(unlock,{mutex})) { host.Fail("Worker mutex unlock");return; }
        }
        j.Regs()[0]=0xabcdef;
    });
    for(unsigned i=0;i<4;++i)CHECK(Call(h,"pthread_create",{ids+4*i,0,worker,0})==0);
    for(unsigned i=0;i<4;++i) { CHECK(Call(h,"pthread_join",{h.MemoryRead32(ids+4*i),result})==0);CHECK(h.MemoryRead32(result)==0xabcdef); }
    CHECK(h.MemoryRead32(counter)==800);CHECK(Call(h,"pthread_mutex_destroy",{mutex})==0);
    uint32_t sem=h.GuestAlloc(16);CHECK(Call(h,"sem_init",{sem,0,0})==0);
    CHECK(Call(h,"sem_trywait",{sem})==UINT32_MAX&&h.MemoryRead32(h.GuestErrnoAddress())==EAGAIN);
    CHECK(Call(h,"sem_post",{sem})==0&&Call(h,"sem_wait",{sem})==0&&Call(h,"sem_destroy",{sem})==0);
    uint32_t guard=h.GuestAlloc(8);CHECK(Call(h,"__cxa_guard_acquire",{guard})==1);
    Call(h,"__cxa_guard_abort",{guard});CHECK(Call(h,"__cxa_guard_acquire",{guard})==1);
    Call(h,"__cxa_guard_release",{guard});CHECK(Call(h,"__cxa_guard_acquire",{guard})==0);
    printf("PASS guest qsort/bsearch callbacks, concurrent pthreads, semaphore, C++ guards\n");
}
void SemaphorePostRetirement(DynarmicHost& h) {
    const uint32_t post=h.GetThunkManager().FindRegisteredSymbol("sem_post");CHECK(post);
    uint32_t sem=Call(h,"malloc",{16});CHECK(sem&&Call(h,"sem_init",{sem,0,0})==0);
    SemProbeArm();sem_probe_role=SemProbeRole::Parent;
    std::atomic<bool> finished{false};
    std::thread watchdog([&] {
        const auto deadline=SemProbeClock::now()+std::chrono::milliseconds(500);
        while(!finished.load(std::memory_order_acquire)) {
            if(SemProbeClock::now()>=deadline)SemProbeTimeout("handshake completion");
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });
    uint32_t posted=UINT32_MAX,guest_error=0;int native_error=0;
    std::thread child([&] {
        sem_probe_role=SemProbeRole::Child;
        SemProbeWait(WaitEntered,"parent semaphore lookup");
        const uint32_t error=h.GuestErrnoAddress();h.MemoryWrite32(error,EINPROGRESS);errno=E2BIG;
        posted=h.RunFunction(post,{sem});native_error=errno;guest_error=h.MemoryRead32(error);
        h.ReleaseCurrentThread();
    });
    CHECK(Call(h,"sem_wait",{sem})==0);
    SemProbeWait(NativePosted,"child publication");
    sem_probe_phase.fetch_or(DestroyAttempt,std::memory_order_release);
    const uint32_t destroyed=Call(h,"sem_destroy",{sem});
    const unsigned destroy_phase=sem_probe_phase.load(std::memory_order_acquire);
    const uint32_t destroy_error=h.MemoryRead32(h.GuestErrnoAddress());
    child.join();finished.store(true,std::memory_order_release);watchdog.join();
    sem_probe_role=SemProbeRole::None;sem_probe_armed.store(false,std::memory_order_release);
    printf("SEM_POST_HANDSHAKE destroy_rc=%d phase=0x%x destroy_errno=%u post_rc=%d\n",
           int32_t(destroyed),destroy_phase,destroy_error,int32_t(posted));
    fflush(stdout);
    CHECK(posted==0&&destroyed==0&&destroy_phase==(WaitEntered|WaitReturned|DestroyAttempt|NativePosted|PostTailEnded));
    CHECK(native_error==sem_probe_post_errno.load()&&guest_error==EINPROGRESS);
    Call(h,"free",{sem});
    const uint32_t reused=Call(h,"malloc",{16});CHECK(reused==sem);
    CHECK(Call(h,"sem_init",{reused,0,2})==0);
    CHECK(Call(h,"sem_trywait",{reused})==0&&Call(h,"sem_trywait",{reused})==0);
    CHECK(Call(h,"sem_trywait",{reused})==UINT32_MAX&&h.MemoryRead32(h.GuestErrnoAddress())==EAGAIN);
    CHECK(Call(h,"sem_destroy",{reused})==0);
    CHECK(Call(h,"sem_post",{reused})==UINT32_MAX&&h.MemoryRead32(h.GuestErrnoAddress())==EINVAL);
    Call(h,"free",{reused});

    // A real blocked wait still pins the object and must reject destruction.
    sem=Call(h,"malloc",{16});CHECK(Call(h,"sem_init",{sem,0,0})==0);
    const uint32_t wait=h.GetThunkManager().FindRegisteredSymbol("sem_wait");CHECK(wait);
    SemProbeArm();uint32_t waited=UINT32_MAX;
    std::thread waiter([&] {
        sem_probe_role=SemProbeRole::Parent;waited=h.RunFunction(wait,{sem});h.ReleaseCurrentThread();
    });
    SemProbeWait(WaitEntered,"blocked waiter lookup");
    CHECK(Call(h,"sem_destroy",{sem})==UINT32_MAX&&h.MemoryRead32(h.GuestErrnoAddress())==EBUSY);
    CHECK(!(sem_probe_phase.load()&WaitReturned));
    CHECK(Call(h,"sem_post",{sem})==0);SemProbeWait(WaitReturned,"blocked waiter release");
    waiter.join();sem_probe_armed.store(false,std::memory_order_release);CHECK(waited==0);
    CHECK(Call(h,"sem_destroy",{sem})==0);Call(h,"free",{sem});

    // Native overflow keeps its exact failure and errno; it does not publish.
    sem=Call(h,"malloc",{16});CHECK(Call(h,"sem_init",{sem,0,SEM_VALUE_MAX})==0);
    CHECK(Call(h,"sem_post",{sem})==UINT32_MAX&&h.MemoryRead32(h.GuestErrnoAddress())==EOVERFLOW);
    CHECK(errno==EOVERFLOW);CHECK(Call(h,"sem_destroy",{sem})==0);Call(h,"free",{sem});
    printf("PASS semaphore publication/retirement, address reuse, blocked-wait guard, failure errno\n");
}
void Zlib(DynarmicHost& h) {
    uint32_t source=Text(h,"compress this text, compress this text, compress this text"),packed=h.GuestAlloc(256),out=h.GuestAlloc(256),length=h.GuestAlloc(8);
    const uint32_t size=strlen(reinterpret_cast<char*>(h.GetGuestMemoryBase()+source))+1;
    h.MemoryWrite32(length,256);h.MemoryWrite32(length+4,0xdeadbeef);
    CHECK(Call(h,"compress2",{packed,length,source,size,9})==Z_OK);const uint32_t compressed=h.MemoryRead32(length);
    CHECK(h.MemoryRead32(length+4)==0xdeadbeef);h.MemoryWrite32(length,256);
    CHECK(Call(h,"uncompress",{out,length,packed,compressed})==Z_OK);
    CHECK(h.MemoryRead32(length)==size&&!memcmp(h.GetGuestMemoryBase()+source,h.GetGuestMemoryBase()+out,size));
    uint32_t stream=h.GuestAlloc(64),version=Call(h,"zlibVersion");h.MemoryWrite64(stream+56,0x123456789abcdef0ULL);
    CHECK(static_cast<int32_t>(Call(h,"inflateInit2_",{stream,15,version,112}))==Z_VERSION_ERROR);
    CHECK(Call(h,"inflateInit2_",{stream,15,version,56})==Z_OK);
    h.MemoryWrite32(stream,packed);h.MemoryWrite32(stream+4,compressed);h.MemoryWrite32(stream+12,out);h.MemoryWrite32(stream+16,256);
    CHECK(Call(h,"inflate",{stream,Z_FINISH})==Z_STREAM_END);CHECK(h.MemoryRead32(stream+20)==size);
    CHECK(Call(h,"inflateReset",{stream})==Z_OK&&h.MemoryRead32(stream+20)==0);
    CHECK(Call(h,"inflateEnd",{stream})==Z_OK&&h.MemoryRead32(stream+28)==0);
    CHECK(h.MemoryRead64(stream+56)==0x123456789abcdef0ULL);
    CHECK(Call(h,"deflateInit2_",{stream,6,Z_DEFLATED,15,8,Z_DEFAULT_STRATEGY,version,56})==Z_OK);
    h.MemoryWrite32(stream,source);h.MemoryWrite32(stream+4,size);h.MemoryWrite32(stream+12,packed);h.MemoryWrite32(stream+16,256);
    CHECK(Call(h,"deflate",{stream,Z_FINISH})==Z_STREAM_END);CHECK(Call(h,"deflateEnd",{stream})==Z_OK);
    CHECK(Call(h,"crc32",{0,source,size})==crc32(0,h.GetGuestMemoryBase()+source,size));
    printf("PASS zlib roundtrip, z_stream32, stack args, versions, reset/end, canaries\n");
}
// Exact pre-fix canonical assets, including their CRLF bytes. This probe
// changes only the external-extension token; it does not translate GLSL.
void ExternalVideoShader(DynarmicHost& h) {
    static constexpr char vertex_source[] =
        "#version 300 es\r\n"
        "precision highp float;\r\n"
        "in vec3 vs_Position;\r\n"
        "in vec2 vs_TexCoord;\r\n"
        "out vec2 ps_TexCoord;\r\n"
        "void main ()\r\n"
        "{\r\n"
        "  vec4 tmpvar_1;\r\n"
        "  tmpvar_1.w = 1.0;\r\n"
        "  tmpvar_1.xyz = vs_Position;\r\n"
        "  gl_Position = tmpvar_1;\r\n"
        "  ps_TexCoord = vs_TexCoord;\r\n"
        "}\r\n"
        "\r\n";
    static constexpr char fragment_source[] =
        "#version 300 es\r\n"
        "#extension GL_OES_EGL_image_external       : require\r\n"
        "precision highp float;\r\n"
        "layout(std140) uniform PSConstants {\r\n"
        "     vec4    MultiplyColor;     vec4    TexelSizeDesaturateGamma;     vec4    ColorKey;\r\n"
        "} constantsP;\r\n"
        "uniform samplerExternalOES ps_Texture0;\r\n"
        "in vec2 ps_TexCoord;\r\n"
        "out vec4 ps_result;\r\n"
        "void main ()\r\n"
        "{\r\n"
        "  vec4 texColor_1;\r\n"
        "  vec4 tmpvar_2;\r\n"
        "  tmpvar_2 = texture  (ps_Texture0, ps_TexCoord);\r\n"
        "  texColor_1.w = tmpvar_2.w;\r\n"
        "  texColor_1.xyz = mix (tmpvar_2.xyz, vec3(dot (tmpvar_2.xyz, vec3(0.2125, 0.7154, 0.0721))), constantsP.TexelSizeDesaturateGamma.z);\r\n"
        "  texColor_1.xyz = exp2(((\r\n"
        "    log2(texColor_1.xyz)\r\n"
        "   * constantsP.TexelSizeDesaturateGamma.www) + 1e-05));\r\n"
        "  ps_result = (texColor_1 * constantsP.MultiplyColor);\r\n"
        "}\r\n"
        "\r\n"
        "\r\n";
    const auto* renderer=glGetString(GL_RENDERER);
    const auto* version=glGetString(GL_VERSION);
    CHECK(renderer&&version);
    GLint major=0,extension_count=0;
    glGetIntegerv(GL_MAJOR_VERSION,&major);
    glGetIntegerv(GL_NUM_EXTENSIONS,&extension_count);
    CHECK(major>=3&&extension_count>=0);
    bool external_essl3=false;
    for(GLint i=0;i<extension_count;++i) {
        const auto* extension=glGetStringi(GL_EXTENSIONS,static_cast<GLuint>(i));
        CHECK(extension);
        if(strcmp(reinterpret_cast<const char*>(extension),
                  "GL_OES_EGL_image_external_essl3")==0)external_essl3=true;
    }
    printf("PROBE external_video renderer=%s version=%s GL_OES_EGL_image_external_essl3=%u\n",
           reinterpret_cast<const char*>(renderer),reinterpret_cast<const char*>(version),
           unsigned(external_essl3));
    printf("PROBE external_video vertex_bytes=%zu vertex_sha256=8091b6374e02b85bdd67af27179f5d8d3958e94f5091c8c89f16205a00e975bb "
           "fragment_bytes=%zu fragment_sha256=b43a5034f207aa838253976dfb426208d13d726972efd0240c0249e988a088ef\n",
           sizeof(vertex_source)-1,sizeof(fragment_source)-1);
    const auto compile=[&](GLenum type,const char* source,size_t size,
                           const char* label,GLint& compiled) {
        uint32_t text=h.GuestAlloc(size+1),array=h.GuestAlloc(4);
        uint32_t length=h.GuestAlloc(4),status=h.GuestAlloc(4);
        CHECK(text&&array&&length&&status&&size<=INT_MAX);
        memcpy(h.GetGuestMemoryBase()+text,source,size);
        h.MemoryWrite8(text+static_cast<uint32_t>(size),0);
        h.MemoryWrite32(array,text);h.MemoryWrite32(length,static_cast<uint32_t>(size));
        const GLuint shader=Call(h,"glCreateShader",{type});CHECK(shader);
        Call(h,"glShaderSource",{shader,1,array,length});
        Call(h,"glCompileShader",{shader});
        Call(h,"glGetShaderiv",{shader,GL_COMPILE_STATUS,status});
        compiled=static_cast<GLint>(h.MemoryRead32(status));
        char log[2048]{};
        glGetShaderInfoLog(shader,sizeof(log),nullptr,log);
        printf("PROBE external_video %s compile=%d log=%s\n",label,compiled,log);
        h.GuestFree(status);h.GuestFree(length);h.GuestFree(array);h.GuestFree(text);
        return shader;
    };
    std::string corrected(fragment_source,sizeof(fragment_source)-1);
    const char legacy[]="GL_OES_EGL_image_external";
    const size_t at=corrected.find(legacy);
    CHECK(at!=std::string::npos&&corrected.find(legacy,at+sizeof(legacy)-1)==std::string::npos);
    corrected.replace(at,sizeof(legacy)-1,"GL_OES_EGL_image_external_essl3");
    GLint vertex_ok=0,legacy_ok=0,corrected_ok=0;
    const GLuint vs=compile(GL_VERTEX_SHADER,vertex_source,sizeof(vertex_source)-1,
                            "textured_quad_v",vertex_ok);
    const GLuint old_ps=compile(GL_FRAGMENT_SHADER,fragment_source,sizeof(fragment_source)-1,
                                "legacy_video_quad_p",legacy_ok);
    const GLuint ps=compile(GL_FRAGMENT_SHADER,corrected.data(),corrected.size(),
                            "corrected_video_quad_p",corrected_ok);
    const GLuint program=Call(h,"glCreateProgram");CHECK(program);
    Call(h,"glAttachShader",{program,vs});Call(h,"glAttachShader",{program,ps});
    Call(h,"glLinkProgram",{program});
    uint32_t link_status=h.GuestAlloc(4);CHECK(link_status);
    Call(h,"glGetProgramiv",{program,GL_LINK_STATUS,link_status});
    const GLint linked=static_cast<GLint>(h.MemoryRead32(link_status));
    char log[2048]{};
    glGetProgramInfoLog(program,sizeof(log),nullptr,log);
    printf("PROBE external_video corrected_link=%d legacy_compile=%d log=%s\n",linked,legacy_ok,log);
    // No UseProgram, draw, texture/sampler/buffer bind or glGetError here.
    // Both successful and failed legacy compiles are permitted controls.
    Call(h,"glDeleteProgram",{program});Call(h,"glDeleteShader",{ps});
    Call(h,"glDeleteShader",{old_ps});Call(h,"glDeleteShader",{vs});h.GuestFree(link_status);
    CHECK(external_essl3&&vertex_ok==GL_TRUE&&corrected_ok==GL_TRUE&&linked==GL_TRUE);
    printf("PASS exact ESSL3 external video compile/link; legacy control recorded\n");
}
void Graphics(DynarmicHost& h) {
    const uint32_t display=Call(h,"eglGetDisplay",{0});
    CHECK(Call(h,"eglInitialize",{display,0,0})); // Required hardware probe cannot silently skip.
    uint32_t attributes=h.GuestAlloc(48),config=h.GuestAlloc(4),count=h.GuestAlloc(4);
    uint32_t attrs[]={EGL_SURFACE_TYPE,EGL_PBUFFER_BIT,EGL_RENDERABLE_TYPE,EGL_OPENGL_ES3_BIT,EGL_RED_SIZE,8,EGL_NONE};
    memcpy(h.GetGuestMemoryBase()+attributes,attrs,sizeof(attrs));
    CHECK(Call(h,"eglChooseConfig",{display,attributes,config,1,count}));CHECK(h.MemoryRead32(count)>0);
    h.MemoryWrite32(attributes,EGL_CONTEXT_CLIENT_VERSION);h.MemoryWrite32(attributes+4,3);h.MemoryWrite32(attributes+8,EGL_NONE);
    uint32_t context=Call(h,"eglCreateContext",{display,h.MemoryRead32(config),0,attributes});CHECK(context);
    uint32_t pbuffer[]={EGL_WIDTH,16,EGL_HEIGHT,16,EGL_NONE};memcpy(h.GetGuestMemoryBase()+attributes,pbuffer,sizeof(pbuffer));
    uint32_t surface=Call(h,"eglCreatePbufferSurface",{display,h.MemoryRead32(config),attributes});CHECK(surface);
    CHECK(Call(h,"eglMakeCurrent",{display,surface,surface,context}));
    CHECK(Call(h,"eglGetCurrentContext")==context);
    CHECK(Call(h,"eglQueryString",{display,EGL_VENDOR})==Call(h,"eglQueryString",{display,EGL_VENDOR}));
    uint32_t buffer=h.GuestAlloc(4);Call(h,"glGenBuffers",{1,buffer});CHECK(h.MemoryRead32(buffer));
    Call(h,"glBindBuffer",{GL_ARRAY_BUFFER,h.MemoryRead32(buffer)});Call(h,"glBufferData",{GL_ARRAY_BUFFER,64,0,GL_DYNAMIC_DRAW});
    uint32_t mapped=Call(h,"glMapBufferRange",{GL_ARRAY_BUFFER,0,64,GL_MAP_WRITE_BIT|GL_MAP_INVALIDATE_BUFFER_BIT});CHECK(mapped);
    memset(h.GetGuestMemoryBase()+mapped,0x45,64);CHECK(Call(h,"glUnmapBuffer",{GL_ARRAY_BUFFER}));
    // Two unshared contexts can both name their first buffer 1. Their live
    // guest mappings must survive context switches without aliasing each other.
    mapped=Call(h,"glMapBufferRange",{GL_ARRAY_BUFFER,0,64,GL_MAP_WRITE_BIT});CHECK(mapped);
    memset(h.GetGuestMemoryBase()+mapped,0x5a,64);
    uint32_t pointer_out=h.GuestAlloc(8);h.MemoryWrite32(pointer_out+4,0xfeedbeef);
    Call(h,"glGetBufferPointerv",{GL_ARRAY_BUFFER,GL_BUFFER_MAP_POINTER,pointer_out});
    CHECK(h.MemoryRead32(pointer_out)==mapped&&h.MemoryRead32(pointer_out+4)==0xfeedbeef);
    h.MemoryWrite32(attributes,EGL_CONTEXT_CLIENT_VERSION);h.MemoryWrite32(attributes+4,3);h.MemoryWrite32(attributes+8,EGL_NONE);
    uint32_t second=Call(h,"eglCreateContext",{display,h.MemoryRead32(config),0,attributes});CHECK(second);
    CHECK(Call(h,"eglMakeCurrent",{display,surface,surface,second}));
    uint32_t buffer2=h.GuestAlloc(4);Call(h,"glGenBuffers",{1,buffer2});
    Call(h,"glBindBuffer",{GL_ARRAY_BUFFER,h.MemoryRead32(buffer2)});Call(h,"glBufferData",{GL_ARRAY_BUFFER,64,0,GL_DYNAMIC_DRAW});
    uint32_t mapped2=Call(h,"glMapBufferRange",{GL_ARRAY_BUFFER,0,64,GL_MAP_WRITE_BIT});CHECK(mapped2&&mapped2!=mapped);
    memset(h.GetGuestMemoryBase()+mapped2,0x7b,64);
    CHECK(Call(h,"eglMakeCurrent",{display,surface,surface,context}));CHECK(Call(h,"glUnmapBuffer",{GL_ARRAY_BUFFER}));
    mapped=Call(h,"glMapBufferRange",{GL_ARRAY_BUFFER,0,64,GL_MAP_READ_BIT});CHECK(mapped&&h.GetGuestMemoryBase()[mapped]==0x5a);
    CHECK(Call(h,"glUnmapBuffer",{GL_ARRAY_BUFFER}));
    CHECK(Call(h,"eglMakeCurrent",{display,surface,surface,second}));CHECK(Call(h,"glUnmapBuffer",{GL_ARRAY_BUFFER}));
    mapped2=Call(h,"glMapBufferRange",{GL_ARRAY_BUFFER,0,64,GL_MAP_READ_BIT});CHECK(mapped2&&h.GetGuestMemoryBase()[mapped2]==0x7b);
    CHECK(Call(h,"glUnmapBuffer",{GL_ARRAY_BUFFER}));Call(h,"glDeleteBuffers",{1,buffer2});
    CHECK(Call(h,"eglMakeCurrent",{display,surface,surface,context}));CHECK(Call(h,"eglDestroyContext",{display,second}));
    uint32_t sync=Call(h,"glFenceSync",{GL_SYNC_GPU_COMMANDS_COMPLETE,0});CHECK(sync);
    uint32_t wait=Call(h,"glClientWaitSync",{sync,GL_SYNC_FLUSH_COMMANDS_BIT,UINT32_MAX,UINT32_MAX});
    CHECK(wait==GL_ALREADY_SIGNALED||wait==GL_CONDITION_SATISFIED);Call(h,"glDeleteSync",{sync});
    Call(h,"glDeleteBuffers",{1,buffer});CHECK(Call(h,"glGetError")==GL_NO_ERROR);
    ExternalVideoShader(h);CHECK(Call(h,"glGetError")==GL_NO_ERROR);
    CHECK(Call(h,"eglMakeCurrent",{display,0,0,0}));CHECK(Call(h,"eglDestroySurface",{display,surface}));CHECK(Call(h,"eglDestroyContext",{display,context}));
    attrs[3]=EGL_OPENGL_ES2_BIT;memcpy(h.GetGuestMemoryBase()+attributes,attrs,sizeof(attrs));
    CHECK(Call(h,"eglChooseConfig",{display,attributes,config,1,count}));CHECK(h.MemoryRead32(count)>0);
    h.MemoryWrite32(attributes,EGL_CONTEXT_CLIENT_VERSION);h.MemoryWrite32(attributes+4,2);h.MemoryWrite32(attributes+8,EGL_NONE);
    context=Call(h,"eglCreateContext",{display,h.MemoryRead32(config),0,attributes});CHECK(context);
    memcpy(h.GetGuestMemoryBase()+attributes,pbuffer,sizeof(pbuffer));surface=Call(h,"eglCreatePbufferSurface",{display,h.MemoryRead32(config),attributes});CHECK(surface);
    CHECK(Call(h,"eglMakeCurrent",{display,surface,surface,context}));CHECK(Call(h,"glGetError")==GL_NO_ERROR);
    uint32_t texture=h.GuestAlloc(4),pixel=h.GuestAlloc(4);h.MemoryWrite32(pixel,UINT32_MAX);
    Call(h,"glGenTextures",{1,texture});Call(h,"glBindTexture",{GL_TEXTURE_2D,h.MemoryRead32(texture)});
    Call(h,"glTexImage2D",{GL_TEXTURE_2D,0,GL_RGBA,1,1,0,GL_RGBA,GL_UNSIGNED_BYTE,pixel});CHECK(Call(h,"glGetError")==GL_NO_ERROR);
    Call(h,"glDeleteTextures",{1,texture});CHECK(Call(h,"eglMakeCurrent",{display,0,0,0}));CHECK(Call(h,"eglDestroySurface",{display,surface}));CHECK(Call(h,"eglDestroyContext",{display,context}));CHECK(Call(h,"eglTerminate",{display}));
    printf("PASS EGL handles/cache, GLES2 textures, GLES3 context-isolated mapped buffers and GLsync\n");
}
void ElfFixtures(DynarmicHost& h) {
    std::vector<uint8_t> bytes(0x500);
    auto put=[&](size_t at,const auto& object) { memcpy(bytes.data()+at,&object,sizeof(object)); };
    Elf32_Ehdr eh{};memcpy(eh.e_ident,ELFMAG,SELFMAG);eh.e_ident[EI_CLASS]=ELFCLASS32;
    eh.e_ident[EI_DATA]=ELFDATA2LSB;eh.e_ident[EI_VERSION]=EV_CURRENT;
    eh.e_machine=EM_ARM;eh.e_type=ET_DYN;eh.e_version=EV_CURRENT;eh.e_ehsize=sizeof(eh);
    eh.e_phoff=sizeof(eh);eh.e_phnum=2;eh.e_phentsize=sizeof(Elf32_Phdr);put(0,eh);
    Elf32_Phdr load{PT_LOAD,0,0,0,0x500,0x500,PF_R|PF_W|PF_X,0x1000};put(sizeof(eh),load);
    std::vector<Elf32_Dyn> dynamic;
    auto tag=[&](int32_t t,uint32_t value) { Elf32_Dyn d{};d.d_tag=t;d.d_un.d_val=value;dynamic.push_back(d); };
    tag(DT_STRTAB,0x120);tag(DT_STRSZ,40);tag(DT_SYMTAB,0x180);tag(DT_SYMENT,16);
    tag(DT_GNU_HASH,0x200);tag(DT_REL,0x340);tag(DT_RELSZ,24);tag(DT_INIT,0x400);
    tag(DT_INIT_ARRAY,0x388);tag(DT_INIT_ARRAYSZ,4);tag(DT_NULL,0);
    Elf32_Phdr dyn{PT_DYNAMIC,0x280,0x280,0,uint32_t(dynamic.size()*8),uint32_t(dynamic.size()*8),PF_R|PF_W,4};put(sizeof(eh)+sizeof(load),dyn);
    memcpy(bytes.data()+0x280,dynamic.data(),dynamic.size()*8);
    const char names[]="\0optional\0absolute\0entry\0";memcpy(bytes.data()+0x120,names,sizeof(names));
    Elf32_Sym weak{1,0,0,ELF32_ST_INFO(STB_WEAK,STT_FUNC),0,SHN_UNDEF};put(0x190,weak);
    Elf32_Sym absolute{10,0x12345678,0,ELF32_ST_INFO(STB_GLOBAL,STT_OBJECT),0,SHN_ABS};put(0x1a0,absolute);
    Elf32_Sym entry{19,0x400,8,ELF32_ST_INFO(STB_GLOBAL,STT_FUNC),0,1};put(0x1b0,entry);
    uint32_t hash[]={1,3,1,0,0,3,1};memcpy(bytes.data()+0x200,hash,sizeof(hash));
    Elf32_Rel rels[]={{0x380,ELF32_R_INFO(1,R_ARM_ABS32)},{0x384,ELF32_R_INFO(2,R_ARM_ABS32)},{0x388,ELF32_R_INFO(0,R_ARM_RELATIVE)}};
    memcpy(bytes.data()+0x340,rels,sizeof(rels));put(0x380,uint32_t(0x11));put(0x388,uint32_t(0x404));
    put(0x400,uint32_t(0xe12fff1e));put(0x404,uint32_t(0xe12fff1e));
    constexpr uint32_t base=0x40000000;
    ElfLoader loader(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),base,base+0x10000);
    CHECK(loader.LoadFromMemory(bytes.data(),bytes.size()));CHECK(loader.Relocate([](const auto&,uint8_t){return 0;}));
    CHECK(h.MemoryRead32(base+0x380)==0x11);CHECK(h.MemoryRead32(base+0x384)==0x12345678);
    CHECK(loader.GetSymbolAddress("absolute")==0x12345678);CHECK(loader.GetSymbolAddress("entry")==base+0x400);
    CHECK(loader.GetInitArray()==std::vector<uint32_t>({base+0x400,base+0x404}));
    weak.st_info=ELF32_ST_INFO(STB_GLOBAL,STT_FUNC);put(0x190,weak);
    ElfLoader strong(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),base,base+0x10000);
    CHECK(strong.LoadFromMemory(bytes.data(),bytes.size()));CHECK(!strong.Relocate([](const auto&,uint8_t){return 0;}));
    CHECK(h.MemoryRead32(base+0x384)==0&&h.MemoryRead32(base+0x388)==0x404);
    CHECK(strong.Relocate([](const auto& name,uint8_t type){return name=="optional"&&type==STT_FUNC?0x2222:0;}));
    CHECK(h.MemoryRead32(base+0x380)==0x2233);
    put(0x214,uint32_t(UINT32_MAX));
    ElfLoader bad(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),base,base+0x10000);
    CHECK(!bad.LoadFromMemory(bytes.data(),bytes.size()));
    put(0x214,uint32_t(3));
    auto packed=dynamic;packed.back().d_tag=DT_ANDROID_REL;packed.back().d_un.d_val=0x340;
    packed.push_back({});memcpy(bytes.data()+0x280,packed.data(),packed.size()*8);
    dyn.p_filesz=dyn.p_memsz=packed.size()*8;put(sizeof(eh)+sizeof(load),dyn);
    ElfLoader packed_loader(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),base,base+0x10000);
    CHECK(!packed_loader.LoadFromMemory(bytes.data(),bytes.size()));
    eh.e_phnum=3;put(0,eh);Elf32_Phdr tls{};tls.p_type=PT_TLS;put(sizeof(eh)+2*sizeof(load),tls);
    ElfLoader tls_loader(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),base,base+0x10000);
    CHECK(!tls_loader.LoadFromMemory(bytes.data(),bytes.size()));
    printf("PASS stripped GNU hash ELF, weak/strong imports, atomic relocation validation, DT_INIT/init_array, SHN_ABS\n");
}
void PosixComplements(DynarmicHost& h) {
    uint32_t timeout=h.GuestAlloc(8);h.MemoryWrite64(timeout,0);
    CHECK(Call(h,"sysconf",{_SC_PAGESIZE})==4096);CHECK(Call(h,"getpagesize")==4096);
    CHECK(Call(h,"getauxval",{6})==4096);CHECK(Call(h,"getauxval",{16})&(1u<<12));
    uint32_t upper=h.MemoryRead32(h.GetThunkManager().FindRegisteredSymbol("_toupper_tab_"));
    CHECK(h.MemoryRead16(upper)==0xffff&&h.MemoryRead16(upper+('a'+1)*2)=='A');
    uint32_t sem=h.GuestAlloc(16),cond=h.GuestAlloc(4),mutex=h.GuestAlloc(4);
    h.MemoryWrite32(cond,0);h.MemoryWrite32(mutex,0);
    CHECK(Call(h,"sem_init",{sem,0,0})==0);
    CHECK(Call(h,"sem_timedwait",{sem,timeout})==UINT32_MAX&&h.MemoryRead32(h.GuestErrnoAddress())==ETIMEDOUT);
    CHECK(Call(h,"sem_post",{sem})==0);CHECK(Call(h,"sem_timedwait",{sem,timeout})==0);CHECK(Call(h,"sem_destroy",{sem})==0);
    CHECK(Call(h,"pthread_mutex_lock",{mutex})==0);
    CHECK(Call(h,"pthread_cond_timedwait_relative_np",{cond,mutex,timeout})==ETIMEDOUT);
    CHECK(Call(h,"pthread_cond_timedwait_monotonic_np",{cond,mutex,timeout})==ETIMEDOUT);
    CHECK(Call(h,"pthread_mutex_unlock",{mutex})==0);
    CHECK(Call(h,"pthread_cond_destroy",{cond})==0);CHECK(Call(h,"pthread_mutex_destroy",{mutex})==0);
    CHECK(Call(h,"select",{0,0,0,0,timeout})==0);
    uint32_t pair=h.GuestAlloc(8);CHECK(Call(h,"pipe",{pair})==0);
    int descriptors[]={int(h.MemoryRead32(pair)),int(h.MemoryRead32(pair+4))};
    uint32_t text=Text(h,"AB"),iov=h.GuestAlloc(16);
    uint32_t vectors[]={text,1,text+1,1};memcpy(h.GetGuestMemoryBase()+iov,vectors,sizeof(vectors));
    CHECK(Call(h,"writev",{uint32_t(descriptors[1]),iov,2})==2);
    uint32_t set=h.GuestAlloc(128);memset(h.GetGuestMemoryBase()+set,0,128);
    const uint32_t word=set+(descriptors[0]/32)*4;h.MemoryWrite32(word,1u<<(descriptors[0]%32));
    CHECK(Call(h,"select",{uint32_t(descriptors[0]+1),set,0,0,timeout})==1);
    CHECK(h.MemoryRead32(word)==1u<<(descriptors[0]%32));close(descriptors[0]);close(descriptors[1]);
    uint32_t name=Text(h,"localhost"),entry=Call(h,"gethostbyname",{name});CHECK(entry);
    CHECK(h.MemoryRead32(entry+8)==2&&h.MemoryRead32(entry+12)==4);
    uint32_t lib=Text(h,"libz.so"),symbol=Text(h,"inflate"),missing=Text(h,"lib_missing_bridge_fixture.so");
    CHECK(Call(h,"dlopen",{missing,2})==0);CHECK(Call(h,"dlerror"));CHECK(Call(h,"dlerror")==0);
    uint32_t handle=Call(h,"dlopen",{lib,2});CHECK(handle);
    CHECK(Call(h,"dlsym",{handle,symbol})==h.GetThunkManager().FindRegisteredSymbol("inflate"));
    CHECK(Call(h,"dlclose",{handle})==0);
    printf("PASS fd_set32/select, hostent32/localhost, dlopen/dlsym/dlerror\n");
}
void GrimBoundaryImports(DynarmicHost& h) {
    CHECK(Call(h,"isnanf",{0x7fc00000})==1);
    CHECK(Call(h,"isnanf",{0})==0);
    uint32_t mask=h.GuestAlloc(16),old=h.GuestAlloc(16),after=h.GuestAlloc(16);
    h.MemoryWrite32(mask,1u<<(SIGUSR1-1));h.MemoryWrite32(old+4,0xabcdef12);
    CHECK(Call(h,"pthread_sigmask",{SIG_BLOCK,mask,old})==0);
    CHECK(h.MemoryRead32(old+4)==0xabcdef12);
    CHECK(Call(h,"pthread_sigmask",{SIG_SETMASK,0,after})==0);
    CHECK(h.MemoryRead32(after)&(1u<<(SIGUSR1-1)));
    CHECK(Call(h,"pthread_sigmask",{SIG_SETMASK,old,0})==0);
    uint32_t previous=Call(h,"bsd_signal",{SIGUSR2,1});CHECK(previous<=1);
    CHECK(Call(h,"bsd_signal",{SIGUSR2,previous})==1);

    FILE* stream=tmpfile();CHECK(stream);CHECK(fwrite("abc\n",1,4,stream)==4);rewind(stream);
    uint32_t token=AdoptHostFile(h,stream);CHECK(token);
    uint32_t wide=h.GuestAlloc(28);h.MemoryWrite32(wide+20,0x12345678);
    CHECK(Call(h,"fgetws",{wide,5,token})==wide);
    CHECK(h.MemoryRead32(wide)=='a'&&h.MemoryRead32(wide+4)=='b');
    CHECK(h.MemoryRead32(wide+8)=='c'&&h.MemoryRead32(wide+12)=='\n');
    CHECK(h.MemoryRead32(wide+16)==0&&h.MemoryRead32(wide+20)==0x12345678);
    CHECK(Call(h,"fclose",{token})==0);

    // One real ARM call chain saves and restores its own JIT context. A host
    // longjmp or a nested JIT would target the wrong execution context.
    uint32_t env=h.GuestAlloc(260),code=h.GuestAlloc(44);
    const uint32_t instructions[]={0xe92d4070,0xe1a04000,0xe1a05001,0xe1a06002,
        0xe12fff35,0xe3500000,0x1a000002,0xe1a00004,0xe3a01007,0xe12fff36,0xe8bd8070};
    memcpy(h.GetGuestMemoryBase()+code,instructions,sizeof(instructions));h.AddExecutableRange(code,44);
    h.MemoryWrite32(env+256,0xdeadbeef);
    uint32_t set=h.GetThunkManager().FindRegisteredSymbol("setjmp");
    uint32_t jump=h.GetThunkManager().FindRegisteredSymbol("longjmp");CHECK(set&&jump);
    CHECK(h.RunFunction(code,{env,set,jump})==7);CHECK(!h.HasFailed());
    h.MemoryWrite32(code+32,0xe3a01000);h.InvalidateGuestCode(code,44);
    CHECK(h.RunFunction(code,{env,set,jump})==1);CHECK(!h.HasFailed());
    CHECK(h.MemoryRead32(env+256)==0xdeadbeef);
    printf("PASS Grim imports: softfp isnanf, signal mask32, FILE ownership/wchar32, real ARM setjmp/longjmp\n");
}
}
int main() {
    setvbuf(stdout,nullptr,_IONBF,0);
    DynarmicHost host;CHECK(host.Initialize());
    AbiAndDispatch(host);ElfFixtures(host);StringsAndStdio(host);ScansetParsing(host);CallbacksAndThreads(host);SemaphorePostRetirement(host);PosixComplements(host);Zlib(host);Graphics(host);GrimBoundaryImports(host);
    printf("PASS all %u checks; %zu registered symbols; page size %ld\n",checks,host.GetThunkManager().GetThunkSymbolTable().size(),sysconf(_SC_PAGESIZE));
    host.ReleaseCurrentThread();return 0;
}
