#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "jni_fake_env.h"
#include <jni.h>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

std::string g_saved_apk_path, g_saved_files_dir;
static JavaVM* test_vm;
JavaVM* GetHostJavaVM() { return test_vm; }
namespace {
unsigned checks;
#define CHECK(e) do { ++checks; if(!(e)) { fprintf(stderr,"JNI FAIL line %d: %s\n",__LINE__,#e);std::abort(); } } while(0)
uint32_t Text(DynarmicHost& h,const char* text) {
    uint32_t p=h.GuestAlloc(strlen(text)+1);CHECK(p);memcpy(h.GetGuestMemoryBase()+p,text,strlen(text)+1);return p;
}
uint32_t Call(DynarmicHost& h,size_t slot,std::vector<uint32_t> args) {
    args.insert(args.begin(),FakeJniEnv::Instance().EnvTableGuestAddr());
    uint32_t value=h.RunFunction(h.GetThunkManager().FindRegisteredSymbol("jni_env_"+std::to_string(slot*4)),args);
    CHECK(!h.HasFailed()&&!FakeJniEnv::Instance().HasFailed());return value;
}
#define SLOT(n) (offsetof(JNINativeInterface,n)/sizeof(void*))
}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*) { test_vm=vm;return JNI_VERSION_1_6; }
extern "C" JNIEXPORT void JNICALL Java_BridgeJniRegression_run(JNIEnv* env,jclass cls) {
    DynarmicHost host;CHECK(host.Initialize());
    auto& jni=FakeJniEnv::Instance();jni.SetJavaVM(test_vm);
    CHECK(jni.CacheClassLoader(env,cls));CHECK(jni.Init(host));CHECK(jni.RunSelfChecks());CHECK(jni.BeginNativeCall(env));
    const uint32_t type=jni.AddObjectRef(cls);
    auto method=[&](const char* name,const char* sig) { uint32_t a=Text(host,name),b=Text(host,sig);uint32_t id=Call(host,SLOT(GetStaticMethodID),{type,a,b});host.GuestFree(a);host.GuestFree(b);CHECK(id);return id; };
    CHECK(Call(host,SLOT(CallStaticByteMethod),{type,method("byteValue","()B")})==uint32_t(-7));
    CHECK(Call(host,SLOT(CallStaticCharMethod),{type,method("charValue","()C")})==0xf123);
    CHECK(Call(host,SLOT(CallStaticShortMethod),{type,method("shortValue","()S")})==uint32_t(-1234));
    const uint32_t float_method=method("floatValue","(F)F");
    const uint64_t promoted=std::bit_cast<uint64_t>(1.25);
    CHECK(Call(host,SLOT(CallStaticFloatMethod),{type,float_method,0,uint32_t(promoted),uint32_t(promoted>>32)})==std::bit_cast<uint32_t>(2.5f));
    uint32_t values=host.GuestAlloc(32,8);host.MemoryWrite32(values,std::bit_cast<uint32_t>(-2.5f));
    CHECK(Call(host,SLOT(CallStaticFloatMethodA),{type,float_method,values})==std::bit_cast<uint32_t>(-5.0f));
    host.MemoryWrite64(values,promoted);
    CHECK(Call(host,SLOT(CallStaticFloatMethodV),{type,float_method,values})==std::bit_cast<uint32_t>(2.5f));
    CHECK(Call(host,SLOT(CallStaticLongMethod),{type,method("mixed","(IFJD)J"),7,0,0x3ff40000,0x55667788,0x11223344,0,0x400c0000})==0x55667788);
    CHECK(host.GetResultHigh()==0x11223344);
    uint32_t utf=Text(host,"hello JNI"),string=Call(host,SLOT(NewStringUTF),{utf});CHECK(string);
    CHECK(Call(host,SLOT(GetStringLength),{string})==9);
    uint32_t copied=Call(host,SLOT(GetStringUTFChars),{string,0});CHECK(copied);
    CHECK(!strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase()+copied),"hello JNI"));
    Call(host,SLOT(ReleaseStringUTFChars),{string,copied});
    uint32_t global=Call(host,SLOT(NewGlobalRef),{string}),weak=Call(host,SLOT(NewWeakGlobalRef),{string});CHECK(global&&weak);
    CHECK(Call(host,SLOT(IsSameObject),{global,weak})==1);
    CHECK(Call(host,SLOT(GetObjectRefType),{global})==JNIGlobalRefType);
    // Recycle more than the old LRU capacity; a still-live global must survive.
    for(unsigned i=0;i<9000;++i) {
        uint32_t local=Call(host,SLOT(NewLocalRef),{global});CHECK(local);
        Call(host,SLOT(DeleteLocalRef),{local});
    }
    CHECK(Call(host,SLOT(GetStringLength),{global})==9);
    CHECK(Call(host,SLOT(PushLocalFrame),{8})==0);
    uint32_t inner=Call(host,SLOT(NewLocalRef),{global});CHECK(inner);
    uint32_t survivor=Call(host,SLOT(PopLocalFrame),{inner});CHECK(survivor);
    CHECK(Call(host,SLOT(IsSameObject),{survivor,global})==1);
    uint32_t array=Call(host,SLOT(NewIntArray),{4});CHECK(array);host.MemoryWrite32(values,42);
    Call(host,SLOT(SetIntArrayRegion),{array,2,1,values});host.MemoryWrite32(values,0);
    Call(host,SLOT(GetIntArrayRegion),{array,2,1,values});CHECK(host.MemoryRead32(values)==42);
    const uint32_t main_env=jni.EnvTableGuestAddr();uint32_t worker_env=0;
    std::thread worker([&] {
        JNIEnv* current=jni.GetEnv();CHECK(current);CHECK(jni.BeginNativeCall(current));worker_env=jni.EnvTableGuestAddr();
        uint32_t class_name=Text(host,"BridgeJniRegression");
        CHECK(Call(host,SLOT(FindClass),{class_name}));host.GuestFree(class_name);
        CHECK(Call(host,SLOT(GetStringLength),{global})==9);
        jni.EndNativeCall();jni.ReleaseCurrentThread();host.ReleaseCurrentThread();
    });worker.join();CHECK(worker_env&&worker_env!=main_env);
    Call(host,SLOT(DeleteWeakGlobalRef),{weak});Call(host,SLOT(DeleteGlobalRef),{global});
    jni.EndNativeCall();jni.ReleaseCurrentThread();host.ReleaseCurrentThread();
    CHECK(!env->ExceptionCheck());printf("PASS %u JNI checks: typed returns, A/V/varargs, references, arrays, worker class loader\n",checks);
}
