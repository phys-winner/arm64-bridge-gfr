// Common math/string/wchar coverage from the Unity, Horn and Telltale bridges.
// Keep all guest pointers in the arena and all scalar returns in the base PCS.
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <cstdlib>
#include <climits>

namespace {
using Jit = Dynarmic::A32::Jit;
using Host = DynarmicHost;
char* Chars(Host& h, uint32_t p) {
    const char* s = GuestCString(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),p);
    if (!s) throw std::out_of_range("Invalid guest string");
    return const_cast<char*>(s);
}
template<class T> T* Array(Host& h, uint32_t p, size_t count) {
    if (p % alignof(T) || count > SIZE_MAX / sizeof(T)) throw std::out_of_range("Guest array overflow");
    auto* value = static_cast<T*>(GuestSpan(h.GetGuestMemoryBase(),h.GetGuestMemorySize(),p,count*sizeof(T)));
    if (!value) throw std::out_of_range("Invalid guest array");
    return value;
}
wchar_t* Wide(Host& h, uint32_t p) {
    static_assert(sizeof(wchar_t)==4);
    auto* s = Array<wchar_t>(h,p,1);
    const size_t limit = std::min<size_t>((h.GetGuestMemorySize()-p)/4,1024*1024);
    if (wcsnlen(s,limit)==limit) throw std::out_of_range("Unterminated guest wide string");
    return s;
}
void Return64(Jit& j, uint64_t value) { j.Regs()[0]=value; j.Regs()[1]=value>>32; }
mbstate_t ReadMbState(Host& h,uint32_t address) {
    mbstate_t state{};
    if(address)memcpy(state.__seq,Array<uint8_t>(h,address,4),4);
    return state;
}
void WriteMbState(Host& h,uint32_t address,const mbstate_t& state) {
    if(address)memcpy(Array<uint8_t>(h,address,4),state.__seq,4);
}
constexpr const char* kWideClasses[]={"", "alnum", "alpha", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "xdigit"};
}

void ThunkManager::RegisterLibcExtraThunks() {
    // Horn's legacy Bionic atomics return the value before the operation.
    RegisterThunk("__atomic_inc",[](Jit& j,Host& h) { j.Regs()[0]=__atomic_fetch_add(Array<uint32_t>(h,j.Regs()[0],1),1u,__ATOMIC_SEQ_CST); });
    RegisterThunk("__atomic_dec",[](Jit& j,Host& h) { j.Regs()[0]=__atomic_fetch_sub(Array<uint32_t>(h,j.Regs()[0],1),1u,__ATOMIC_SEQ_CST); });
    RegisterThunk("__atomic_swap",[](Jit& j,Host& h) { j.Regs()[0]=__atomic_exchange_n(Array<uint32_t>(h,j.Regs()[1],1),j.Regs()[0],__ATOMIC_SEQ_CST); });
    RegisterThunk("__atomic_cmpxchg",[](Jit& j,Host& h) { uint32_t expected=j.Regs()[0];j.Regs()[0]=!__atomic_compare_exchange_n(Array<uint32_t>(h,j.Regs()[2],1),&expected,j.Regs()[1],false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST); });
    auto unary = [this](const char* name, double(*fn)(double)) {
        RegisterThunk(name,[fn](Jit& j,Host&) { WriteDF(j,0,fn(ReadDF(j,0))); });
    };
    unary("sinh",std::sinh); unary("cosh",std::cosh); unary("tanh",std::tanh);
    unary("atan",std::atan); unary("exp2",std::exp2); unary("trunc",std::trunc);
    unary("round",std::round); unary("fabs",std::fabs); unary("log2",std::log2);
    auto unaryf = [this](const char* name, float(*fn)(float)) {
        RegisterThunk(name,[fn](Jit& j,Host&) { WriteSF(j,0,fn(ReadSF(j,0))); });
    };
    unaryf("exp2f",std::exp2); unaryf("truncf",std::trunc); unaryf("roundf",std::round);
    unaryf("rintf",std::rint); unaryf("fabsf",std::fabs); unaryf("log2f",std::log2);
    RegisterThunk("remainder",[](Jit& j,Host&) { WriteDF(j,0,std::remainder(ReadDF(j,0),ReadDF(j,1))); });
    RegisterThunk("ldexpf",[](Jit& j,Host&) { WriteSF(j,0,std::ldexp(ReadSF(j,0),static_cast<int>(j.Regs()[1]))); });
    RegisterThunk("scalbn",[](Jit& j,Host&) { WriteDF(j,0,std::scalbn(ReadDF(j,0),static_cast<int>(j.Regs()[2]))); });
    RegisterThunk("frexpf",[](Jit& j,Host& h) { WriteSF(j,0,std::frexp(ReadSF(j,0),Array<int>(h,j.Regs()[1],1))); });
    RegisterThunk("modf",[](Jit& j,Host& h) { WriteDF(j,0,std::modf(ReadDF(j,0),Array<double>(h,j.Regs()[2],1))); });
    RegisterThunk("modff",[](Jit& j,Host& h) { WriteSF(j,0,std::modf(ReadSF(j,0),Array<float>(h,j.Regs()[1],1))); });
    RegisterThunk("isnan",[](Jit& j,Host&) { j.Regs()[0]=std::isnan(ReadDF(j,0)); });
    RegisterThunk("isnanf",[](Jit& j,Host&) { j.Regs()[0]=std::isnan(ReadSF(j,0)); });
    RegisterThunk("__isinf",[](Jit& j,Host&) { j.Regs()[0]=std::isinf(ReadDF(j,0)); });
    RegisterThunk("__isinff",[](Jit& j,Host&) { j.Regs()[0]=std::isinf(ReadSF(j,0)); });
    RegisterThunk("__isfinitef",[](Jit& j,Host&) { j.Regs()[0]=std::isfinite(ReadSF(j,0)); });
    RegisterThunk("__fpclassifyf",[](Jit& j,Host&) { j.Regs()[0]=std::fpclassify(ReadSF(j,0)); });
    auto ctype = [this](const char* name, int(*fn)(int)) {
        RegisterThunk(name,[fn](Jit& j,Host&) { int c=static_cast<int>(j.Regs()[0]); j.Regs()[0]=(c>=0&&c<=UCHAR_MAX)?fn(c):0; });
    };
    ctype("isalnum",isalnum); ctype("isalpha",isalpha); ctype("iscntrl",iscntrl);
    ctype("isdigit",isdigit); ctype("isgraph",isgraph); ctype("islower",islower);
    ctype("isprint",isprint); ctype("ispunct",ispunct); ctype("isupper",isupper); ctype("isxdigit",isxdigit);
    RegisterThunk("tolower",[](Jit& j,Host&) { int c=static_cast<int>(j.Regs()[0]);j.Regs()[0]=c>=0&&c<=UCHAR_MAX?tolower(c):c; });
    RegisterThunk("strpbrk",[](Jit& j,Host& h) { j.Regs()[0]=HostToGuest(h.GetGuestMemoryBase(),strpbrk(Chars(h,j.Regs()[0]),Chars(h,j.Regs()[1]))); });
    RegisterThunk("strcasestr",[](Jit& j,Host& h) { j.Regs()[0]=HostToGuest(h.GetGuestMemoryBase(),strcasestr(Chars(h,j.Regs()[0]),Chars(h,j.Regs()[1]))); });
    RegisterThunk("strspn",[](Jit& j,Host& h) { j.Regs()[0]=strspn(Chars(h,j.Regs()[0]),Chars(h,j.Regs()[1])); });
    RegisterThunk("strcspn",[](Jit& j,Host& h) { j.Regs()[0]=strcspn(Chars(h,j.Regs()[0]),Chars(h,j.Regs()[1])); });
    RegisterThunk("strsep",[](Jit& j,Host& h) {
        const uint32_t cell=j.Regs()[0];auto* output=Array<uint32_t>(h,cell,1);
        char* next=*output?Chars(h,*output):nullptr;
        char* result=strsep(&next,Chars(h,j.Regs()[1]));
        *output=HostToGuest(h.GetGuestMemoryBase(),next);j.Regs()[0]=HostToGuest(h.GetGuestMemoryBase(),result);
    });
    RegisterThunk("strlcpy",[](Jit& j,Host& h) { j.Regs()[0]=strlcpy(Array<char>(h,j.Regs()[0],j.Regs()[2]),Chars(h,j.Regs()[1]),j.Regs()[2]); });
    RegisterThunk("strcoll",[](Jit& j,Host& h) { j.Regs()[0]=strcoll(Chars(h,j.Regs()[0]),Chars(h,j.Regs()[1])); });
    RegisterThunk("strxfrm",[](Jit& j,Host& h) { j.Regs()[0]=strxfrm(Array<char>(h,j.Regs()[0],j.Regs()[2]),Chars(h,j.Regs()[1]),j.Regs()[2]); });
    RegisterThunk("atol",[](Jit& j,Host& h) { j.Regs()[0]=static_cast<int32_t>(strtoll(Chars(h,j.Regs()[0]),nullptr,10)); });
    auto integer64=[](Jit& j,Host& h,bool sign) {
        char* end=nullptr;const uint32_t out=j.Regs()[1];errno=0;
        const char* s=Chars(h,j.Regs()[0]);const int radix=j.Regs()[2];
        const uint64_t result=sign?static_cast<uint64_t>(strtoll(s,&end,radix)):strtoull(s,&end,radix);
        if(out)*Array<uint32_t>(h,out,1)=HostToGuest(h.GetGuestMemoryBase(),end);
        if(errno)h.MemoryWrite32(h.GuestErrnoAddress(),errno);Return64(j,result);
    };
    RegisterThunk("strtoll",[integer64](Jit& j,Host& h) { integer64(j,h,true); });
    RegisterThunk("strtoull",[integer64](Jit& j,Host& h) { integer64(j,h,false); });
    RegisterThunk("strtoimax",[integer64](Jit& j,Host& h) { integer64(j,h,true); });
    RegisterThunk("strtoumax",[integer64](Jit& j,Host& h) { integer64(j,h,false); });
    RegisterThunk("wcslen",[](Jit& j,Host& h) { j.Regs()[0]=wcslen(Wide(h,j.Regs()[0])); });
    RegisterThunk("wcscpy",[](Jit& j,Host& h) { auto* s=Wide(h,j.Regs()[1]);wcscpy(Array<wchar_t>(h,j.Regs()[0],wcslen(s)+1),s); });
    RegisterThunk("wcscoll",[](Jit& j,Host& h) { j.Regs()[0]=wcscoll(Wide(h,j.Regs()[0]),Wide(h,j.Regs()[1])); });
    RegisterThunk("wmemcpy",[](Jit& j,Host& h) { wmemcpy(Array<wchar_t>(h,j.Regs()[0],j.Regs()[2]),Array<wchar_t>(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2]); });
    RegisterThunk("wmemmove",[](Jit& j,Host& h) { wmemmove(Array<wchar_t>(h,j.Regs()[0],j.Regs()[2]),Array<wchar_t>(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2]); });
    RegisterThunk("wmemset",[](Jit& j,Host& h) { wmemset(Array<wchar_t>(h,j.Regs()[0],j.Regs()[2]),j.Regs()[1],j.Regs()[2]); });
    RegisterThunk("wmemcmp",[](Jit& j,Host& h) { j.Regs()[0]=wmemcmp(Array<wchar_t>(h,j.Regs()[0],j.Regs()[2]),Array<wchar_t>(h,j.Regs()[1],j.Regs()[2]),j.Regs()[2]); });
    RegisterThunk("wmemchr",[](Jit& j,Host& h) { j.Regs()[0]=HostToGuest(h.GetGuestMemoryBase(),wmemchr(Array<wchar_t>(h,j.Regs()[0],j.Regs()[2]),j.Regs()[1],j.Regs()[2])); });
    RegisterThunk("wcstombs",[](Jit& j,Host& h) { j.Regs()[0]=wcstombs(j.Regs()[0]?Array<char>(h,j.Regs()[0],j.Regs()[2]):nullptr,Wide(h,j.Regs()[1]),j.Regs()[2]); });
    RegisterThunk("wcrtomb",[](Jit& j,Host& h) {
        const uint32_t p=j.Regs()[2];mbstate_t state=ReadMbState(h,p);
        j.Regs()[0]=wcrtomb(j.Regs()[0]?Array<char>(h,j.Regs()[0],MB_LEN_MAX):nullptr,j.Regs()[1],p?&state:nullptr);
        WriteMbState(h,p,state);if(j.Regs()[0]==UINT32_MAX)h.MemoryWrite32(h.GuestErrnoAddress(),errno);
    });
    RegisterThunk("mbrtowc",[](Jit& j,Host& h) {
        const uint32_t p=j.Regs()[3];mbstate_t state=ReadMbState(h,p);
        j.Regs()[0]=mbrtowc(j.Regs()[0]?Array<wchar_t>(h,j.Regs()[0],1):nullptr,j.Regs()[1]?Array<char>(h,j.Regs()[1],j.Regs()[2]):nullptr,j.Regs()[2],p?&state:nullptr);
        WriteMbState(h,p,state);if(j.Regs()[0]==UINT32_MAX)h.MemoryWrite32(h.GuestErrnoAddress(),errno);
    });
    RegisterThunk("btowc",[](Jit& j,Host&) { j.Regs()[0]=btowc(j.Regs()[0]); });
    RegisterThunk("wctob",[](Jit& j,Host&) { j.Regs()[0]=wctob(j.Regs()[0]); });
    RegisterThunk("towlower",[](Jit& j,Host&) { j.Regs()[0]=towlower(j.Regs()[0]); });
    RegisterThunk("towupper",[](Jit& j,Host&) { j.Regs()[0]=towupper(j.Regs()[0]); });
    // Translate descriptors explicitly; wctype_t itself grows from 32 to 64 bits.
    RegisterThunk("wctype",[](Jit& j,Host& h) { const char* name=Chars(h,j.Regs()[0]);j.Regs()[0]=0;for(uint32_t i=1;i<std::size(kWideClasses);++i)if(!strcmp(name,kWideClasses[i])) { j.Regs()[0]=i;break; } });
    RegisterThunk("iswctype",[](Jit& j,Host&) { uint32_t kind=j.Regs()[1];j.Regs()[0]=kind&&kind<std::size(kWideClasses)?iswctype(j.Regs()[0],wctype(kWideClasses[kind])):0; });
    auto wctype_fn = [this](const char* name,int(*fn)(wint_t)) { RegisterThunk(name,[fn](Jit& j,Host&) { j.Regs()[0]=fn(j.Regs()[0]); }); };
    wctype_fn("iswalnum",iswalnum); wctype_fn("iswalpha",iswalpha); wctype_fn("iswdigit",iswdigit);
    wctype_fn("iswspace",iswspace); wctype_fn("iswupper",iswupper); wctype_fn("iswxdigit",iswxdigit);
}
