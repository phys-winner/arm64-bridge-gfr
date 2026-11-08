#include "guest_cp15.h"
#include "dynarmic_host.h"
#include <atomic>

GuestCp15::Callback GuestCp15::Unsupported() {
    return Callback{[](void* opaque,uint32_t,uint32_t)->uint64_t {
        static_cast<DynarmicHost*>(opaque)->Fail("Unsupported guest CP15 operation");return 0;
    }, &host_};
}
std::optional<GuestCp15::Callback> GuestCp15::CompileInternalOperation(bool,unsigned,Reg,Reg,Reg,unsigned) { return Unsupported(); }
GuestCp15::CallbackOrAccessOneWord GuestCp15::CompileGetOneWord(bool two,unsigned op,Reg n,Reg m,unsigned op2) {
    if(!two && !op && n==Reg::C13 && m==Reg::C0 && op2==3)
        return Callback{[](void* p,uint32_t,uint32_t)->uint64_t { return static_cast<DynarmicHost*>(p)->GuestTlsAddress(); },&host_};
    if(!two && !op && n==Reg::C13 && m==Reg::C0 && op2==2)
        return Callback{[](void* p,uint32_t,uint32_t)->uint64_t { return static_cast<DynarmicHost*>(p)->GuestTlsWritable(); },&host_};
    return Unsupported();
}
GuestCp15::CallbackOrAccessOneWord GuestCp15::CompileSendOneWord(bool two,unsigned op,Reg n,Reg m,unsigned op2) {
    if(!two && !op && n==Reg::C13 && m==Reg::C0 && op2==2)
        return Callback{[](void* p,uint32_t value,uint32_t)->uint64_t { static_cast<DynarmicHost*>(p)->SetGuestTlsWritable(value);return 0; },&host_};
    // ARMv6 encodings of DMB / DSB / ISB. Cache invalidation is handled by the
    // ARM cacheflush syscall, which supplies an explicit guest address range.
    if(!two && !op && n==Reg::C7 && ((m==Reg::C10&&(op2==4||op2==5)) || (m==Reg::C5&&op2==4)))
        return Callback{[](void*,uint32_t,uint32_t)->uint64_t { std::atomic_thread_fence(std::memory_order_seq_cst);return 0; },std::nullopt};
    return Unsupported();
}
GuestCp15::CallbackOrAccessTwoWords GuestCp15::CompileSendTwoWords(bool,unsigned,Reg) { return Unsupported(); }
GuestCp15::CallbackOrAccessTwoWords GuestCp15::CompileGetTwoWords(bool,unsigned,Reg) { return Unsupported(); }
std::optional<GuestCp15::Callback> GuestCp15::CompileLoadWords(bool,bool,Reg,std::optional<uint8_t>) { return Unsupported(); }
std::optional<GuestCp15::Callback> GuestCp15::CompileStoreWords(bool,bool,Reg,std::optional<uint8_t>) { return Unsupported(); }
