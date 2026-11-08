#pragma once
#include <dynarmic/interface/A32/coprocessor.h>
class DynarmicHost;

// User-space CP15 subset observed in the Colin McRae / Deus Ex / Warband
// bridges. Each callback reads the calling thread, never the compiler thread.
class GuestCp15 final : public Dynarmic::A32::Coprocessor {
    DynarmicHost& host_;
    using Reg=Dynarmic::A32::CoprocReg;
    Callback Unsupported();
public:
    explicit GuestCp15(DynarmicHost& host):host_(host) {}
    std::optional<Callback> CompileInternalOperation(bool,unsigned,Reg,Reg,Reg,unsigned) override;
    CallbackOrAccessOneWord CompileSendOneWord(bool,unsigned,Reg,Reg,unsigned) override;
    CallbackOrAccessTwoWords CompileSendTwoWords(bool,unsigned,Reg) override;
    CallbackOrAccessOneWord CompileGetOneWord(bool,unsigned,Reg,Reg,unsigned) override;
    CallbackOrAccessTwoWords CompileGetTwoWords(bool,unsigned,Reg) override;
    std::optional<Callback> CompileLoadWords(bool,bool,Reg,std::optional<uint8_t>) override;
    std::optional<Callback> CompileStoreWords(bool,bool,Reg,std::optional<uint8_t>) override;
};
