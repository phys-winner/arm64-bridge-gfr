// Keep save serialization native; run its measured zlib bottleneck in ARM64.
#include "save_compression_preimages.h"
uint32_t save_host_compress;
bool save_compression_validate(std::string& error) {
    if (!binding("compress", 0x1ac7b8, error)
        || !preimage(0x1ac7b8, save_compress_body, sizeof(save_compress_body), "save compress", error)
        || !preimage(0x73b6c, save_compress_save_call, sizeof(save_compress_save_call), "save compress call", error)) return false;
    save_host_compress = engine->GetThunkManager().FindRegisteredSymbol("compress2");
    if (word(base + 0x2a3bc8) != originals.at("compress") || !save_host_compress
        || save_host_compress == originals.at("compress")) {
        error = "Grim save compression binding mismatch"; return false;
    }
    return true;
}
void save_compression_hook(Jit& jit, Host&) {
    const std::vector<uint32_t> args{jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], 1u};
    const uint32_t capacity = word(args[1]);
    // Level1 shortens the game-thread pause while retaining the zlib save format.
    uint32_t result = call(save_host_compress, args);
    if (result == uint32_t(-5)) {
        // Near the original fixed save capacity, retain level6's compression ratio.
        put(args[1], capacity);
        result = call("compress", {args[0], args[1], args[2], args[3]});
    }
    // The original zlib1.2.8 wrapper publishes the output length only on success.
    if (result) put(args[1], capacity);
    jit.Regs()[0] = result;
}
