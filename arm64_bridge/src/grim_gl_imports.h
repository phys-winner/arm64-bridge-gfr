#pragma once

class ThunkManager;

// Register before guest relocation; engine-specific GOT hooks are installed later.
void RegisterGrimGlImports(ThunkManager& manager);
