# Save compression regression

The runner compares the native zlib fast path against the pinned guest decoder,
including bounded output, zero-length input, fallback and invalid-stream cases.
The save format and the original fallback compressor remain unchanged.

```powershell
./arm64_bridge/build_arm64.ps1 -AllowNetwork -BuildTests
./arm64_bridge/tests/build_save_compression_regression.ps1
```

Place your original guest library under
`arm64_bridge/app/assets/guest_libs/libGrimFandango.so` before building this runner.
The build script verifies its SHA-256. For offline dependencies, pass
`-BoostSourceDirectory` and `-DynarmicSourceDirectory` to both scripts.
Run the Android AArch64 executable on an explicitly selected test device with
the path to that same original guest library as its only argument.
No commercial game library or saved game is distributed here.
