# Timer retirement regression

The regression exercises the original ARM32 timer code through the bridge and
checks callback retirement, object lifetime, and mutex serialization.

Build the native regression targets first, then the specialized runner:

```powershell
./arm64_bridge/build_arm64.ps1 -AllowNetwork -BuildTests
./arm64_bridge/tests/build_timer_regression.ps1
```

For offline dependencies, pass `-BoostSourceDirectory` and
`-DynarmicSourceDirectory` to both scripts. Supply your own original guest library
as the runner's only argument. The runner is built for Android AArch64, requires
an explicitly selected test device, and must be copied to that device manually.
Do not replace or modify the guest library; its instruction preimages are checked.
Generated binaries and device logs are local outputs and are not tracked.

The fixture compares the unsafe original sequence with the patched sequence;
it does not establish that every gameplay crash has the same cause.
