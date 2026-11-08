[CmdletBinding()]
param(
    [string]$SdkRoot = "$env:LOCALAPPDATA/Android/Sdk",
    [string]$BoostSourceDirectory,
    [string]$DynarmicSourceDirectory,
    [string]$NdkVersion = '27.2.12479018'
)
$ErrorActionPreference = 'Stop'
$Project = (Resolve-Path -LiteralPath "$PSScriptRoot/../..").Path
$Bridge = Join-Path $Project 'arm64_bridge'
$Toolchain = Join-Path $SdkRoot "ndk/$NdkVersion/toolchains/llvm/prebuilt/windows-x86_64"
$Compiler = Join-Path $Toolchain 'bin/clang++.exe'
$Build = Join-Path $Bridge 'build_arm64'
if (-not $BoostSourceDirectory) { $BoostSourceDirectory = Join-Path $Build '_deps/boost-src' }
if (-not $DynarmicSourceDirectory) { $DynarmicSourceDirectory = Join-Path $Build '_deps/dynarmic-src' }
$Object = Join-Path $PSScriptRoot 'timer_retirement_regression.o'
$Binary = Join-Path $PSScriptRoot 'timer_retirement_regression'
$Compile = @(
    '--target=aarch64-none-linux-android26', "--sysroot=$Toolchain/sysroot",
    '-std=c++20', '-O2', '-g', '-fPIE', '-DANDROID', '-DARM32_BRIDGE_ENABLE_LOGGING=0',
    '-Wformat', '-Werror=format-security', "-I$Bridge/src", "-I$BoostSourceDirectory",
    "-I$DynarmicSourceDirectory/include", "-I$DynarmicSourceDirectory/src",
    '-c', "$PSScriptRoot/timer_retirement_regression.cpp", '-o', $Object
)
& $Compiler @Compile
if ($LASTEXITCODE -ne 0) { throw 'Timer regression compile failed' }
$FixtureObject = Join-Path $PSScriptRoot 'timer_mutex_fixture.o'
$FixtureCompile = @($Compile)
$FixtureCompile[$FixtureCompile.IndexOf("$PSScriptRoot/timer_retirement_regression.cpp")] = "$PSScriptRoot/timer_mutex_fixture.cpp"
$FixtureCompile[$FixtureCompile.IndexOf($Object)] = $FixtureObject
& $Compiler @FixtureCompile
if ($LASTEXITCODE -ne 0) { throw 'Timer mutex fixture compile failed' }
$CoreNames = @(
    'elf_loader', 'dynarmic_host', 'guest_cp15', 'thunk_manager', 'thunks_gl',
    'thunks_gl_gles2_core', 'thunks_libc', 'thunks_libc_extra',
    'thunks_zlib', 'thunks_android', 'grim_gl_imports', 'jni_fake_env'
)
$Objects = foreach ($Name in $CoreNames) {
    $Path = Join-Path $Build "CMakeFiles/bridge_regression.dir/src/$Name.cpp.o"
    if (-not (Test-Path -LiteralPath $Path)) { throw "Build existing bridge tests first; absent: $Path" }
    $Path
}
$Runtime = Join-Path $Build 'CMakeFiles/bridge_regression.dir/tests/standalone_runtime.cpp.o'
if (-not (Test-Path -LiteralPath $Runtime)) { throw "Build existing bridge tests first; absent: $Runtime" }
$Link = @(
    '--target=aarch64-none-linux-android26', "--sysroot=$Toolchain/sysroot",
    '-static-libstdc++', '-fPIE', '-pie', '-Wl,--gc-sections',
    '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384',
    '-Wl,--wrap=pthread_mutex_lock', $Object, $FixtureObject
) + @($Runtime) + @($Objects) + @(
    "$Build/_deps/dynarmic-build/src/dynarmic/libdynarmic.a",
    "$Build/_deps/dynarmic-build/externals/mcl/src/libmcl.a",
    "$Build/_deps/dynarmic-build/externals/fmt/libfmt.a",
    '-lGLESv3', '-lGLESv1_CM', '-lEGL', '-llog', '-landroid', '-ldl', '-lm', '-lz', '-latomic',
    '-o', $Binary
)
& $Compiler @Link
if ($LASTEXITCODE -ne 0) { throw 'Timer regression link failed' }
Get-FileHash -LiteralPath $Binary -Algorithm SHA256
Write-Output "Standalone runner: $Binary"
Write-Output 'Run on the selected device with one argument: path to the pinned original guest libGrimFandango.so.'
