# ARM64 Bridge for Grim Fandango Remastered

An experimental Android ARM64 compatibility bridge for the original ARM32 version
of **Grim Fandango Remastered**. It runs the unmodified 32-bit engine through
[Dynarmic](https://github.com/azahar-emu/dynarmic) inside a native 64-bit Android
process, with host-side implementations of the services the engine needs.

This repository contains bridge source code and build, packaging, cache-analysis,
and regression scripts. Obtain the game and its data separately. No APK, OBB,
commercial game library, fonts, audio, textures, saves, or third-party dependency
sources are distributed here. This is an unofficial project, unaffiliated with
Double Fine Productions or the game's other rights holders.

## How it works

- Loads the original ARM32 ELF engine into guest memory and executes ARM
  instructions using Dynarmic's A32 frontend.
- Provides JNI, Android, POSIX, libc, zlib, and OpenGL ES bridge functions.
- Reads complete game cache containers from data APKs or an external OBB pair,
  without extracting the entire cache on first launch.
- Implements game-specific fixes for touch input, Android Back handling, shutdown,
  timer retirement, language restoration, and save compression.
- Adds frame-rate choices and optional diagnostic/menu features through the Java
  helpers and game-specific hooks.
- Produces a single AArch64 `libGrimFandango.so` with 16 KiB ELF segment alignment.

The hooks and cache index target the original Android **1.5.19** inputs. Runtime
checks validate expected guest instructions before applying the relevant hooks.
A different engine binary or cache layout requires analysis and updated checks;
this is not a general-purpose Android emulator.

## Requirements

The supplied build scripts target Windows with PowerShell 7. Native code uses
C++20. Install the following tools outside this repository:

| Tool or dependency | Version used by the scripts |
| --- | --- |
| Android NDK | 27.2.12479018 (r27c) |
| Android SDK CMake / Ninja | 3.22.1 |
| Native build platform | android-26; arm64-v8a; static C++ runtime |
| Java development kit | JDK 17 or newer; Java 24 used during development |
| Java compile platform | Android SDK platform 36 |
| D8 / APK build tools | 37.0.0; ART runner defaults to 36.1.0 |
| Python | 3.11 or newer; standard library only |
| Git | Required by CMake to fetch Dynarmic and its submodules |
| Boost headers | 1.83.0; archive checked by SHA-256 |
| Dynarmic | e77b1ba0b7da7cbe93021b01a663acfe7c4dd516 |

Set `ANDROID_SDK_ROOT`, put `java`, `javac`, and `pwsh` on `PATH`, and set
`JAVA_HOME` for the ART runner. The native script also accepts `-SdkRoot`,
`-NdkVersion`, and `-CmakeVersion`.

The prepared application targets Android 7.0 or newer and OpenGL ES 3.0.
The native library defaults to API 26, so Android 7.x support requires rebuilding
with `-AndroidPlatform android-24` and separate device validation. Compatibility
with every Android release, GPU, or 64-bit device is not established.

## Build the bridge

From the repository root:

```powershell
./arm64_bridge/build_arm64.ps1 -AllowNetwork
```

CMake downloads the pinned Boost archive and recursively checks out the pinned
Dynarmic revision under the ignored build directory. Dynarmic manages its own
pinned fmt, mcl, oaknut, robin-map, and other submodules. Nothing is vendored into
this repository. The output is `arm64_bridge/dist/libGrimFandango.so`.

For an offline build, provide an extracted Boost tree and a complete recursive
Dynarmic checkout in directories of your choice:

```powershell
./arm64_bridge/build_arm64.ps1 -BoostSourceDirectory $BoostSource -DynarmicSourceDirectory $DynarmicSource
```

`$BoostSource` must contain `boost/version.hpp`. `$DynarmicSource` must contain
Dynarmic's `CMakeLists.txt` and populated external libraries. Use the revisions
listed above. Reusing cached downloaded dependencies also works without
`-AllowNetwork`. Use a fresh build directory when switching dependency sources.

The Python wrapper records local build evidence and provides packaging as a
separate stage:

```powershell
python -B arm64_bridge/build.py native --allow-network
```

For manual CMake builds, use the NDK toolchain, `ANDROID_ABI=arm64-v8a`,
`ANDROID_PLATFORM=android-26`, `ANDROID_STL=c++_static`, and a Release build.
CMake's `FETCHCONTENT_SOURCE_DIR_BOOST` and `FETCHCONTENT_SOURCE_DIR_DYNARMIC`
variables select externally supplied dependency sources.

## Game inputs and APK packaging

The packaging scripts consume a **prepared apktool project**, not a stock APK.
Keep it locally under `arm64_bridge/app/`, with its manifests, resources, SDL
integration, game assets, and four data split projects under `app/splits/`:
`obb_main`, `obb_patch`, `rus_text`, and `rus_voice`. These files are deliberately
ignored by Git. This repository does not automatically recreate that prepared
project from a retail installation; retaining or independently reconstructing
its integration changes is required for a complete APK rebuild.

Provide the original ARM32 engine as
`arm64_bridge/app/assets/guest_libs/libGrimFandango.so`.
The engine used by the specialized save regression has SHA-256:

```text
826295d73af744bbfa89b92163940c6047e2e0bf7c76ff3cb199e6e6bbba9872
```

The original whole OBB names are
`main.150.com.doublefine.grimfandangoremastered.obb` and
`patch.1512.com.doublefine.grimfandangoremastered.obb`.
Russian resources are optional game inputs, not open-source dependencies.
The compiled cache index describes a particular set of containers; arbitrary
substitutes are not interchangeable.

Set `ANDROID_TOOLS_ROOT` to an external tool directory containing `baksmali.jar`
and `sdk/build-tools/37.0.0/lib/d8.jar`, then compile the bridge-owned Java helpers:

```powershell
python -B arm64_bridge/build_java.py
```

This compiles `CacheReader`, `RegistryPreflight`, `PortLauncher`, and `PortBack`,
converts them to smali, and applies those classes to the local prepared project.
The upstream SDL classes remain inputs. The `--baseline` option is an internal
comparison mode requiring a separately retained baseline source; it is not part
of the normal build.

For APK packaging, the external tool directory must also contain `apktool.jar`
and `sdk/build-tools/37.0.0/{aapt2.exe,zipalign.exe}`. Set `APK_SIGN_ROOT` to a local
directory containing `apksigner.jar`, `testkey.pk8`, and `testkey.x509.pem`.
Set `APK_CERT_SHA256` to that certificate's SHA-256 fingerprint (64 hex digits).
Keys and certificates must stay outside version control.

```powershell
python -B arm64_bridge/build.py package --tool-root $env:ANDROID_TOOLS_ROOT
```

The wrapper builds the base APK only. To package and validate all five prepared
targets together:

```powershell
python -B work/tools/apk_build.py --project-root arm64_bridge --tool-root $env:ANDROID_TOOLS_ROOT --java (Get-Command java).Source --arm64-bridge --target all
```

The outputs are `arm64_bridge/out/base.apk` and
`arm64_bridge/out/splits/*.apk`. The packager checks package/version identity,
signing certificates, guest storage, ABI, and 16 KiB ZIP alignment. It does not
install or run the game. Sign every APK in a set with the same certificate.
An APK signed with your own key may not update an existing differently signed
installation; preserve your saves before changing installations.

## Checks

The symbol parser and explicit-device selection checks need no game data or
connected device:

```powershell
python -B -m unittest discover -s arm64_bridge/tests -p test_check_symbols.py
python -B -m unittest discover -s arm64_bridge/tests -p test_apk_signing.py
python -B arm64_bridge/tests/test_selected_device_cli.py
```

The following checks use the local JDK or NDK. Run the Java helper build before
the language parser test:

```powershell
python -B arm64_bridge/tests/offline_back.py
python -B arm64_bridge/tests/test_language_hook.py
python -B arm64_bridge/tests/test_language_setting.py
```

Build the Android regression targets with `-BuildTests`. Run them only on a device
you explicitly select:

```powershell
./arm64_bridge/build_arm64.ps1 -AllowNetwork -BuildTests
./arm64_bridge/tests/run_android_tests.ps1 -Serial $env:ANDROID_SERIAL
```

The device runner copies and executes test programs. The Python harness likewise
requires an explicit `--serial`. Neither should be run against an unintended
device. See [timer regression](arm64_bridge/tests/TIMER_RETIREMENT.md) and
[save compression regression](arm64_bridge/tests/SAVE_COMPRESSION.md) for the
specialized guest-code tests.

`check_symbols.py` checks relocation-backed guest imports against the bridge's
registered providers. The scripts under `work/tools/cache_*` inspect cache inputs
and generate index data; their output is local build material.

## Status and limitations

This is a game-specific compatibility project under active restoration. Prior
local testing covered cold launches, elevator transitions, cutscenes, save/load,
Russian language restoration, and 16 KiB-page operation. Those observations do
not establish full-game correctness. A reported intermittent black background
and rare crash were not conclusively reproduced or attributed. Full playthrough,
audio acceptance, and a broad device compatibility matrix are incomplete.

Build evidence can contain local paths and device identifiers. `.gitignore`
uses an allowlist so evidence, private history, proprietary inputs, dependency
checkouts, build artifacts, signing inputs, and local state stay untracked.
Review staged content before extending that allowlist.

## License

The bridge and project-owned scripts are licensed under the
**GNU General Public License, version 3 or any later version**
(`SPDX-License-Identifier: GPL-3.0-or-later`); see [LICENSE](LICENSE).
Redistributing modified versions or covered binaries requires complying with
that license, including its corresponding-source requirements.

External dependencies retain their own licenses: Boost uses the Boost Software
License 1.0; Dynarmic uses the license in its pinned
[LICENSE.txt](https://github.com/azahar-emu/dynarmic/blob/e77b1ba0b7da7cbe93021b01a663acfe7c4dd516/LICENSE.txt).
Consult the license notices in Dynarmic's external libraries when distributing a
linked binary. This project's license does not grant rights to proprietary game
code, assets, trademarks, or third-party translations. Binary instruction
preimages and format compatibility metadata are present for version checks;
the commercial engine itself must be supplied separately.
