# Building
Lumen requires [CMake](https://cmake.org) 3.20 or later.

## Building Locally

### Compiler
It is recommended to use one of the following compilers:

| Compiler    | Version |
|:------------|:--------|
| GCC         | 14+     |
| Clang       | 17+     |
| Apple Clang | 15+     |

### Dependencies

#### FreeBSD
> [!CAUTION]
> Lumen support for FreeBSD is experimental and may be incomplete or not work as expected

##### Install dependencies
```sh
pkg install -y \
  audio/opus \
  audio/pulseaudio \
  devel/cmake \
  devel/evdev-proto \
  devel/git \
  devel/libevdev \
  devel/llvm19 \
  devel/ninja \
  devel/pkgconf \
  devel/qt6-base \
  ftp/curl \
  graphics/libdrm \
  graphics/qt6-svg \
  graphics/wayland \
  multimedia/libva \
  net/miniupnpc \
  ports-mgmt/pkg \
  security/openssl \
  shells/bash \
  www/npm-node22 \
  x11/libX11 \
  x11/libxcb \
  x11/libXfixes \
  x11/libXrandr \
  x11/libXtst
```

Use LLVM 19 when configuring a local FreeBSD build:

```sh
export CC=clang19
export CXX=clang++19
```

#### Linux
Dependencies vary depending on the distribution. You can reference our
[linux_build.sh](https://github.com/simonfalke-01/Lumen/blob/master/scripts/linux_build.sh) script for a list of
dependencies we use in Debian-based, Fedora-based and Arch-based distributions. Please submit a PR if you would like to extend the
script to support other distributions.

##### KMS Capture
If you are using KMS, patching the Lumen binary with `setcap` is required. Some post-install scripts handle this. If building
from source and using the binary directly, this will also work:

```bash
sudo cp build/lumen /tmp
sudo setcap cap_sys_admin,cap_sys_nice+p /tmp/lumen
sudo getcap /tmp/lumen
sudo mv /tmp/lumen build/lumen
```

##### CUDA Toolkit
Lumen requires CUDA Toolkit for NVFBC capture. There are two caveats to CUDA:

1. The version installed depends on the version of GCC.
2. The version of CUDA you use will determine compatibility with various GPU generations.
   At the time of writing, the recommended version to use is CUDA ~13.1.
   See [CUDA compatibility](https://docs.nvidia.com/deploy/cuda-compatibility/index.html) for more info.

> [!NOTE]
> To install older versions, select the appropriate run file based on your desired CUDA version and architecture
> according to [CUDA Toolkit Archive](https://developer.nvidia.com/cuda-toolkit-archive)

#### macOS
You can either use [Homebrew](https://brew.sh) or [MacPorts](https://www.macports.org) to install dependencies.

##### Homebrew
```bash
dependencies=(
  "boost"  # Optional
  "cmake"
  "doxygen"  # Optional, for docs
  "graphviz"  # Optional, for docs
  "icu4c"  # Optional, if boost is not installed
  "miniupnpc"
  "ninja"
  "node"
  "openssl@3"
  "opus"
  "pkg-config"
  "qtbase"
  "qtsvg"
)
brew install "${dependencies[@]}"
```

If there are issues with an SSL header that is not found:

@tabs{
  @tab{ Intel | ```bash
    ln -s /usr/local/opt/openssl/include/openssl /usr/local/include/openssl
    ```}
  @tab{ Apple Silicon | ```bash
    ln -s /opt/homebrew/opt/openssl/include/openssl /opt/homebrew/include/openssl
    ```
  }
}

##### MacPorts
```bash
dependencies=(
  "cmake"
  "curl"
  "doxygen"  # Optional, for docs
  "graphviz"  # Optional, for docs
  "libopus"
  "miniupnpc"
  "ninja"
  "npm9"
  "pkgconfig"
  "qt6-qtbase"
  "qt6-qtsvg"
)
sudo port install "${dependencies[@]}"
```

#### Windows

> [!WARNING]
> Cross-compilation is not supported on Windows. You must build on the target architecture.

First, you need to install [MSYS2](https://www.msys2.org).

For AMD64 startup "MSYS2 UCRT64" (or for ARM64 startup "MSYS2 CLANGARM64") then execute the following commands.

##### Update all packages
```bash
pacman -Syu
```

##### Set toolchain variable
For UCRT64:
```bash
export TOOLCHAIN="ucrt-x86_64"
```

For CLANGARM64:
```bash
export TOOLCHAIN="clang-aarch64"
```

##### Install dependencies
```bash
dependencies=(
  "git"
  "mingw-w64-${TOOLCHAIN}-boost"  # Optional
  "mingw-w64-${TOOLCHAIN}-cmake"
  "mingw-w64-${TOOLCHAIN}-cppwinrt"
  "mingw-w64-${TOOLCHAIN}-curl-winssl"
  "mingw-w64-${TOOLCHAIN}-doxygen"  # Optional, for docs... better to install official Doxygen
  "mingw-w64-${TOOLCHAIN}-graphviz"  # Optional, for docs
  "mingw-w64-${TOOLCHAIN}-miniupnpc"
  "mingw-w64-${TOOLCHAIN}-onevpl"
  "mingw-w64-${TOOLCHAIN}-openssl"
  "mingw-w64-${TOOLCHAIN}-opus"
  "mingw-w64-${TOOLCHAIN}-toolchain"
  "mingw-w64-${TOOLCHAIN}-qt6-static"
)
if [[ "${MSYSTEM}" == "UCRT64" ]]; then
  dependencies+=(
    "mingw-w64-${TOOLCHAIN}-MinHook"
    "mingw-w64-${TOOLCHAIN}-nodejs"
    "mingw-w64-${TOOLCHAIN}-nsis"
  )
fi
pacman -S "${dependencies[@]}"
```

Static Qt is enabled by default on Windows. Lumen automatically adds the MSYS2 static Qt prefix at
`${MINGW_PREFIX}/qt6-static` when that package is installed. If an IDE does not inherit `MINGW_PREFIX`, Lumen
derives the same prefix from the selected compiler. If static Qt is installed in a custom location, specify it with
`-DCMAKE_PREFIX_PATH=/path/to/qt6-static`.

To use dynamic Qt instead, configure with `-DSUNSHINE_USE_STATIC_QT=OFF` and ensure the dynamic Qt package is
available through the normal toolchain prefix.

To create a WiX installer, you also need to install [.NET](https://dotnet.microsoft.com/download).

For ARM64: To build frontend, you also need to install [Node.JS](https://nodejs.org/en/download)

##### Lumen Virtual HID driver

The Windows application and Lumen Virtual HID driver use separate toolchains. The Virtual HID driver currently supports
Windows 11 x64 only. One root driver and one SYSTEM-only control interface provide Lumen's virtual keyboard, relative
and absolute mouse, consumer controls, and dynamic gamepads. Continue to build the AMD64 application in MSYS2 UCRT64,
but build the VHF driver with MSVC from Visual Studio and the Windows Driver Kit (WDK). Do not build the driver with the
MSYS2 application toolchain.

Install [Visual Studio 2022](https://visualstudio.microsoft.com/vs/) with the **Desktop development with C++** workload,
a Windows 11 SDK, and the matching [Windows Driver Kit](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk).
From a Visual Studio 2022 Developer Command Prompt in the repository root, build the x64 driver:

```bat
msbuild src\platform\windows\virtual_hid_driver\LumenVirtualHid.vcxproj /m /t:Build /p:Configuration=Release /p:Platform=x64
```

The default build output is
`src/platform/windows/virtual_hid_driver/build/x64/Release/package`. The regular CMake build does not build or sign the
driver. To include it in an installer, supply its package directory with
`SUNSHINE_VIRTUAL_HID_DRIVER_PACKAGE_DIR`. Omitting that option produces a package without the Virtual HID driver;
Lumen remains usable with `windows_input_backend = sendinput`, and Xbox 360 gamepads remain available through ViGEm.

A Lumen Windows package contains the x64 `LumenVirtualHid.inf`, `LumenVirtualHid.cat`, `LumenVirtualHid.dll`, and
a bundled `.cer` file when configured with `SUNSHINE_VIRTUAL_HID_BUNDLED_CERTIFICATE=ON`. Setup trusts only that
certificate. A committed upgrade replaces only the recorded prior Lumen signer, and a committed uninstall removes
only the recorded thumbprint. The MSI exposes one optional **Lumen Virtual Input** feature for the entire driver; it
does not install libvirtualhid's broker, service, installer, or licensing UI. Users can deselect this feature and use
`SendInput` plus ViGEm-backed Xbox 360 controllers. The Windows ARM64 application build has no Virtual HID driver
package and uses `SendInput` plus ViGEm.

Protocol generation 3 preserves the static keyboard/mouse ABI at version 2 and negotiates the dynamic-gamepad extension
separately at version 1, so old static-input clients are not broken by larger structures. The extension remains part of
the existing `LumenVirtualHid` service and package identity. Build validation runs
`lumen-vhidctl smoke-gamepad` as LocalSystem to create, enumerate, submit to, and destroy every supported VHF profile.
For Generic PID it reads a distinctive submitted input report from the real HID collection, writes a PID output report,
and requires that exact report through the authenticated output queue. It also rejects mutated and cross-file handles,
verifies owner-file cleanup and the 16-device limit, and confirms every HID collection disappears. The helper must not
make the control interface accessible to normal
administrators or install a separate broker.
The same installed helper runs `smoke-vigem` after provisioning the bundled ViGEmBus package, submits a distinctive
Xbox 360 state, and requires a live, indexed ViGEm bus target plus a successful report update. It also reports XUSB
user-index assignment and whether the current process can read the exact state through `XInputGetState`; those are
diagnostics rather than gates because Windows service and hosted-CI sessions can be isolated from the interactive
XInput device namespace even when the ViGEm target is healthy.

##### Lumen Virtual Microphone driver

Client microphone passthrough uses a separate Windows 11 x64 WaveRT driver. Build it from a Visual Studio 2022
Developer Command Prompt with the matching WDK:

```bat
msbuild src\platform\windows\virtual_microphone_driver\LumenVirtualMicrophone.vcxproj /m /t:Build /p:Configuration=Release /p:Platform=x64
```

The driver project stages `LumenVirtualMicrophone.inf`, `LumenVirtualMicrophone.sys`, and
`LumenVirtualMicrophone.cat`. Pass that directory to CMake with
`-DSUNSHINE_VIRTUAL_MICROPHONE_DRIVER_PACKAGE_DIR=<package-directory>`. The packager rejects extra files, missing
files, a non-AMD64 target, or an INF without the exact `ROOT\LumenVirtualMicrophone` identity. The MSI exposes the
package as the optional, default-off **Client Microphone Passthrough** feature. Lite ZIP packages exclude both the
driver and `lumen-vmicctl.exe`. Automated tagged builds omit this optional driver until the production driver pipeline
is enabled; normal Windows CI still builds and validates the driver and its MSI feature.

##### Lumen Virtual Display driver source

The repository contains an x64 UMDF2 indirect-display driver under
`src/platform/windows/virtual_display_driver`. The regular CMake build does not
build or package it. The complete Windows profile below accepts it only as an
exact signed package; the lite package continues through existing DDA/WGC
capture without installing the driver.

Build the driver only from a Visual Studio 2022 Developer Command Prompt with a
matching Windows 11 SDK and WDK:

```bat
msbuild src\platform\windows\virtual_display_driver\LumenVirtualDisplay.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

Portable tests cover mode arithmetic, ABI layouts, generation and lease
lifecycle, rollback, EDID policy, and exact-one connector selection. ABI 3 adds
two persistent shared texture/fence slots and a bounded event-driven frame
channel. The driver performs one GPU `CopyResource` from each accepted IddCx
surface into a safe slot; this is a one-copy path, not zero-copy. Regular and
lite packages continue to use DDA/WGC, while only the strict complete profile
accepts the separately built driver package. Public release still requires
Windows validation of swap-chain lifetime, first activation, InfVerif, and
Microsoft-signed catalogs. HDR and latency claims remain outside the portable
test boundary. See the
[driver README](../src/platform/windows/virtual_display_driver/README.md) for
the exact validation boundary.

##### Complete Windows profile

The complete MSI includes the MsQuic ABI 2 runtime and the Virtual HID,
Virtual Microphone, and Virtual Display packages. Build it with the strict
PowerShell entry point:

```powershell
.\scripts\windows\build-full-profile.ps1 `
  -SourceRoot $PWD `
  -StagingRoot C:\LumenBuild\full `
  -Msys2Root C:\msys64 `
  -MsQuicPackageRoot C:\LumenBuild\msquic-2.6.0 `
  -PythonPath C:\Python314\python.exe `
  -DotNetRoot 'C:\Program Files\dotnet' `
  -NodeRoot 'C:\Program Files\nodejs' `
  -SignedDriverRoot C:\LumenBuild\signed-drivers `
  -BuildVersion 0.1.0
```

The signed-driver root must contain `virtual-hid`, `virtual-microphone`, and
`virtual-display` subdirectories plus the unchanged
`full-profile-driver-manifest.json` produced with the raw submission. Each
driver directory contains exactly its INF, Microsoft-signed catalog, and driver
binary. The script builds all three raw driver submissions and the MsQuic shim
first. If signed packages are absent it writes
`full-profile-driver-manifest.json` and stops before configuring the
application. The script extracts the frozen archive into a disjoint staging
tree, verifies every extracted path, byte count, and SHA-256 value against
`full-profile-files.json`, and builds every driver, shim, test, and package only
from that immutable snapshot. After signed packages are supplied, it verifies
the source-freeze identity, kernel signing, and catalog coverage; derives the ABI 2
DLL/import-library hashes from the actual MSVC outputs; builds with
`LUMEN_WINDOWS_FULL_PROFILE=ON`; synchronizes the locked Python environment
without downloading another interpreter; builds with warnings as errors; runs
the full test executable; creates MSI and lite ZIP packages; and validates the
MSI tables. `PythonPath`, `DotNetRoot`, and `NodeRoot` may be omitted when the
tools are on `PATH`, but automation should pass their exact locations.

Release CI requires `full_profile_driver_run_id`; a tag cannot silently omit a
driver or fall back to the legacy transport. Source bundles can be created with
`scripts/windows/freeze-full-profile-source.ps1`. The freeze records every
file hash, archive hash, MsQuic source identity, VDD ABI, and runtime pins still
waiting for Windows artifacts.

For an isolated local full-system test, run
`scripts/windows/sign-full-profile-local-test.ps1` on the three raw submission
directories, then pass its output to the full builder with
`-AllowTestSignedDrivers`. The resulting MSI contains
`metadata/LOCAL-TEST-SIGNED.json`; it is not a public release artifact. The test
certificate must be trusted on the test host before installing its drivers.
Public release builds reject this marker and require kernel-policy-valid signed
catalogs.

### Clone
Ensure [git](https://git-scm.com) is installed on your system, then clone the repository using the following command:

```bash
git clone https://github.com/simonfalke-01/Lumen.git --recurse-submodules
cd Lumen
mkdir build
```

### Build

```bash
cmake -B build -G Ninja -S .
ninja -C build
```

> [!TIP]
> Available build options can be found in
> [options.cmake](https://github.com/simonfalke-01/Lumen/blob/master/cmake/prep/options.cmake).

### Package

@tabs{
  @tab{FreeBSD | @tabs{
    @tab{pkg | ```bash
      cpack -G FREEBSD --config ./build/CPackConfig.cmake
      ```}
  }}
  @tab{Linux | @tabs{
    @tab{deb | ```bash
      cpack -G DEB --config ./build/CPackConfig.cmake
      ```}
    @tab{rpm | ```bash
      cpack -G RPM --config ./build/CPackConfig.cmake
      ```}
  }}
  @tab{macOS | @tabs{
    @tab{DragNDrop | ```bash
      cpack -G DragNDrop --config ./build/CPackConfig.cmake
      ```}
  }}
  @tab{Windows | @tabs{
    @tab{NSIS Installer | ```bash
      cpack -G NSIS --config ./build/CPackConfig.cmake
      ```}
    @tab{WiX Installer | ```bash
      cpack -G WIX --config ./build/CPackConfig.cmake
      ```}
    @tab{Portable | ```bash
      cpack -G ZIP --config ./build/CPackConfig.cmake
      ```}
  }}
}

### Remote Build
It may be beneficial to build remotely in some cases. This will enable easier building on different operating systems.

1. Fork the project
2. Activate workflows
3. Trigger the *CI* workflow manually
4. Download the artifacts/binaries from the workflow run summary

<div class="section_buttons">

| Previous                              |                            Next |
|:--------------------------------------|--------------------------------:|
| [Troubleshooting](troubleshooting.md) | [Contributing](contributing.md) |

</div>

<details style="display: none;">
  <summary></summary>
  [TOC]
</details>
