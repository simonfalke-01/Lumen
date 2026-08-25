# Lumen Virtual Display Driver

`LumenVirtualDisplay` is Lumen's x64 UMDF2 indirect-display driver. The elevated
Lumen service owns one generation-fenced virtual monitor with an exact
resolution, reduced rational refresh rate, dynamic range, and bit depth.

Lite packages do not include the driver. An MSI includes and selects the VDD
component by default only when its build receives the exact signed package. The
complete Windows profile requires that package and its lifecycle helper.

## Platform and API contract

- Windows 10 version 1903 (build 18362) or later, x64.
- Visual Studio 2022 with Windows SDK/WDK 10.0.26100.0.
- UMDF 2.25 with IddCx 1.10 headers and IddCx 1.4 as the SDR runtime minimum.
- `IddCxAdapterSetRenderAdapter`, monitor arrival/departure, dynamic mode, and
  swap-chain acquire/finish APIs.
- Host-side `QueryDisplayConfig`, `SetDisplayConfig`, and Advanced Color APIs.

ABI 5 advertises HDR only when every required IddCx 1.10 function, callback
field, structure, and `IDDCX_METADATA2` field is available at runtime. Missing
HDR API support returns `STATUS_NOT_SUPPORTED`; it is never inferred from an OS
version string.

## Exact mode and color contract

The driver accepts even modes from 256x200 through 8192x8192 and reduced
rational refresh rates from 10 through 480 Hz, further bounded by pixel count,
pixel rate, the active GPU, and the selected encoder. It publishes exactly one
mode per generation. The host rejects silent driver or DisplayConfig changes.

ABI 5 admits only these color-mode pairs:

- SDR: 8-bit wire mode, BGRA8 direct-frame texture, sRGB surface color space.
- HDR: 10-bit wire mode, FP16 direct-frame texture, linear scRGB surface color
  space.

HDR uses the driver's PQ/BT.2020 EDID, exact `IddCxMonitorUpdateModes2` target,
and target-scoped Advanced Color state. The FP16/scRGB capture source remains
linear; downstream stream negotiation preserves the selected PQ or HLG transfer
instead of deriving it from static metadata.

## ABI 5 direct frames

The driver creates two persistent shared textures and one shared D3D11 fence
per slot on the assigned IddCx render adapter. It performs at most one GPU
`CopyResource` from each accepted IddCx surface into a free slot. This is a
one-copy path, not zero-copy.

For each slot:

1. The driver acquires the even keyed-mutex value.
2. It copies the surface, signals the odd producer fence, and releases the odd
   keyed-mutex value to Lumen.
3. Lumen acquires the odd value, waits on the producer fence, converts and
   encodes on the same device, then signals and releases the next even value.
4. The driver reuses the slot only after the exact host release.

When both slots are occupied, the driver drops the newly acquired surface. It
never overwrites an acquired or ready slot. Latency and Quality sessions use the
same ownership contract.

Each frame descriptor includes:

- validated surface color space and SDR white level;
- resolved HDR metadata type (`DEFAULT`, `UNCHANGED`, or `NEW`) and effective
  HDR10 static metadata; and
- the exact immutable color-transform version retained for the frame lease.

Color-transform queries support the default state, a 256-entry per-channel RGB
gamma table, or a 3x4 matrix with scalar and a 4,096-entry one-dimensional RGB
LUT. Unknown, malformed, stale, protected, or non-finite metadata and transforms
disable direct frames for that generation. HDR surfaces must be exact FP16/scRGB
input; already-PQ surfaces are rejected rather than interpreted heuristically.

## Security and adapter binding

- Standard users cannot open the secured device interface.
- Mutating IOCTLs require exact packed sizes, write access, the real requestor
  PID, the owning WDF file, and a nonzero monotonic generation.
- ABI 5 reports the retained generation floor and requested/assigned adapter
  LUIDs, preventing generation reuse after a service restart.
- Same-request retries are idempotent. Another process, file, or generation is
  rejected.
- WUDFHost event, texture, and fence handles carry the source PID and creation
  time. The LocalSystem host pins that process before reverse-duplicating them,
  preventing PID-reuse substitution.
- Direct frames require exact agreement between the assigned adapter and the
  active NVIDIA encoder probe: LUID, PCI identity, revision, and UMD driver
  version.
- Display topology and Advanced Color state are restored after failure and
  normal stop. Crash cleanup removes the monitor; stale recovery verifies the
  former process is dead.

## Fail-closed behavior and compatibility

Umbra v3 treats the default `optional` runtime policy as required: unless VDD is
explicitly disabled, startup requires the exact VDD mode and a healthy ABI 5
direct-frame channel. Direct-frame or NVENC failure ends/reinitializes the v3
session; it does not switch capture backends mid-session.

Legacy Moonlight keeps its compatibility behavior. With `optional`, a VDD
activation failure may return to the configured physical display only after a
proven-safe rollback. If an SDR VDD is already active and its direct channel is
unavailable or quarantined, Lumen may capture that VDD through DDA/WGC.

An active HDR VDD always requires the ABI 5 FP16/metadata/transform path.
Startup or runtime failure is terminal for that attempt; untransformed DDA/WGC
HDR fallback is forbidden.

Surface preservation at this boundary is not a claim that capture-to-display is
lossless or indistinguishable from a direct cable.

## Build and validation

Build from a Visual Studio Developer Command Prompt:

```powershell
msbuild LumenVirtualDisplay.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

Portable tests validate mode, ABI, metadata, transform, generation, and slot
ownership rules. Release evidence additionally requires `/W4 /WX`, Code
Analysis/PREfast, InfVerif, a Microsoft-signed package, MSI lifecycle tests, and
live first-activation plus failure-injection tests on every declared Windows/GPU
matrix. HDR correctness and latency percentiles require separate end-to-end
hardware evidence.
