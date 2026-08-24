# Lumen Virtual Display Driver

`LumenVirtualDisplay` is Lumen's source-built UMDF2 indirect display driver. It
exposes one exact, session-scoped resolution and rational refresh rate through
Microsoft IddCx and is controlled only by the elevated Lumen host service.

Regular and lite packages do not include this driver. The strict complete
Windows profile includes the separately built, signed package and its lifecycle
helper. Surface-fidelity and copy descriptions apply only to the driver/capture
handoff, not to the encoded, transported, decoded, or displayed stream.

## Supported platform and APIs

- Windows 10 version 1903 (build 18362) or later, x64.
- Visual Studio 2022 with Windows SDK/WDK 10.0.26100.0.
- UMDF 2.25 with IddCx 1.10 headers, a minimum required IddCx version of 1.4,
  and the downlevel `IddCx0102` extension binding.
- `IddCxAdapterInitAsync`, `IddCxMonitorCreate`, `IddCxMonitorArrival`,
  `IddCxMonitorDeparture`, `IddCxAdapterSetRenderAdapter`, the default/target
  mode callbacks, and the IddCx swap-chain acquire/finish APIs.
- `QueryDisplayConfig`, `SetDisplayConfig`, and
  `DisplayConfigGetDeviceInfo` are used by the host coordinator, not by the
  driver.

IddCx 1.4 is available throughout Lumen's supported Windows version range and
is the production minimum. Newer IddCx-only features remain gated until their
separate Windows and hardware validation is complete.

## Exact mode contract

The current baseline accepts practical even modes from 256x200 through
8192x8192 and reduced rational refresh rates from 10 through 480 Hz, further
bounded by total pixels, pixel rate, the active GPU, and the selected encoder.
It reports exactly one dynamic monitor/target mode per generation. The host
rejects any driver or DisplayConfig adjustment; it never silently clamps.
The permanent connector is EDID-less by design so IddCx obtains the exact
session mode exclusively through the default and target-mode callbacks.

The baseline handoff is explicitly SDR, 8-bit BGRA with no format loss inside
the VDD surface boundary. This is not an end-to-end lossless-stream claim. IddCx 1.10
`IddCxMonitorUpdateModes2` is required for a proven HDR/WCG path. Until a
separate Windows 11 hardware gate exists, HDR10 and 10-bit capability bits stay
clear and HDR requests fall back before VDD mutation.

## Security and lifecycle

- The device object uses `SDDL_DEVOBJ_SYS_ALL_ADM_ALL`; standard users cannot
  open the control interface.
- All mutating IOCTLs require write access, exact packed sizes, the real
  requestor PID, the owning WDF file object, and a nonzero monotonic generation.
- ABI v4 reports the driver's retained generation floor and requested/actual
  render-adapter LUIDs, so a restarted Lumen
  service continues above it instead of reusing a fenced generation.
- One process/file/generation owns the driver. Same-request retries are
  idempotent; other sessions receive busy/access-denied.
- File cleanup removes the monitor after a service crash. Explicit stale
  recovery additionally verifies that the former process is no longer alive.
- Host DisplayConfig state is snapshotted before arrival and restored on every
  failure and normal stop.

## Direct-frame contract

ABI v4 implements one concrete, hardware-gated capture path. After IddCx assigns
the swap chain, the driver creates exactly two persistent BGRA8 shared textures
and one shared D3D11 fence per texture on the IddCx render adapter. For each
accepted desktop surface the driver performs at most one `CopyResource` into a
safe slot, signals that slot's odd producer fence value, and finishes the IddCx
frame. This is a one-copy path, not zero-copy.

The Lumen service opens the secured device as the exact prepared owner process.
After exact requestor PID/file/generation authorization, the driver publishes
raw unnamed WUDFHost event, texture, and fence handles with the source PID and
process creation time. The LocalSystem host pins that live source process,
checks its creation time to prevent PID-reuse substitution, and reverse-
duplicates each handle into itself. The host validates ABI generation, mode,
adapter LUID, unique handles, texture descriptors, and the exact validated RTX
4060/NVIDIA driver identity before importing either slot. A driver-published
auto-reset event wakes bounded resource and frame waits; the Latency path
performs no millisecond polling.
For each slot, the driver acquires the current even keyed-mutex value, submits
the copy and odd producer fence, then releases that odd key to the host. The
host acquires the odd key, GPU-waits the producer fence, passes the imported
texture through same-device conversion and NVENC, signals the next even
consumer fence, and releases the same even key back to the producer on exact
lease release. The driver never overwrites an acquired or ready slot. Any
keyed-mutex, GPU wait, copy-device health, fence, descriptor, or terminal IddCx
failure quarantines every direct slot for that generation and wakes the host so
capture can fall back without reusing unproven memory.

The textures use the NT-handle and keyed-mutex creation flags required by
`IDXGIResource1::CreateSharedHandle`. The keyed mutex provides bounded CPU-side
slot ownership; the explicit shared D3D11 fence provides GPU ordering and timing
telemetry.

PREPARE carries the exact adapter identity frozen by the active encoder probe.
Before monitor arrival the driver submits that LUID through
`IddCxAdapterSetRenderAdapter`. The API is a preference, so the actual
`EvtIddCxMonitorAssignSwapChain.RenderAdapterLuid` remains authoritative. A
mismatch disables direct-frame publication for that generation while leaving
the VDD available to the established DDA/WGC fallback.

Direct-frame activation requires an active NVENC encoder and exact agreement
between the frozen encoder identity and the imported VDD adapter LUID, PCI
identity, revision, and UMD driver version. Missing or mismatched identity data
fails closed to DDA/WGC; there are no manual environment-variable gates.

Latency and Quality modes both preserve keyed-mutex ownership and ready-slot
order, dropping a new IddCx surface when both slots are occupied. If any
capability, identity, handle, fence, import, timeout, conversion,
or NVENC boundary fails, Lumen quarantines the direct source and reinitializes on
the existing DDA/WGC path for the already-active virtual display.

## Build and validation

Build the project from a Developer Command Prompt:

```powershell
msbuild LumenVirtualDisplay.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

Portable tests validate only pure mode and ABI metadata rules. They do not prove
driver production, resource sharing, or frame flow. Required evidence for the
direct path is a clean WDK build with `/W4 /WX`, Code Analysis/PREfast, InfVerif,
then installation and first-activation frame-flow testing on the explicitly
validated Windows RTX 4060 host. Installation must not occur until every build
and package gate is green. HDR and latency percentiles remain separate hardware
validation gates.
