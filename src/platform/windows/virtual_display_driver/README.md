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
- UMDF 2.23 and IddCx 1.2 (`IddCx0102`).
- `IddCxAdapterInitAsync`, `IddCxMonitorCreate`, `IddCxMonitorArrival`,
  `IddCxMonitorDeparture`, the default/target mode callbacks, and the IddCx
  swap-chain acquire/finish APIs.
- `QueryDisplayConfig`, `SetDisplayConfig`, and
  `DisplayConfigGetDeviceInfo` are used by the host coordinator, not by the
  driver.

IddCx 1.2 is available throughout Lumen's supported Windows version range. The
driver requires 1.4 rather than using untested runtime down-level shims.

## Exact mode contract

The current baseline accepts practical even modes from 256x200 through
8192x8192 and reduced rational refresh rates from 10 through 480 Hz, further
bounded by total pixels, pixel rate, the active GPU, and the selected encoder.
It reports exactly one dynamic monitor/target mode per generation. The host
rejects any driver or DisplayConfig adjustment; it never silently clamps.

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
- ABI v3 reports the driver's retained generation floor, so a restarted Lumen
  service continues above it instead of reusing a fenced generation.
- One process/file/generation owns the driver. Same-request retries are
  idempotent; other sessions receive busy/access-denied.
- File cleanup removes the monitor after a service crash. Explicit stale
  recovery additionally verifies that the former process is no longer alive.
- Host DisplayConfig state is snapshotted before arrival and restored on every
  failure and normal stop.

## Direct-frame contract

ABI v3 implements one concrete, hardware-gated capture path. After IddCx assigns
the swap chain, the driver creates exactly two persistent BGRA8 shared textures
and one shared D3D11 fence per texture on the IddCx render adapter. For each
accepted desktop surface the driver performs at most one `CopyResource` into a
safe slot, signals that slot's odd producer fence value, and finishes the IddCx
frame. This is a one-copy path, not zero-copy.

The Lumen service opens the secured device as the exact prepared owner process.
The driver duplicates only unnamed texture/fence handles directly into that
process. The host validates ABI generation, mode, adapter LUID, unique handles,
texture descriptors, and the exact validated RTX 4060/NVIDIA driver identity
before importing either slot. A driver-published auto-reset event wakes bounded
resource and frame waits; the Latency path performs no millisecond polling.
The host GPU-waits the producer fence, passes the
imported texture through same-device conversion and NVENC, then signals the even
consumer fence and releases the exact generation/sequence/slot. The driver never
overwrites an acquired slot. A failed GPU wait, copy-device health check, or
fence signal quarantines every direct slot for that generation and wakes the
host so capture can fall back without reusing unproven memory.

The production host keeps this path disabled unless all of the following are
present and exact: `LUMEN_EXPERIMENTAL_VDD_DIRECT_FRAME=1`,
`LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_HARDWARE_VALIDATED=RTX4060`,
`LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_MODEL`, and
`LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_VALIDATED_DRIVER`. The packed adapter
LUID, PCI device ID, PCI subsystem ID, and PCI revision must also exactly match
the `LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_ADAPTER_LUID`,
`LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_DEVICE_ID`,
`LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_SUBSYSTEM_ID`, and
`LUMEN_EXPERIMENTAL_FUSED_D3D11_NVENC_REVISION` decimal values. The current committed
NVENC probe must also match the driver render-adapter LUID, PCI identity, and
UMD driver version. These gates prevent a successful build from being treated
as hardware validation.

Latency mode may replace only the oldest ready, unleased slot. Quality mode
preserves ready FIFO order and drops a new IddCx surface when both slots are
occupied. If any capability, identity, handle, fence, import, timeout, conversion,
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
