# Lumen virtual microphone driver foundation

This directory contains the isolated Windows kernel transport foundation for
client-to-host microphone audio. The shared ABI accepts only 48 kHz, mono,
signed 16-bit little-endian PCM, with at most 20 ms (960 frames) per fixed-size
buffered write.

The control device is intentionally limited to `LocalSystem` by both
`IoCreateDeviceSecure` and the INF hardware security descriptor. A single file
object owns a caller-selected, generation-scoped writer lease. Closing that file
resets the FIFO and ends the generation. The kernel ABI contains no pointers,
handles, networking, or codec state.

## FIFO contract

- Capacity: 9,600 frames (200 ms).
- Underflow: return the requested frame count and fill missing frames with
  digital silence.
- Overflow: discard the oldest queued frames, preserving the newest audio.
- Counters: accepted frames, stale writes, synthesized underflow silence,
  overflow drops, resets, and current fill are exposed by
  `IOCTL_LUMEN_VMIC_QUERY_STATS`.
- Serialization: the portable core requires external locking; the kernel
  control wrapper uses one spin lock around lease and FIFO state.

## WaveRT endpoint

The `wavert` subtree is the capture-side subset of Microsoft's maintained
SimpleAudioSample PortCls implementation. Lumen installs one topology miniport
and one WaveRT miniport; the render endpoint table is empty. The capture filter
advertises exactly 48 kHz, mono, signed 16-bit PCM in default, communications,
and raw processing modes.

The WaveRT stream timer fills each newly available DMA region through
`LumenVirtualMicrophoneControlReadFrames()`. That call consumes live PCM from
the secured FIFO and writes digital silence for any shortfall. The INF registers
only `KSCATEGORY_CAPTURE`, audio/realtime, and topology interfaces and names the
endpoint `Lumen Virtual Microphone`.

The PCM control device is distinct from the audio filter device. Windows audio
services retain the standard Microsoft sample access needed to open WaveRT
pins, while the injection path created by `IoCreateDeviceSecure` remains
`LocalSystem`-only.

## ABI lifecycle

1. Open `\\.\LumenVirtualMicrophone` for read/write access from the Lumen
   `LocalSystem` service.
2. Call `QUERY_ABI` and validate the ABI version and fixed format fields.
3. Select a non-zero generation and call `OPEN_STREAM` with that generation and
   the exact advertised format.
4. Send fixed-size `WRITE_PCM` requests with 1..960 meaningful samples and the
   active generation. Samples after `frame_count` are ignored.
5. Use `RESET` after a discontinuity. Reset retains ownership and generation.
6. Close the handle to end the stream. Cleanup always empties buffered audio.

All requests use `METHOD_BUFFERED` and require an exact input/output length.

| Operation | Exact contract |
| --- | --- |
| `QUERY_ABI` | No input; 16-byte response. |
| `OPEN_STREAM` | 16-byte input, no output. The format must match exactly and the requested generation must be non-zero. A different owner or generation returns `STATUS_DEVICE_BUSY`; repeating the same open is idempotent. |
| `WRITE_PCM` | Fixed 1,932-byte input, no output. `frame_count` must be 1..960. A wrong file object or generation returns `STATUS_REVISION_MISMATCH` and increments `stale_writes`. |
| `RESET` | 8-byte input, no output. It validates ownership/generation, empties the FIFO, and retains the active lease. |
| `QUERY_STATS` | No input; 56-byte response. |

`IRP_MJ_CLEANUP` resets queued audio, increments the reset counter, clears the
owner, and returns the visible generation to zero.

## Portable verification

From this directory on any host with a C/C++ compiler:

```sh
cc -std=c11 -Wall -Wextra -Werror -c LumenPcmRing.c -o /tmp/lumen_pcm_ring.o
c++ -std=c++17 -Wall -Wextra -Werror tests/ring_tests.cpp \
  /tmp/lumen_pcm_ring.o -o /tmp/lumen_pcm_ring_tests
/tmp/lumen_pcm_ring_tests
```

The Windows driver project requires Visual Studio 2022 and WDK
`10.0.26100.0`, matching the existing Lumen driver toolchain. Build the x64
package with:

```powershell
msbuild LumenVirtualMicrophone.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

## Official references

- [Microsoft Simple Audio Sample](https://github.com/microsoft/Windows-driver-samples/tree/main/audio/simpleaudiosample)
- [Microsoft SysVAD sample](https://github.com/microsoft/Windows-driver-samples/tree/main/audio/sysvad)
- [Developing a WaveRT miniport driver](https://learn.microsoft.com/windows-hardware/drivers/audio/developing-a-wavert-miniport-driver)
- [WaveRT port driver introduction](https://learn.microsoft.com/windows-hardware/drivers/audio/introducing-the-wavert-port-driver)
- [IoCreateDeviceSecure](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdmsec/nf-wdmsec-iocreatedevicesecure)

The reference checkout used during implementation was Microsoft
`Windows-driver-samples` commit `717778a20ba4dd2440fe609f69153a1f8a64f597`.
Its required notice is retained in `THIRD_PARTY_NOTICES.md`.
