<div align="center">
  <img src="sunshine.svg" alt="Lumen project icon" width="192">
  <h1>Lumen</h1>
  <p>A self-hosted game-streaming host compatible with Moonlight.</p>
</div>

Lumen is a Sunshine-derived host for Windows, Linux, macOS, and FreeBSD. The
current production protocol remains compatible with unmodified Moonlight
clients. The Windows/NVIDIA path also contains opt-in work for bounded input,
stream policy, encoder startup, packetization, and virtual displays.

## Stream policies

- **Legacy** preserves Moonlight wire behavior for clients that send no Lumen
  policy extension.
- **Latency** selects the P1/ultra-low-latency NVENC profile, immediate packet
  pacing, shorter client decode queues, and immediate presentation.
- **Quality** selects the P5/high-quality NVENC profile, stable packet pacing,
  bounded larger client decode queues, and display-linked presentation.

Legacy Moonlight packet ordering and reliable input delivery do not change.
Codec, HDR, and YUV 4:4:4 remain explicit client preferences, not mode aliases.

The separate `codec-lossless-required` request is experimental and fail-closed.
It means lossless encoding after the selected encoder-input conversion; it does
not mean an end-to-end lossless, HDR-perfect, or HDMI-equivalent stream.

## Compatibility and modern protocol work

Vanilla Moonlight compatibility remains a release requirement. Existing
clients continue to use GameStream's HTTP(S), RTSP, and UDP listeners.

The repository also contains experimental Umbra/Lumen control, pairing, and
single-port QUIC implementations. They are not shipped as the production path.
The QUIC design uses one UDP port only for a future Umbra-specific protocol;
vanilla Moonlight still requires the legacy ports. See:

- [Experimental single-port QUIC v3 specification](docs/protocols/umbra-lumen-quic-v3.md)
- [Performance tuning and measurement boundaries](docs/performance_tuning.md)

## Virtual display status

The Windows virtual display directory contains the source-built IddCx driver
and its hardware-gated one-copy shared-texture/fence capture path. It is not
part of current release packages and is not production-ready until Windows
installation and frame-flow gates pass. Unsupported or unvalidated boundaries
fall back to DDA/WGC. See the [VDD source README](src/platform/windows/virtual_display_driver/README.md).

## Install, configure, and build

- [Getting Started](docs/getting_started.md)
- [Configuration](docs/configuration.md)
- [Building](docs/building.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Documentation index](docs/guides.md)

Do not expose the Web UI or management API directly to the public Internet.
Use a trusted private network or an authenticated tunnel. Streaming ports and
management access are separate concerns. Legacy four-digit Moonlight pairing
is accepted only from loopback or private/trusted LAN source addresses; public
or WAN pairing receives a wire-compatible XML 403 response before state is
allocated. Pair on the LAN, then use an authenticated tunnel for remote access.
WAN media encryption is mandatory by default. Setting `wan_encryption_mode = 1`
is an explicit compatibility downgrade for older clients and is logged as a
warning because unsupported clients may otherwise stream without full media
encryption.

## Project status

Repository tests prove parser, state-machine, wire-compatibility, and portable
policy behavior. They do not prove RTX 4060 driver behavior, VDD installation,
HDR fidelity, physical input-to-photon latency, or WAN performance. Those claims
require deployment and hardware evidence.

## License and attribution

Lumen remains GPL-3.0 and retains Sunshine and third-party attribution. See
[LICENSE](LICENSE), [NOTICE](NOTICE), and [Legal](docs/legal.md).
