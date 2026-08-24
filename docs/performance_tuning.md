# Performance Tuning

Start with a fixed test matrix: host GPU and driver, capture output, resolution,
refresh rate, codec tuple, client display, stream policy, bitrate, packet size,
and network type. Change one variable at a time. A smoother stream or a higher
reported FPS is not proof of lower input-to-photon latency.

## Session policies

Umbra can request `latency` or `quality`. Unmodified Moonlight clients omit the
extension and retain Lumen's legacy behavior.

| Host behavior | Latency | Quality |
| --- | --- | --- |
| NVENC preset/tuning | P1, ultra-low-latency | P5, high-quality |
| Multipass | Disabled | Quarter-resolution |
| Adaptive quantization | Disabled | Enabled |
| Packet pacing | Immediate | Stable |
| Ordinary/recovery FEC | 0% / 10% | 10% / 20% |

These are current defaults, not universal recommendations. Explicit advanced
NVENC or FEC settings can override parts of the profile. Record the effective
settings when comparing runs.

Umbra additionally uses a one-frame compressed queue, two decoder submissions,
and immediate presentation in Latency mode; Quality uses a two-frame queue,
five submissions, and display-linked presentation. Latency removes the legacy
Moonlight input path's deliberate one-millisecond mouse/stylus batching wait.
Quality and Legacy retain that wait. Packet ordering and reliable ENet input
delivery are unchanged in every mode.

Codec selection, HDR, and YUV 4:4:4 are explicit preferences. A mode does not
silently enable or replace them.

### Latency mode

Use Latency mode when the objective is to minimize queued work:

- Match the stream FPS to a refresh rate the host and client can sustain.
- Select a hardware codec explicitly, then compare its measured p99 encode and
  decode time on the same matrix.
- Keep the bitrate below the path's stable capacity; excess bitrate increases
  queueing and recovery cost even on a fast link.
- Avoid display-driver overrides such as Fast Sync unless an A/B measurement on
  the exact system proves an improvement. Driver settings can add pacing or
  conflict with capture.

Latency mode may permit tearing when immediate presentation is selected. It
does not claim zero milliseconds and cannot remove display scanout time.

### Quality mode

Use Quality mode when stable pacing and compression quality take priority:

- Enable 10-bit, HDR, or 4:4:4 explicitly only when the complete
  encoder/decoder/display tuple is proven and bandwidth is sufficient.
- Use a bitrate that the path sustains without loss or persistent queues.
- Keep V-Sync/display-linked pacing enabled for tear-free output.
- Do not treat HDR signaling as proof of correct tone mapping or color volume.

The default Quality profile is rate-controlled and can show compression
artifacts. The separate `codec-lossless-required` request disables incompatible
encoder tools and fails closed when the exact tuple is unproven. It preserves
the selected YUV encoder-input samples; it does not prove lossless capture,
RGB-to-YUV conversion, chroma conversion, display color management, or scanout.

## Network tests

Use `iperf3` to characterize sustained throughput, jitter, and loss, but do not
run it concurrently with a latency benchmark. Ping and RTT are diagnostics, not
a processing-latency correction. Input travels to the host and the resulting
changed frame travels back on different legs; subtracting a summary RTT from a
latency percentile is invalid.

For causally watermarked traces, compute both schema fields per event:

```text
combined_network_transit_residual_ms <- summarize per event:
    observed_input_to_present_submit_ns
  - client_input_to_send_ns
  - host_receive_to_video_send_ns
  - client_video_receive_to_present_submit_ns

host_client_processing_residual_ms <- summarize per event:
    client_input_to_send_ns
  + host_receive_to_video_send_ns
  + client_video_receive_to_present_submit_ns
```

The first field is the combined uplink and downlink; the second is the measured
host-plus-client component. Neither produces one-way latency or physical input-to-photon.
WAN/cellular runs belong to a separate matrix and cannot qualify a LAN target.

## Measurement limits

- Use monotonic clocks for durations.
- Correlate host and client records with exact run, trace, mode, and protocol
  identifiers.
- Compute both raw-event values before percentiles; never subtract percentile
  summaries.
- Report p50, p95, p99, sample count, omissions, and unavailable evidence.
- Measure input-to-photon with a synchronized physical input and optical rig.

Portable tests and CI can validate queue bounds and policy selection. They do
not validate an RTX 4060 driver path, VDD behavior, HDR fidelity, scanout, or a
latency target.

<div class="section_buttons">

| Previous | Next |
|:--|--:|
| [Guides](guides.md) | [API](api.md) |

</div>

<details style="display: none;">
  <summary></summary>
  [TOC]
</details>
