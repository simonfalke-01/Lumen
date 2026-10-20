# GameStream Migration

NVIDIA discontinued the GameStream host feature. Lumen implements a compatible
host protocol for GameStream clients, but compatibility does not establish equal
latency, quality, HDR behavior, or application discovery on every system.

## Move applications

Add each application in the admin panel's **Apps** page, or edit `apps.json`
directly. Lumen reads application commands, working directories, and images
from `apps.json`.

Keep a backup of the source configuration and test Desktop first. Application
launch commands, permissions, service-account access, HDR, and display selection
can differ from NVIDIA GameStream.

## Existing GameStream clients

Unmodified GameStream clients can pair with and stream from Lumen through the
legacy GameStream path. Lumen-specific Latency/Quality and modern protocol
extensions are optional; a client that does not send them retains legacy
behavior.

Legacy PIN pairing must be completed from loopback or a private/trusted LAN.
Lumen rejects public/WAN `/pair` traffic before allocating pairing state because
the four-digit GameStream transcript is unsuitable for Internet exposure.

## Internet streaming

Remove or disable the GameStream Internet Hosting Tool before enabling Lumen's
own UPnP or manual forwarding. Running two hosts or two port-mapping tools can
produce conflicts. Prefer a trusted VPN or authenticated tunnel when practical.

Do not expose Lumen's Web UI or management API directly to the public Internet.
Legacy GameStream streaming requires multiple ports.

## Known migration differences

- Lumen does not reproduce NVIDIA's automatic application catalog exactly.
- Host-side game-setting changes depend on explicit application configuration.
- Encoder, HDR, input, audio, and display behavior require validation on the
  target host and client.

<div class="section_buttons">

| Previous | Next |
|:--|--:|
| [Third-Party Packages](third_party_packages.md) | [Legal](legal.md) |

</div>

<details style="display: none;">
  <summary></summary>
  [TOC]
</details>
