# Troubleshooting

## General

### Forgotten Credentials
Reset the Web UI credentials from the matching installation type.

General installation:

```bash
lumen --creds {new-username} {new-password}
```

AppImage:

```bash
./lumen.AppImage --creds {new-username} {new-password}
```

Flatpak:

```bash
flatpak run --command=lumen io.github.simonfalke.Lumen --creds {new-username} {new-password}
```

> [!TIP]
> Remember to replace `{new-username}` and `{new-password}` with your new credentials.
> Do not include the curly braces.

### Unusual Mouse Behavior
If you experience unusual mouse behavior, try attaching a physical mouse to the Lumen host.

### Web UI Access
Can't access the web UI?

1. Check firewall rules.

### Controller works on Steam but not in games
One trick might be to change Steam settings and check or uncheck the configuration to support Xbox/PlayStation
controllers and leave only support for Generic controllers.

Also, if you have many controllers already directly connected to the host, it might help to disable them so that the
Lumen-provided controller (connected to the guest) is the "first" one. In Linux this can be achieved on USB
devices by finding the device in `/sys/bus/usb/devices/` and writing `0` to the `authorized` file.

### Network performance test

For real-time game streaming the most important characteristic of the network
path between server and client is not pure bandwidth but rather stability and
consistency (low latency with low variance, minimal or no packet loss).

The network can be tested using the multi-platform tool [iPerf3](https://iperf.fr).

On the Lumen host `iperf3` is started in server mode:

```bash
iperf3 -s
```

On the client device iperf3 is asked to perform a 60-second UDP test in a reverse
direction (from server to client) at a given bitrate (e.g. 50 Mbps):

```bash
iperf3 -c {HostIpAddress} -t 60 -u -R -b 50M
```

Watch the output on the client for packet loss and jitter. Both should be close
to zero for a stable low-latency stream. There is no universal acceptable
percentage: codec, bitrate, FEC, frame rate, and client buffering change the
visible result. Compare the exact stream matrix and inspect p95/p99, not only an
average.

For Android clients use
[PingMaster](https://play.google.com/store/apps/details?id=com.appplanex.pingmasternetworktools).

For iOS clients use [HE.NET Network Tools](https://apps.apple.com/us/app/he-net-network-tools/id858241710).

If you are testing a remote connection (over the internet), you will need to
forward the port 5201 (TCP and UDP) from your host.

### Packet loss (Buffer overrun)
If the host PC (running Lumen) has a much faster connection to the network
than the slowest segment of the network path to the client device (running
Moonlight), massive packet loss can occur: Lumen emits its stream in bursts
every 16 ms (for 60 fps), but those bursts can't be passed on fast enough to the
client and must be buffered by one of the network devices inbetween. If the
bitrate is high enough, these buffers will overflow and data will be discarded.

This can easily happen if e.g., the host has a 2.5 Gbit/s connection and the
client only 1 Gbit/s or Wi-Fi. Similarly, a 1 Gbps host may be too fast for a
client having only a 100 Mbps interface.

As a workaround the transmission speed of the host NIC can be reduced: 1 Gbps
instead of 2.5 or 100 Mbps instead of 1 Gbps. A technically more advanced
solution would be to configure traffic shaping rules at the OS level, so that
only Lumen's traffic is slowed down.

Such a solution on Linux could look like that:

```bash
# 1) Remove existing qdisc (pfifo_fast)
sudo tc qdisc del dev <NIC> root

# 2) Add HTB root qdisc with default class 1:1
sudo tc qdisc add dev <NIC> root handle 1: htb default 1

# 3) Create class 1:1 for full 10 Gbit/s (all other traffic)
sudo tc class add dev <NIC> parent 1: classid 1:1 htb \
    rate 10000mbit ceil 10000mbit burst 32k

# 4) Create class 1:10 for Lumen game stream at 1 Gbit/s
sudo tc class add dev <NIC> parent 1: classid 1:10 htb \
    rate 1000mbit ceil 1000mbit burst 32k

# 5) Filter UDP source port 47998 into class 1:10
sudo tc filter add dev <NIC> protocol ip parent 1: prio 1 \
    u32 match ip protocol 17 0xff \
    match ip sport 47998 0xffff flowid 1:10
```

In that way only the Lumen traffic is limited by 1 Gbit. This is not persistent on reboots.
If you use a different port for the game stream, you need to adjust the last command.

Lumen versions > 0.23.1 include improved networking code that should
alleviate or even solve this issue (without reducing the NIC speed).

### Packet loss (MTU)
Although unlikely, some guests might work better with a lower
[MTU](https://en.wikipedia.org/wiki/Maximum_transmission_unit) from the host.
For example, an LG TV was found to have 30-60% packet loss when the host had MTU
set to 1500 and 1472, but 0% packet loss with a MTU of 1428 set in the network card
serving the stream (a Linux PC). It's unclear how that helped precisely, so it's a last
resort suggestion.

## Linux

### Hardware Encoders throttle/drop FPS during high GPU load
Capture methods (`wlgrab`) or encoders (`nvenc`, `vaapi`) that utilize EGL contexts may exhibit FPS drops
in conjunction with a Lumen installation that runs in a sandboxed or reduced permissions state
(Flatpak, AppImage, or when using Portal capture) due to the lack of active CAP_SYS_NICE process permissions
needed to set up high priority EGL contexts.

To check if you are affected by this issue, look out for this message in your Lumen log:
```
Warning: EGL: context priority set to HIGH but CAP_SYS_NICE capability is missing
```

> [!IMPORTANT]
> Switching to Vulkan encoding should resolve the issue for the majority of configurations, but refer to this
> table for recommended configurations (especially if Vulkan encoding is not supported on your system):
> | Desktop Environment | Vulkan Supported? | Recommended Lumen Install Type | Recommended Capture & Encoder Configuration       |
> |:--------------------|-------------------|-----------------------------------|--------------------------------------------------:|
> | KDE Plasma          | Yes               | Any                               | `portal` or `kwin` capture with `vulkan` encoding |
> | KDE Plasma          | No                | Non-Sandboxed                     | `kwin` capture with `vaapi`/`nvenc` encoding      |
> | GNOME / other       | Yes               | Any                               | `portal` capture with `vulkan` encoding           |
> | GNOME / other       | No                | Non-Sandboxed                     | `kms` capture with `vaapi`/`nvenc` encoding       |

### Hardware Encoding fails
Due to legal concerns, Mesa has disabled hardware decoding and encoding by default.

```txt
Error: Could not open codec [h264_vaapi]: Function not implemented
```

If you see the above error in the Lumen logs, compiling *Mesa* manually may be required. See the official Mesa3D
[Compiling and Installing](https://docs.mesa3d.org/install.html) documentation for instructions.

> [!IMPORTANT]
> You must re-enable the disabled encoders. You can do so by passing the following argument to the build
> system. You may also want to enable decoders, however, that is not required for Lumen and is not covered here.
> ```bash
> -Dvideo-codecs=h264enc,h265enc
> ```

> [!NOTE]
> Other build options are listed in the
> [meson options](https://gitlab.freedesktop.org/mesa/mesa/-/blob/main/meson_options.txt) file.

### Portal token issues
Portal capture requires you to manually approve Remote Desktop permissions via an on-screen prompt on the host.
This creates a portal token which is used to automaticaly reauthorize on subsequent reconnects, but under certain
circumstances (a Lumen crash, switching to another desktop environment, or if a monitor hotplug event occurs)
the portal token may become lost or invalid, necessitating manual re-approval of capture permissions.

Users of the KDE Plasma desktop can bypass this issue either by switching to `kwin` capture or setting the following
configuration to enable permanent capture autorization for Lumen via Portal capture:
```
flatpak permission-set kde-authorized remote-desktop io.github.simonfalke.Lumen yes
```
> [!NOTE]
> Although this configuration is plumbed through Flatpak, it will work with any supported Lumen installation type.

### Input not working
After installation, the `udev` rules need to be reloaded. Our post-install script tries to do this for you
automatically, but if it fails, you may need to restart your system.

If the input is still not working, you may need to add your user to the `input` group.

```bash
sudo usermod -aG input $USER
```

#### Multiseat

If you run multiple concurrent Wayland sessions on separate logind seats (e.g. `seat0`, `seat1`),
your compositor may ignore injected input unless Lumen's virtual devices are assigned to the correct seat.

Lumen determines its target seat from `XDG_SEAT`, which is typically set automatically by your display manager.
If needed, you can override it manually in your systemd service file or shell environment before starting Lumen.

When the seat is not `seat0`, Lumen appends the seat name to its virtual device names, for example:

- Keyboard passthrough (seat1)
- Lumen PS5 (virtual) pad (seat1)

Lumen creates two mouse devices: a relative one and an absolute one.

To assign Lumen's virtual devices to the correct seat, create this udev rules file
(/etc/udev/rules.d/72-lumen-virtual-seat.rules):
```udev
SUBSYSTEM=="input", KERNEL=="input*", ATTR{name}=="*(seat1)*", TAG+="seat", ENV{ID_SEAT}="seat1"
```

Then reload udev:

```bash
sudo udevadm control --reload-rules && sudo udevadm trigger -s input
```

### KMS Streaming fails
KMS screencasting requires elevated privileges which are not allowed for Flatpak or AppImage packages.
This means that you must install Lumen using the native package format of your distribution, if available.
KMS capture will soon be phased out in favour of XDG Portal Capture (which works with all package types).

### KMS Streaming; some windows flicker/disappear on KDE Plasma 6.5+
KWin's overlay support interferes with KMS capture. As of KWin 6.5 this is not yet set by default, but
for future versions that enables this by default, you may be able to disable again via a special
[environment variable](https://invent.kde.org/plasma/kwin/-/wikis/Environment-Variables#kwin_use_overlays):

```bash
export KWIN_USE_OVERLAYS=0
```

> [!NOTE]
> Disabling overlays will reduce KWin's rendering efficiency. Consider using XDG Portal Capture instead.

### KMS streaming fails on Nvidia GPUs
If KMS screen capture results in a black screen being streamed, you may need to
set the parameter `modeset=1` for Nvidia's kernel module. This can be done by
adding the following directive to the kernel command line:

```bash
nvidia_drm.modeset=1
```

Consult your distribution's documentation for details on how to do this. (Most
often grub is used to load the kernel and set its command line.)

### AMD encoding latency issues
If you notice unexpectedly high encoding latencies (e.g., in Moonlight's
performance overlay) or strong fluctuations thereof, your system's Mesa
libraries are outdated (<24.2). This is particularly problematic at higher
resolutions (4K).

Starting with Mesa-24.2, applications can request a
[low-latency mode](https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/30039)
by running them with a special
[environment variable](https://docs.mesa3d.org/envvars.html#envvar-AMD_DEBUG):
```bash
export AMD_DEBUG=lowlatencyenc
```
Lumen sets this variable automatically, no manual
configuration is needed.

To check whether low-latency mode is being used, one can watch the VCLK and DCLK
frequencies in amdgpu_top. Without this encoder tuning both clock frequencies
will fluctuate strongly, whereas with active low-latency encoding they will stay
high as long as the encoder is used.

### Gamescope compatibility
Some users have reported stuttering issues when streaming games running within Gamescope.

## macOS

### Dynamic session lookup failed
If you get this error:

> Dynamic session lookup supported but failed: launchd did not provide a socket path, verify that
> org.freedesktop.dbus-session.plist is loaded!

Try this.
```bash
launchctl load -w /Library/LaunchAgents/org.freedesktop.dbus-session.plist
```

## Windows

### Virtual keyboard or mouse is unavailable

With the default `windows_input_backend = auto`, Lumen uses the Lumen Virtual HID keyboard and mouse driver when it
is compatible and accessible to `LumenService`. Set `windows_input_backend = sendinput` to skip the driver probe and
always use SendInput.

Check the log in the web UI's `Troubleshooting` tab or at `config/lumen.log` in the Lumen installation directory.
Then inspect the Plug and Play topology from Command Prompt:

```bat
cd /d "%ProgramFiles%\Lumen"
tools\lumen-vhidctl.exe status --json
```

`status --json` does not require elevation. Its `state` is `installed`, `absent`, or `unhealthy`; it reports whether the
root device and expected HID collections are present and started. It does not prove that the service can use the exact
driver ABI. The current ABI requires exactly one keyboard, two mouse collections (relative and absolute), and one
Consumer Control collection.

The exact ABI check is separate:

```bat
tools\lumen-vhidctl.exe probe --json
```

`probe --json` must run as `SYSTEM`; an Administrator command prompt is not sufficient. Its `state` is `compatible`,
`absent`, `inaccessible`, or `incompatible`. Use the Lumen service log as the normal record of this service-only
probe.

If the helper reports that the driver is missing, incompatible, or unusable, rerun the Windows 11 x64 Lumen
installer and select repair. Installer and repair logs are stored in `%%TEMP%/Lumen/logs/install/`; uninstall logs
are stored in `%%TEMP%/Lumen/logs/uninstall/`. The helper is not included in standalone/lite packages.

Lumen Windows installers trust only the exact bundled driver certificate thumbprint. A committed upgrade removes only
the exact previously recorded Lumen signer. Use the optional SendInput-only installation when system policy blocks
Virtual HID.

> [!NOTE]
> A direct Lumen launch cannot access the Virtual HID report interface, even when run as Administrator. Run the
> installed `LumenService` to use Virtual HID. `SunshineService` belongs to the upstream product and is never used as
> a Lumen fallback. Standalone/lite builds use `SendInput` when no
> compatible, accessible driver is installed.

If the installed driver and application use incompatible protocol versions, keep both on the same Lumen release or
run installer repair. Uninstalling Lumen stops the service before removing the Virtual HID device and driver package.
Use Windows **Installed apps** to repair or uninstall Lumen; Windows may require a restart to finish
removing an in-use driver.

If initialization fails, or the first actual Virtual HID report is rejected, Lumen switches the whole backend to
SendInput. Once the driver accepts a report, Lumen does not mix per-event SendInput into the active Virtual HID session:
supported relative and absolute mouse input remains on Virtual HID, while unsupported keys, Consumer Control overflow,
and Unicode text are rejected. A later report failure fails closed and stops keyboard and mouse injection instead of
risking duplicate or stuck input. Disconnect Moonlight to trigger the input session's atomic reset-and-release
operation. A successful reset neutralizes and reclaims Virtual HID without replaying held state; a failed reset keeps
input fail closed. If disconnecting does not recover input, restart `LumenService` and review the failure before
reconnecting. Reboot Windows if the topology remains `unhealthy`, the installer reports that a reboot is required, or a
service restart does not recover the driver; then rerun repair if `status --json` is still not `installed`.

Look for one of these backend-selection messages in `lumen.log`:

```text
Windows keyboard and mouse backend: Lumen Virtual HID
Windows keyboard and mouse backend: SendInput fallback (stage=..., status=...)
Lumen Virtual HID failed closed (stage=..., status=...)
```

`SendInput` remains subject to Windows User Interface Privilege Isolation (UIPI). It may not control an application at
a higher integrity level, and Windows does not reliably identify UIPI as the reason an input call failed.

### Client microphone endpoint is unavailable

The optional client microphone feature requires the Windows installer's **Client Microphone Passthrough** component.
From the installed Lumen service context, the lifecycle helper verifies the exact root device, active capture
endpoint, and control ABI:

```bat
cd /d "%ProgramFiles%\Lumen"
tools\lumen-vmicctl.exe status --json
tools\lumen-vmicctl.exe probe --json
```

Healthy output reports one `ROOT\LumenVirtualMicrophone` root, one active `Lumen Virtual Microphone` capture endpoint,
and ABI state `compatible`. The control path is restricted to `LumenService`, so `probe` reports `inaccessible` from a
normal Administrator shell. Endpoint names are diagnostic only because Windows permits users to rename them. The
helper identifies the active capture endpoint through the exact `PKEY_DeviceInterface_FriendlyName` adapter identity
owned by the driver INF. Windows does not expose a usable `PKEY_Device_InstanceId` for this MMDevice endpoint.
Installation allows up to 30 seconds for asynchronous Core Audio endpoint materialization. A readiness failure reports
the root, device tree, endpoint and adapter names, and control ABI predicates independently. Repair the same Lumen
release if those predicates do not converge.

### No gamepad detected
First check the configured Windows backend and profile:

- `gamepad_backend = auto` uses ViGEm for explicit Xbox 360 plus Xbox/unknown automatic controllers, and Lumen Virtual
  HID for modern/generic explicit profiles plus PlayStation/Nintendo automatic controllers. An automatic Virtual HID
  creation failure may fall back to Xbox 360/ViGEm only before the device becomes visible, with the original failure
  logged.
- `gamepad_backend = vigem` accepts only `gamepad = x360`. Install ViGEmBus from the troubleshooting tab of the web UI.
- `gamepad_backend = virtualhid` rejects `gamepad = x360` without falling back. Install the **Lumen Virtual Input** MSI
  feature and choose `generic`, `xone`, `xseries`, `ds4`, `ds5`, or `switch`.

An explicit incompatible combination is reported instead of silently changing the selected profile or backend. The
Lumen Virtual HID control interface is intentionally available only to the Lumen service running as LocalSystem; an
`inaccessible` result from `lumen-vhidctl probe` in a normal Administrator shell is expected.

A LocalSystem `probe --json` reports protocol generation 3 as base ABI 2 plus dynamic-gamepad ABI 1. A different base
or gamepad ABI is incompatible; Lumen keeps the Xbox 360/ViGEm path available instead of sending modern reports to a
mismatched driver.

You can also manually install ViGEmBus from
[ViGEmBus releases](https://github.com/nefarius/ViGEmBus/releases/latest). You must use version 1.17 or newer.

After installation, it is recommended to restart your computer.

### Permission denied
Since Lumen runs as a service on Windows, it may not have the same level of access that your regular user account
has. You may get permission denied errors when attempting to launch a game or application from a non-system drive.

You will need to modify the security permissions on your disk. Ensure that user/principal SYSTEM has full
permissions on the disk.

### Stuttering
Return NVIDIA Control Panel overrides to application-controlled defaults before
investigating Lumen pacing. In particular, disable forced Fast Sync if it causes
stutter. Treat any driver override as an A/B experiment on the exact display and
stream matrix; it is not a general latency recommendation.

<div class="section_buttons">

| Previous      |                    Next |
|:--------------|------------------------:|
| [API](api.md) | [Building](building.md) |

</div>

<details style="display: none;">
  <summary></summary>
  [TOC]
</details>
