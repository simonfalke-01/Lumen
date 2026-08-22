# Getting Started

On Windows AMD64, the recommended method for running Lumen is to use the installer included in the
[latest release][latest-release]. Other platforms currently require a source build or independently maintained package.

[Pre-releases](https://github.com/simonfalke-01/Lumen/releases) are also available. These should be considered beta,
and release artifacts may be missing when merging changes on a faster cadence.

## Binaries

This fork currently publishes Windows AMD64 MSI and ZIP artifacts. Versioned assets are available on the
[release page][latest-release].

> [!NOTE]
> Some third party packages also exist.
> See [Third Party Packages](third_party_packages.md) for more information.
> No support will be provided for third party packages!

## Install

### Other platforms

Lumen currently publishes no fork-owned FreeBSD, Linux, macOS, Docker, Flatpak, Homebrew, or community-repository
artifacts. Build those platforms from source using [Building](building.md), or use community packaging with the
understanding that it is independently maintained and may still use the upstream Sunshine identity.

### Windows

> [!WARNING]
> Lumen has its own installer and service identity and will not replace an official Sunshine installation. When
> Sunshine is detected, the installer can copy its configuration without deleting the source, but the two hosts cannot
> run at the same time because they use the same GameStream ports. Stop or uninstall Sunshine before starting Lumen.

#### Installer (recommended)

> [!CAUTION]
> The msi installer is preferred moving forward. Before using a different type of installer, you should manually
> uninstall the previous installation.

1. Download and install based on your architecture:

   | Architecture          | Installer pattern                                      |
   |-----------------------|--------------------------------------------------------|
   | AMD64/x64 (Intel/AMD) | `Lumen-<version>-Windows-AMD64-installer.msi`          |

> [!TIP]
> Installer logs can be found in the following directory:
> `%%TEMP%/Lumen/logs/install/`

The Windows 11 x64 installer offers the optional **Virtual Keyboard and Mouse** driver feature. It is not selected by
default. Lumen uses `windows_input_backend = auto` by default, which prefers the driver when it is installed,
compatible, and accessible to `LumenService`; otherwise, Lumen uses the Windows `SendInput` backend and records
the reason in the log. Deselect the feature to install without a bundled driver.

> [!IMPORTANT]
> Each Lumen Windows installer carries the exact Virtual HID certificate used for its bundled driver. Upgrades replace
> only Lumen's recorded prior thumbprint after the MSI transaction commits. Deselect Virtual HID and use `SendInput` on
> systems where driver installation is blocked.

> [!NOTE]
> Only the service account (`SYSTEM`) can probe the exact Virtual HID ABI or submit Virtual HID input. Launching
> Lumen directly uses `SendInput`, even when it is run as Administrator. Unicode text also continues to use
> `SendInput` while Virtual HID handles normal keyboard and mouse input.

To install without the bundled driver from the command line, set the MSI property to `0`:

```bat
msiexec /i Lumen-<version>-Windows-AMD64-installer.msi LUMEN_INSTALL_VHID=0
```

Use `LUMEN_INSTALL_VHID=1` to explicitly select the feature during a silent install. Deselecting the feature removes an
existing Lumen Virtual HID driver but does not change Lumen's configuration. For a SendInput-only deployment, also
set `windows_input_backend = sendinput` in Lumen's configuration.

In Virtual HID mode, Windows controls the repeat cadence for held keys. The `key_repeat_delay` and
`key_repeat_frequency` settings apply when Lumen uses the `SendInput` fallback.

> [!CAUTION]
> You should carefully select or unselect the options you want to install. Do not blindly install or
> enable features.

To uninstall, find Lumen in the list <a href="ms-settings:installed-apps">here</a> and select "Uninstall" from the
overflow menu. Different versions of Windows may provide slightly different steps for uninstall.

#### Standalone (lite version)

> [!WARNING]
> By using this package instead of the installer, performance will be reduced. This package is not
> recommended for most users. No support will be provided!

The lite package does not install the Lumen Virtual HID driver. With the default `auto` setting, it can use an existing
compatible driver only when Lumen runs through `LumenService`; set `windows_input_backend = sendinput` to force a
SendInput-only setup.

1. Download and extract based on your architecture:

   | Architecture          | Archive pattern                              |
   |-----------------------|----------------------------------------------|
   | AMD64/x64 (Intel/AMD) | `Lumen-<version>-Windows-AMD64-lite.zip`     |

2. Open command prompt as administrator
3. Firewall rules

   Install:
   ```bash
   cd /d {path to extracted directory}
   scripts/add-firewall-rule.bat
   ```

   Uninstall:
   ```bash
   cd /d {path to extracted directory}
   scripts/delete-firewall-rule.bat
   ```

4. Windows service

   Install:
   ```bash
   cd /d {path to extracted directory}
   scripts/install-service.bat
   scripts/autostart-service.bat
   ```

   Uninstall:
   ```bash
   cd /d {path to extracted directory}
   scripts/uninstall-service.bat
   ```

## Initial Setup
After installation, some initial setup is required.

The FreeBSD, Linux, and macOS notes below apply only to source builds or independently maintained packages.

### FreeBSD

#### Virtual Input Devices

> [!IMPORTANT]
> To use virtual input devices (keyboard, mouse, gamepads), you must add your user to the `input` group.

The installation process creates the `input` group and configures permissions for `/dev/uinput`.
To allow your user to create virtual input devices, run:

```bash
pw groupmod input -m $USER
```

After adding yourself to the group, log out and log back in for the changes to take effect.

### Linux

#### Services

**Start once**
```bash
systemctl --user start app-io.github.simonfalke.Lumen
```

**Start on boot**
```bash
systemctl --user --now enable app-io.github.simonfalke.Lumen
```

> [!NOTE]
> The service is named `app-io.github.simonfalke.Lumen` for XDG Desktop Portal compatibility and is also aliased
> to `lumen.service` for convenience.

### macOS
The first time you start Lumen, you will be asked to grant access to screen recording and your microphone.

Lumen supports native system audio capture on macOS 14.0 (Sonoma) and newer via Apple’s Audio Tap API.
To use it, simply leave the **Audio Sink** setting blank.

If you prefer to manage your own loopback device, you can still use
[Soundflower](https://github.com/mattingalls/Soundflower) or
[BlackHole](https://github.com/ExistentialAudio/BlackHole)
and enter its device name in the [audio_sink](configuration.md#audio_sink) field.

> [!NOTE]
> Command Keys are not forwarded by Moonlight. Right Option-Key is mapped to CMD-Key.

> [!CAUTION]
> Gamepads are not currently supported.

### Windows
In order for virtual gamepads to work, you must install ViGEmBus. You can do this from the troubleshooting tab
in the web UI, as long as you are running Lumen as a service or as an administrator. After installation, it is
recommended to restart your computer.

![ViGEmBus Installation](images/vigembus-installer.png)

## Usage

### Basic usage
If Lumen is not installed/running as a service, then start Lumen with the following command, unless a start
command is listed in the specified package [install](#install) instructions above.

> [!NOTE]
> A service is a process that runs in the background. This is the default when installing Lumen from the
> Windows installer. Running multiple instances of Lumen is not advised.

```bash
lumen
```

### Specify config file
```bash
lumen <directory of conf file>/lumen.conf
```

> [!NOTE]
> This step is optional, you do not need to specify a config file.
> If no config file is entered, the default location will be used.
> The configuration file specified will be created if it doesn't exist.

### Start Lumen over SSH (Linux/X11)
Assuming you are already logged into the host, you can use this command

```bash
ssh <user>@<ip_address> 'export DISPLAY=:0; lumen'
```

If you are logged into the host with only a tty (teletypewriter), you can use `startx` to start the X server prior to
executing Lumen. You nay need to add `sleep` between `startx` and `lumen` to allow more time for the display to
be ready.

```bash
ssh <user>@<ip_address> 'startx &; export DISPLAY=:0; lumen'
```

> [!TIP]
> You could also use the `~/.bash_profile` or `~/.bashrc` files to set up the `DISPLAY` variable.

See the project [Discussions](https://github.com/simonfalke-01/Lumen/discussions) for community headless-host setups.

### Configuration

Lumen is configured via the web ui, which is available on [https://localhost:47990](https://localhost:47990)
by default. You may replace *localhost* with your internal ip address.

> [!NOTE]
> Lumen generates a local HTTPS certificate on first use. Add it to your browser's trust store if required.

> [!CAUTION]
> If running for the first time, make sure to note the username and password that you created.

1. Change the web-ui to your desired theme, using the dropdown menu in the navbar.
   ![Theme Selection](images/split-themes.png)
2. Add games and applications.
   ![Applications](images/applications.png)
3. Adjust any configuration settings as needed. You can search for options in the search bar.
   ![Configuration](images/configuration-search.png)
4. Find Moonlight clients and other tools for Lumen in the `Featured Apps` tab.
   ![Featured Apps](images/featured-apps.png)
5. In Moonlight, you may need to add the PC manually.
6. When Moonlight requests for you insert the pin:

   - Login to the web-ui
   - Go to "PIN" in the Navbar
   - Type in your PIN and press `Enter`, and enter a name of your choosing for the device.
     You should get a Success Message!
   - In Moonlight, select one of the Applications listed

7. If you run into issues, logs are available in the `Troubleshooting` tab.
   You can navigate through each warning/error message for clues to the issue.
   ![Logs](images/troubleshooting-logs.png)

### Arguments
To get a list of available arguments, run the following command.

@tabs{
   @tab{ General | ```bash
      lumen --help
      ```}
}

### Shortcuts
All shortcuts start with `Ctrl+Alt+Shift`, just like Moonlight.

* `Ctrl+Alt+Shift+N`: Hide/Unhide the cursor (This may be useful for Remote Desktop Mode for Moonlight)
* `Ctrl+Alt+Shift+F1/F12`: Switch to different monitor for Streaming

### Application List
* Applications should be configured via the web UI
* A basic understanding of working directories and commands is required
* You can use Environment variables in place of values
* `$(HOME)` will be replaced by the value of `$HOME`
* `$$` will be replaced by `$`, e.g. `$$(HOME)` will be become `$(HOME)`
* `env` - Adds or overwrites Environment variables for the commands/applications run by Lumen.
  This can only be changed by modifying the `apps.json` file directly.

### Considerations
* On Windows, Lumen uses the Desktop Duplication API which only supports capturing from the GPU used for display.
  If you want to capture and encode on the eGPU, connect a display or HDMI dummy display dongle to it and run the games
  on that display.
* When an application is started, if there is an application already running, it will be terminated.
* If any of the prep-commands fail, starting the application is aborted.
* When the application has been shutdown, the stream shuts down as well.

  * For example, if you attempt to run `steam` as a `cmd` instead of `detached` the stream will immediately fail.
    This is due to the method in which the steam process is executed. Other applications may behave similarly.
  * This does not apply to `detached` applications.

* The "Desktop" app works the same as any other application except it has no commands. It does not start an application,
  instead it simply starts a stream. If you removed it and would like to get it back, just add a new application with
  the name "Desktop" and "desktop.png" as the image path.
* For the Linux flatpak you must prepend commands with `flatpak-spawn --host`.
* If inputs (mouse, keyboard, gamepads...) aren't working after connecting:

  * On FreeBSD/Linux, add the user running lumen to the `input` group.

* The FreeBSD version of Lumen is missing some features that are present on Linux.
  The following are known limitations.

  * Only X11 and Wayland capture are supported
  * DualSense/DS5 emulation is not available due to missing uhid features


### HDR Support
Streaming HDR content is officially supported on Windows hosts and experimentally supported for Linux hosts.

* General HDR support information and requirements:

  * HDR must be activated in the host OS, which may require an HDR-capable display or EDID emulator dongle
    connected to your host PC.
  * You must also enable the HDR option in your Moonlight client settings, otherwise the stream will be SDR
    (and probably overexposed if your host is HDR).
  * A good HDR experience relies on proper HDR display calibration both in the OS and in game. HDR calibration can
    differ significantly between client and host displays.
  * You may also need to tune the brightness slider or HDR calibration options in game to the different HDR brightness
    capabilities of your client's display.
  * Some GPUs video encoders can produce lower image quality or encoding performance when streaming in HDR compared
    to SDR.

Additional information:

@tabs{
  @tab{ Windows |
  - HDR streaming is supported for Intel, AMD, and NVIDIA GPUs that support encoding HEVC Main 10 or AV1 10-bit profiles.
  - We recommend calibrating the display by streaming the Windows HDR Calibration app to your client device and saving an HDR calibration profile to use while streaming.
  - Older games that use NVIDIA-specific NVAPI HDR rather than native Windows HDR support may not display properly in HDR.
  }

@tab{ Linux |
  - HDR streaming is supported for Intel and AMD GPUs that support encoding HEVC Main 10 or AV1 10-bit profiles using VAAPI.
  - The KMS capture backend is required for HDR capture. Other capture methods, like NvFBC or X11, do not support HDR.
  - You will need a desktop environment with a compositor that supports HDR rendering, such as Gamescope or KDE Plasma 6.

  @seealso{[Arch wiki on HDR Support for Linux](https://wiki.archlinux.org/title/HDR_monitor_support) and
  [Reddit Guide for HDR Support for AMD GPUs](https://www.reddit.com/r/linux_gaming/comments/10m2gyx/guide_alpha_test_hdr_on_linux)}
  }
}

### Tutorials and Guides
Tutorial videos are available [here](https://www.youtube.com/playlist?list=PLMYr5_xSeuXAbhxYHz86hA1eCDugoxXY0).

Guides are available [here](guides.md).

@admonition{Community! |
Tutorials and Guides are community generated. Want to contribute? Reach out to us on our discord server.}

<div class="section_buttons">

| Previous                 |                      Next |
|:-------------------------|--------------------------:|
| [Overview](../README.md) | [Changelog](changelog.md) |

</div>

<details style="display: none;">
  <summary></summary>
  [TOC]
</details>

[latest-release]: https://github.com/simonfalke-01/Lumen/releases/latest
