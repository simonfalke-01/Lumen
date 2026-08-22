#!/bin/sh

# User Service
mkdir -p ~/.config/systemd/user
cp "/app/share/lumen/systemd/user/app-io.github.simonfalke.Lumen.service" "$HOME/.config/systemd/user/app-io.github.simonfalke.Lumen.service"
echo "Lumen User Service has been installed."
echo "Use [systemctl --user enable app-io.github.simonfalke.Lumen] once to autostart Lumen on login."

# Load uhid (DS5 emulation)
UHID=$(cat /app/share/lumen/modules-load.d/60-lumen.conf)
echo "Enabling DS5 emulation."
flatpak-spawn --host pkexec sh -c "echo '$UHID' > /etc/modules-load.d/60-lumen.conf"
flatpak-spawn --host pkexec modprobe uhid

# Udev rule
UDEV=$(cat /app/share/lumen/udev/rules.d/60-lumen.rules)
echo "Configuring mouse permission."
flatpak-spawn --host pkexec sh -c "echo '$UDEV' > /etc/udev/rules.d/60-lumen.rules"
echo "Restart computer for mouse permission to take effect."
