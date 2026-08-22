#!/bin/sh

# User Service
systemctl --user stop app-io.github.simonfalke.Lumen
rm "$HOME/.config/systemd/user/app-io.github.simonfalke.Lumen.service"
systemctl --user daemon-reload
echo "Lumen User Service has been removed."

# Remove rules
flatpak-spawn --host pkexec sh -c "rm /etc/modules-load.d/60-lumen.conf"
flatpak-spawn --host pkexec sh -c "rm /etc/udev/rules.d/60-lumen.rules"
echo "Input rules removed. Restart computer to take effect."
