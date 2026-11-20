## Linux implants

### Executive Summary

We identified a Linux x86-64 implant, submitted from China, with extensive capabilities and multiple persistence mechanisms, currently scoring 0 detections on VirusTotal.

The implant uses multiple techniques to maintain persistence, ranging from scheduled tasks and service configuration to shell initialization and dynamic linker manipulation.

**Key Capabilities:**
- **Command Execution:** Remote shell access through PTY (forkpty).
- **Pivoting:** Integrated SOCKS proxying and TCP port forwarding.
- **File Operations:** File transfer and filesystem manipulation.
- **Process Management:** Process enumeration, termination, and background job management.
- **Surveillance:** Screenshot capture via DISPLAY.

**Persistence Mechanisms:**
- **Scheduled Execution:** Crontab.
- **Service-Based:** systemd and init.d.
- **Shell Initialization:** profile.d and bashrc.
- **Desktop Persistence:** XDG autostart and MOTD.
- **System-Level:** udev and ld.so.preload.

**Privilege and Credential Access:**
- PAM backdoor with a hardcoded password.
- Username and password logging.
- SUID shell copy for privilege escalation.

Use our THOR Scanner to detect the threat in your environment.

### Files (SHA-256)
| SHA-256 |
| ------- |
| `f751099ced6bb6b97525b8e0a7ee4a21e00cff410de37251bcc4b51c8fdd367c` |
| `f5c7523c96211c80c891f4c3bde3668955d34da7988df86096f82950fbd78f5c` |
| `ac6e566adedc55b521963c3c7ef8f79bd7745b55d3dc3666cdbd4413dccba713` |
| `156ced00c6f4d50d69be9351bd8d3e380e7247ed7f7761cb7ff008d114b28b36` |
| `c6a2d78ee7cd74bd02a833277f2fd955afef8f3d45d6c228ce912986d78ebf29` |

### Files (Paths)

  - `/etc/systemd/system/system-updated.service`
  - `/etc/ld.so.preload`
  - `/etc/pam.d/.common-auth.bak`
  - `/var/log/.auth_debug`
  - `/var/lib/.dbus-session`
  - `/var/lib/.dbus-session/state`
  - `/var/lib/dbus/.session-init`
  - `/var/lock/.dbus-session`
  - `/tmp/agent`
  - `/etc/profile.d/locale-check.sh`
  - `/etc/profile.d/glib-defaults.sh`
  - `/etc/profile.d/dconf-session.sh`
  - `/etc/profile.d/bash-extra-completion.sh`
  - `/etc/udev/rules.d/70-usb-power.rules`
  - `/etc/udev/rules.d/85-network-device.rules`
  - `/etc/udev/rules.d/75-display-backlight.rules`
  - `/etc/udev/rules.d/80-input-device.rules`
  - `/lib/x86_64-linux-gnu/security/pam_cap_audit.so`
  - `/lib/x86_64-linux-gnu/security/pam_systemd_home.so`
  - `/lib/x86_64-linux-gnu/security/pam_access_extra.so`
  - `/lib/x86_64-linux-gnu/security/pam_polkit_agent.so`
  - `org.freedesktop.PolicyKit1.desktop`
  - `org.freedesktop.secrets.desktop`
  - `org.gnome.SettingsDaemon.desktop`
  - `org.freedesktop.Tracker3.desktop`
  - `_helper.so`
