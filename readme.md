# 🚀 L2TP Manager - Modern L2TP/IPSec VPN Management Solution

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

A powerful, web-based management interface for VPN servers with advanced per-user routing capabilities. Simplify your VPN user management with an intuitive dashboard and granular network control.

**Now dual-VPN:** the same panel manages **both L2TP/IPSec and OpenVPN-over-TCP** from one place (`/l2tp-manager`), backed by **one shared user store** (`/etc/ppp/chap-secrets`). Install either or both VPNs on the same server — in any order, repeatedly — without breaking the other.

## 🌟 Key Features

- **🔐 Secure Web Interface** - Manage users through HTTPS with modern authentication
- **🔀 Dual VPN** - L2TP/IPSec **and** OpenVPN-over-TCP from a single panel
- **👥 Shared User Store** - One `/etc/ppp/chap-secrets` serves both L2TP and OVPN
- **🛣️ Per-User Routing** - Assign custom routes to individual VPN users
- **⚡ One-Click Installation** - Deploy everything with a single command
- **📱 Responsive Design** - Works on desktop and mobile devices
- **🔄 Automatic Route Application** - Routes applied when users connect
- **🛡️ Duplicate Prevention** - Smart detection to prevent route conflicts
- **📋 MikroTik Scripts** - Per-user buttons generate ready-to-paste MikroTik config

## 🚀 Quick Start - One Line Installation

Two all-in-one installers. Each sets up its VPN plus the shared web panel and per-user routing. They can run on the **same server, in any order, and repeatedly** — each upserts its own state key-by-key, so they never clobber each other. Run one, the other, or both.

**L2TP/IPSec:**
```bash
curl -fsSL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/all-in-one-installer.sh | sudo bash
```

**OpenVPN (TCP):**
```bash
curl -fsSL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/ovpn-all-in-one-installer.sh | sudo bash
```

## 🔀 Dual VPN: L2TP + OpenVPN

The panel and user store are shared; only the transport differs. You can offer L2TP where it's allowed and OpenVPN-over-TCP where UDP/L2TP is blocked — same users, same dashboard.

### Coexistence design
- **Separate IP pools** so the two VPNs never fight over addresses:
  - **L2TP** — pool `10.255.0.0/16`, local gateway `10.255.10.10`
  - **OVPN** — pool `10.10.30.0/24`, local gateway `10.10.30.1`
- **One shared user store** — both VPNs authenticate against `/etc/ppp/chap-secrets`. Add a user once; they can connect over either transport.
- **Shared state file** `/etc/l2tp-manager/vpn.conf` — each installer **upserts keys one at a time** (never rewrites the whole file), so running the OVPN installer keeps the L2TP keys and vice-versa. The panel reads this file to know which VPNs are live and only shows buttons for the installed ones.

### OpenVPN specifics
- **Cert-less auth** — username/password only, validated against the same `/etc/ppp/chap-secrets` (no client certificates to distribute).
- **TCP port 8443** by default — override at install time with `OVPN_PORT=...` (e.g. `OVPN_PORT=1194 sudo -E bash ovpn-all-in-one-installer.sh`).
- **MikroTik-compatible crypto** — AES-256-CBC / SHA1, so RouterOS clients connect out of the box.

### MikroTik scripts from the panel
Each user row has **L2TP** and **OVPN** buttons that generate ready-to-paste MikroTik scripts (interface add + RADIUS setup). Only the VPN types actually installed on the server are offered.

## 🛠️ Manual Installation Options

### Full L2TP Server + GUI Installation
⚠️ **Warning**: This will remove all existing L2TP configurations and users
```bash
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-l2tp-full-installer.sh | sudo bash
```
This installer also records the L2TP keys into the shared `/etc/l2tp-manager/vpn.conf` (see [Dual VPN](#-dual-vpn-l2tp--openvpn)), preserving any OVPN keys already present.

### Full OpenVPN Server + GUI Installation
```bash
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/ovpn-all-in-one-installer.sh | sudo bash
```

### GUI Only Installation
Install only the web management interface:
```bash
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-install.sh | sudo bash
```

### Per-User Routing System (Optional)
Add advanced routing capabilities:
```bash
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/install-l2tp-per-user-routing.sh | sudo bash

```

## 🔧 Access Your Dashboard

After installation, access the management interface:

- **HTTP**:  `http://your-server-ip:8090/l2tp-manager/`
- **HTTPS**: `https://your-server-ip:8099/l2tp-manager/`

### Default Credentials
- **Username**: `admin`
- **Password**: `change@me` *(Please change this immediately)*

## 🎯 Per-User Routing System

The advanced routing system allows you to configure custom network routes that are automatically applied when L2TP users connect to your VPN.

### Features:
- 🔄 **Automatic Route Application** - Routes applied when PPP interfaces come up
- 🧹 **Clean Route Removal** - Routes automatically removed when users disconnect
- 🌐 **Flexible Configuration** - Specify custom gateways and destinations
- 📊 **Web Interface Management** - Add/remove routes through the dashboard
- 🛡️ **Duplicate Prevention** - Smart detection prevents conflicting routes

### How It Works:
1. Add routes through the web interface
2. Routes are stored in `/etc/l2tp-manager/routes.d/`
3. When users connect, routes are automatically applied to their PPP interface
4. When users disconnect, routes are automatically cleaned up

## 📋 System Requirements

- **OS**: Ubuntu/Debian-based Linux distribution
- **Memory**: 512MB RAM minimum
- **Disk Space**: 100MB free space
- **Network**: Internet access for installation
- **Privileges**: sudo access required

## 🔒 Security Notes

- Change the default admin password immediately after installation
- The HTTPS certificate is self-signed by default
- Firewall rules are configured automatically
- All sensitive operations require sudo privileges

## 🆘 Troubleshooting

### Common Issues:
1. **Installation fails**: Ensure you have sudo privileges and internet access
2. **Cannot access dashboard**: Check if Apache is running (`systemctl status apache2`)
3. **Routes not applying**: Verify PPP interfaces are coming up correctly
4. **Permission errors**: Ensure `/etc/ppp/chap-secrets` is writable

### Useful Commands:
```bash
# Check L2TP service status
sudo systemctl status strongswan
sudo systemctl status xl2tpd

# View current routes
ip route show

# List configured user routes
sudo /usr/local/sbin/l2tp-routectl list
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Support

For issues, questions, or contributions, please [open an issue](https://github.com/h4775346/l2tp-manager/issues) on GitHub.