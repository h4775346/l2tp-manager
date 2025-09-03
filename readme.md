# 🚀 L2TP Manager - Modern L2TP/IPSec VPN Management Solution

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

A powerful, web-based management interface for L2TP/IPSec VPN servers with advanced per-user routing capabilities. Simplify your VPN user management with an intuitive dashboard and granular network control.

## 🌟 Key Features

- **🔐 Secure Web Interface** - Manage users through HTTPS with modern authentication
- **👥 User Management** - Add, delete, and configure L2TP users with ease
- **🛣️ Per-User Routing** - Assign custom routes to individual VPN users
- **⚡ One-Click Installation** - Deploy everything with a single command
- **📱 Responsive Design** - Works on desktop and mobile devices
- **🔄 Automatic Route Application** - Routes applied when users connect
- **🛡️ Duplicate Prevention** - Smart detection to prevent route conflicts

## 🚀 Quick Start - One Line Installation

Install L2TP server, web management panel, and per-user routing system in one command:

```bash
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/all-in-one-installer.sh | sudo bash
```

## 🛠️ Manual Installation Options

### Full L2TP Server + GUI Installation
⚠️ **Warning**: This will remove all existing L2TP configurations and users
```bash
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-l2tp-full-installer.sh | sudo bash
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