# L2TP Per-User Routing System

This document describes the per-user routing system implemented for the L2TP Manager.

## Overview

The per-user routing system allows administrators to define custom routing rules that are applied when L2TP users connect to the system. Each user (identified by their peer IP) can have specific routes configured that will be automatically applied when their PPP interface comes up.

## Components

### 1. Installation Script
- **File**: `install-l2tp-per-user-routing.sh`
- Installs all components of the routing system

### 2. CLI Tool
- **File**: `/usr/local/sbin/l2tp-routectl`
- **Purpose**: Manage per-user routes from the command line
- **Commands**:
  - `add --peer <peer_ip> --dst <CIDR> [--gw <ip>] [--dev <iface>]`
  - `del --peer <peer_ip> --dst <CIDR>`
  - `list [--peer <peer_ip>]`
  - `apply [--peer <peer_ip>]`

### 3. Hooks
- **ip-up hook**: `/etc/ppp/ip-up.d/l2tp-routes` - Applies routes when PPP interface comes up
- **ip-down hook**: `/etc/ppp/ip-down.d/l2tp-routes` - Cleans up routes when PPP interface goes down

### 4. Systemd Service
- **Service**: `route-l2tp-apply-all.service` - Applies all routes at system startup
- **Timer**: `route-l2tp-apply-all.timer` - Periodically applies routes

### 5. Configuration
- **Routes storage**: `/etc/l2tp-manager/routes.d/`
- **Sysctl config**: `/etc/sysctl.d/99-l2tp-routing.conf` - Enables IP forwarding and configures rp_filter
- **Sudoers**: `/etc/sudoers.d/l2tp-routectl` - Allows www-data to execute the CLI tool

## PHP Integration

The web interface has been extended with a "Manage Routes" section that allows administrators to:
- Add routes for specific users
- View all configured routes
- Apply routes manually
- Refresh the routes display

## Installation

1. Run the installation script:
   ```bash
   sudo ./install-l2tp-per-user-routing.sh
   ```

2. The script will:
   - Create all necessary directories and files
   - Install the CLI tool
   - Set up the PPP hooks
   - Configure systemd services
   - Set up sysctl parameters
   - Configure sudoers permissions

## Usage

### Command Line
```bash
# Add a route
sudo /usr/local/sbin/l2tp-routectl add --peer 10.255.10.11 --dst 192.168.1.0/24

# Add a route with custom gateway
sudo /usr/local/sbin/l2tp-routectl add --peer 10.255.10.11 --dst 192.168.1.0/24 --gw 10.255.10.1

# List all routes
sudo /usr/local/sbin/l2tp-routectl list

# List routes for specific peer
sudo /usr/local/sbin/l2tp-routectl list --peer 10.255.10.11

# Apply routes for specific peer
sudo /usr/local/sbin/l2tp-routectl apply --peer 10.255.10.11

# Delete a route
sudo /usr/local/sbin/l2tp-routectl del --peer 10.255.10.11 --dst 192.168.1.0/24
```

### Web Interface
1. Log into the L2TP Manager web interface
2. Click on "Manage Routes" button
3. Select a user from the dropdown
4. Enter the destination network in CIDR notation
5. Optionally specify a gateway (defaults to the peer IP)
6. Click "Add Route"
7. Routes are automatically applied when the user connects

## Persistence

- Routes are stored in `/etc/l2tp-manager/routes.d/<PEER_IP>.routes` files
- Routes are automatically reapplied when:
  - The user reconnects (via ip-up hook)
  - The system reboots (via systemd service)
  - Manually triggered through the web interface or CLI

## Security

- The web interface uses sudo to execute the CLI tool
- Permissions are restricted through the sudoers configuration
- Only the www-data user can execute the routing commands without a password