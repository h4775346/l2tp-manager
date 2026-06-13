#!/bin/bash

# Stop on first error so a failed sub-installer can't leave a half-built server
# that still prints "Installation Complete".
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

trap 'echo -e "${RED}❌ All-in-one install FAILED at line $LINENO. Fix the error above and re-run.${NC}" >&2' ERR

# Download a remote installer to a temp file and run it, failing if the download
# fails (piping curl straight into bash hides download errors and runs partial
# scripts when the connection drops mid-transfer).
run_remote() {
    local url="$1" tmp
    tmp="$(mktemp)"
    if ! curl -fsSL "$url" -o "$tmp"; then
        rm -f "$tmp"
        echo -e "${RED}Failed to download: $url${NC}" >&2
        return 1
    fi
    bash "$tmp"
    local rc=$?
    rm -f "$tmp"
    return $rc
}

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   L2TP Manager - All-in-One Installer${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${BLUE}                    By Abanoub              ${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   echo -e "${YELLOW}Please run with sudo: sudo $0${NC}"
   exit 1
fi

echo -e "${YELLOW}Starting all-in-one installation...${NC}"

# Install the L2TP server. NOTE: sas4-l2tp-full-installer.sh already installs the
# web management interface at its end, so we don't call sas4-install.sh again here.
echo -e "${YELLOW}Installing L2TP server + web interface...${NC}"
run_remote https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-l2tp-full-installer.sh

# Install the per-user routing system
echo -e "${YELLOW}Installing per-user routing system...${NC}"
run_remote https://raw.githubusercontent.com/h4775346/l2tp-manager/master/install-l2tp-per-user-routing.sh

# Restart services to apply all changes (handle both strongswan unit names)
echo -e "${YELLOW}Restarting services...${NC}"
if systemctl list-unit-files | grep -q '^strongswan-starter\.service'; then
    systemctl restart strongswan-starter
else
    systemctl restart strongswan
fi
systemctl restart xl2tpd
systemctl reload apache2 2>/dev/null || true

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    # Fallback: try to get IP from default route interface
    SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -1)
fi
if [ -z "$SERVER_IP" ]; then
    # Final fallback: try to get from ip addr
    SERVER_IP=$(ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="your-server-ip"
fi

echo -e "${BLUE}Access your L2TP Manager:${NC}"
echo -e "  HTTP : http://${SERVER_IP}:8090/l2tp-manager/"
echo -e "  HTTPS: https://${SERVER_IP}:8099/l2tp-manager/"
echo ""
echo -e "${YELLOW}Default Credentials:${NC}"
echo -e "  Username: admin"
echo -e "  Password: change@me (Please change this immediately)"
echo ""
echo -e "${GREEN}Enjoy your L2TP Manager with per-user routing!${NC}"
