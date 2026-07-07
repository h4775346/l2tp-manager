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

trap 'echo -e "${RED}❌ OVPN all-in-one install FAILED at line $LINENO. Fix the error above and re-run.${NC}" >&2' ERR

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
echo -e "${BLUE}   OpenVPN (TCP) - All-in-One Installer${NC}"
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

echo -e "${YELLOW}Starting OpenVPN all-in-one installation...${NC}"
echo -e "${YELLOW}This coexists with L2TP — if the L2TP installer already ran on this box,${NC}"
echo -e "${YELLOW}both VPNs share the same user panel and /etc/ppp/chap-secrets.${NC}"
echo ""

# Install the OpenVPN server. NOTE: ovpn-install.sh already installs the web
# management interface at its end, so we don't call sas4-install.sh again here.
echo -e "${YELLOW}Installing OpenVPN server + web interface...${NC}"
run_remote https://raw.githubusercontent.com/h4775346/l2tp-manager/master/ovpn-install.sh

# Restart services to apply all changes.
echo -e "${YELLOW}Restarting services...${NC}"
systemctl restart openvpn@server
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

# Read back the OVPN port that ovpn-install.sh recorded (defaults to 8443).
OVPN_PORT=8443
if [ -f /etc/l2tp-manager/vpn.conf ]; then
    OVPN_PORT=$(grep -oP '^OVPN_PORT=\K.*' /etc/l2tp-manager/vpn.conf 2>/dev/null || echo 8443)
fi

echo -e "${BLUE}Access your VPN Manager panel:${NC}"
echo -e "  HTTP : http://${SERVER_IP}:8090/l2tp-manager/"
echo -e "  HTTPS: https://${SERVER_IP}:8099/l2tp-manager/"
echo ""
echo -e "${YELLOW}Default Credentials:${NC}"
echo -e "  Username: admin"
echo -e "  Password: change@me (Please change this immediately)"
echo ""
echo -e "${BLUE}MikroTik OVPN client one-liner (cert-less, RouterOS 7):${NC}"
echo -e "  /interface ovpn-client add name=ovpn-sas connect-to=${SERVER_IP} port=${OVPN_PORT} \\"
echo -e "    protocol=tcp user=<panel-user> password=<panel-pass> certificate=none auth=sha1 \\"
echo -e "    cipher=aes256-cbc verify-server-certificate=no add-default-route=no disabled=no"
echo -e "  ${YELLOW}(RouterOS 6: use cipher=aes256)${NC}"
echo ""
echo -e "${GREEN}Enjoy your OpenVPN server — managed from the same panel as L2TP!${NC}"
