#!/bin/bash

# Stop on first error so a failed sub-installer can't leave a half-built server
# that still prints "Installation Complete".
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

trap 'echo -e "${RED}❌ SSTP all-in-one install FAILED at line $LINENO. Fix the error above and re-run.${NC}" >&2' ERR

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
echo -e "${BLUE}   SSTP (TCP) - All-in-One Installer${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${BLUE}                    By Abanoub              ${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo -e "${YELLOW}Please run with sudo: sudo $0${NC}"
   exit 1
fi

echo -e "${YELLOW}Starting SSTP all-in-one installation...${NC}"
echo -e "${YELLOW}This coexists with L2TP + OpenVPN — shared panel and chap-secrets.${NC}"
echo ""

echo -e "${YELLOW}Installing SSTP server + shared web interface...${NC}"
run_remote https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sstp-install.sh

echo -e "${YELLOW}Restarting services...${NC}"
systemctl restart sstpd
systemctl reload apache2 2>/dev/null || true

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   Installation Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

SERVER_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -1)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="your-server-ip"
fi

SSTP_PORT=4433
if [ -f /etc/l2tp-manager/vpn.conf ]; then
    SSTP_PORT=$(grep -oP '^SSTP_PORT=\K.*' /etc/l2tp-manager/vpn.conf 2>/dev/null || echo 4433)
fi

echo -e "${BLUE}Access your VPN Manager panel:${NC}"
echo -e "  HTTP : http://${SERVER_IP}:8090/l2tp-manager/"
echo -e "  HTTPS: https://${SERVER_IP}:8099/l2tp-manager/"
echo ""
echo -e "${YELLOW}Default Credentials:${NC}"
echo -e "  Username: admin"
echo -e "  Password: change@me (Please change this immediately)"
echo ""
echo -e "${BLUE}MikroTik SSTP client one-liner:${NC}"
echo -e "  /interface sstp-client add name=sstp-sas connect-to=${SERVER_IP} port=${SSTP_PORT} \\"
echo -e "    user=<panel-user> password=<panel-pass> verify-server-certificate=no \\"
echo -e "    add-default-route=no disabled=no"
echo ""
echo -e "${GREEN}Enjoy your SSTP server — managed from the same panel as L2TP/OVPN!${NC}"
