#!/bin/bash

# Triple VPN all-in-one: L2TP/IPsec + OpenVPN/TCP + SSTP/TCP + shared GUI
# + per-user routing. Each sub-installer upserts only its own vpn.conf keys.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

trap 'echo -e "${RED}❌ Triple-VPN install FAILED at line $LINENO. Fix the error above and re-run.${NC}" >&2' ERR

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
echo -e "${BLUE}   Triple VPN - All-in-One Installer${NC}"
echo -e "${BLUE}   L2TP + OpenVPN + SSTP + GUI + routing${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${BLUE}                    By Abanoub              ${NC}"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo -e "${YELLOW}Please run with sudo: sudo $0${NC}"
   exit 1
fi

BASE=https://raw.githubusercontent.com/h4775346/l2tp-manager/master

echo -e "${YELLOW}[1/4] L2TP/IPsec + shared web panel...${NC}"
run_remote "$BASE/sas4-l2tp-full-installer.sh"

echo -e "${YELLOW}[2/4] Per-user routing...${NC}"
run_remote "$BASE/install-l2tp-per-user-routing.sh"

echo -e "${YELLOW}[3/4] OpenVPN (TCP) — panel already installed, SKIP_GUI=1...${NC}"
export SKIP_GUI=1
run_remote "$BASE/ovpn-install.sh"

echo -e "${YELLOW}[4/4] SSTP (TCP) — panel already installed, SKIP_GUI=1...${NC}"
export SKIP_GUI=1
run_remote "$BASE/sstp-install.sh"

echo -e "${YELLOW}Restarting services...${NC}"
if systemctl list-unit-files | grep -q '^strongswan-starter\.service'; then
    systemctl restart strongswan-starter || true
else
    systemctl restart strongswan || true
fi
systemctl restart xl2tpd || true
systemctl restart openvpn@server || true
systemctl restart sstpd || true
systemctl reload apache2 2>/dev/null || true

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   Triple VPN Installation Complete!${NC}"
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

OVPN_PORT=8443
SSTP_PORT=4433
if [ -f /etc/l2tp-manager/vpn.conf ]; then
    OVPN_PORT=$(grep -oP '^OVPN_PORT=\K.*' /etc/l2tp-manager/vpn.conf 2>/dev/null || echo 8443)
    SSTP_PORT=$(grep -oP '^SSTP_PORT=\K.*' /etc/l2tp-manager/vpn.conf 2>/dev/null || echo 4433)
fi

echo -e "${BLUE}Panel:${NC}"
echo -e "  HTTP : http://${SERVER_IP}:8090/l2tp-manager/"
echo -e "  HTTPS: https://${SERVER_IP}:8099/l2tp-manager/"
echo -e "  User: admin   Pass: change@me  (change this)"
echo ""
echo -e "${BLUE}Listen:${NC}"
echo -e "  L2TP  UDP 1701 + IPsec 500/4500"
echo -e "  OVPN  TCP ${OVPN_PORT}"
echo -e "  SSTP  TCP ${SSTP_PORT}"
echo ""
echo -e "${BLUE}MikroTik (user1 from the panel):${NC}"
echo -e "  /interface l2tp-client add name=l2tp-sas connect-to=${SERVER_IP} user=user1 password=<chap> use-ipsec=yes ipsec-secret=<psk> add-default-route=no"
echo -e "  /interface ovpn-client add name=ovpn-sas connect-to=${SERVER_IP} port=${OVPN_PORT} protocol=tcp user=user1 password=<chap> certificate=none auth=sha1 cipher=aes256-cbc verify-server-certificate=no add-default-route=no"
echo -e "  /interface sstp-client add name=sstp-sas connect-to=${SERVER_IP} port=${SSTP_PORT} user=user1 password=<chap> verify-server-certificate=no add-default-route=no"
echo ""
echo -e "${GREEN}All three VPNs share /etc/ppp/chap-secrets and the same GUI.${NC}"
