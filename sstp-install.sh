#!/bin/bash

# ==============================================================================
# SAS4 SSTP Server - Full Installation Script
# ==============================================================================
# Python sstpd for MikroTik SSTP clients, authenticating against the SAME
# /etc/ppp/chap-secrets the L2TP/OVPN panel maintains. Coexists with L2TP and
# OpenVPN: this script MUST NOT touch xl2tpd, strongswan, ipsec.*, or openvpn.
#
# Listens TCP 4433 (override: SSTP_PORT=...). Shared panel is /l2tp-manager/.
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

trap 'echo -e "${RED}❌ Installation FAILED at line $LINENO. The server may be half-configured — re-run this script after fixing the error above.${NC}" >&2' ERR

if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo -e "${RED}This script needs root. Run with: sudo $0${NC}" >&2
    exit 1
fi

SSTP_PORT="${SSTP_PORT:-4433}"

echo -e "${CYAN}"
echo "                    By Abanoub                   "
echo -e "${NC}"
echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}   SSTP VPN Server - Full Installation${NC}"
echo -e "${BLUE}==============================================${NC}"
echo ""
echo -e "${YELLOW}ℹ️  Installs sstpd (TCP ${SSTP_PORT}) against /etc/ppp/chap-secrets.${NC}"
echo -e "${YELLOW}   Coexists with L2TP + OpenVPN. Does not touch them.${NC}"
echo ""

set_vpn_conf() {
    local k="$1" v="$2" f="/etc/l2tp-manager/vpn.conf"
    mkdir -p /etc/l2tp-manager
    touch "$f"
    if grep -q "^${k}=" "$f"; then
        sed -i "s|^${k}=.*|${k}=${v}|" "$f"
    else
        echo "${k}=${v}" >> "$f"
    fi
    chown root:www-data "$f" 2>/dev/null || true
    chmod 640 "$f"
}

WAN_IF="$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || true)"
if [[ -z "$WAN_IF" ]]; then
    WAN_IF="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true)"
fi
if [[ -z "$WAN_IF" ]]; then
    echo -e "${RED}Could not auto-detect the uplink interface. Set WAN_IF=<iface> before running.${NC}" >&2
    exit 1
fi
echo -e "${CYAN}🌐 Detected uplink interface: ${GREEN}${WAN_IF}${NC}"

SERVER_IP="$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' | head -1 || true)"
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(hostname -I | awk '{print $1}')"
fi
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="$(ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1)"
fi
if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP="your-server-ip"
fi
echo -e "${CYAN}🌐 Detected server IP: ${GREEN}${SERVER_IP}${NC}"
echo ""

echo -e "${CYAN}🔄 Updating system packages...${NC}"
sudo apt update -y

echo -e "${CYAN}📦 Installing system dependencies...${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo -E apt install -y ppp openssl iptables-persistent curl

echo -e "${GREEN}✅ System dependencies installed${NC}"
echo ""

echo -e "${CYAN}📦 Installing uv...${NC}"
export PATH="$HOME/.local/bin:/root/.local/bin:$PATH"
if command -v uv &>/dev/null; then
    echo -e "${YELLOW}↪ uv already installed${NC}"
else
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:/root/.local/bin:$PATH"
fi
echo ""

echo -e "${CYAN}🐍 Installing Python 3.12 via uv...${NC}"
uv python install 3.12
echo -e "${GREEN}✅ Python 3.12 ready${NC}"
echo ""

echo -e "${CYAN}📦 Installing sstp-server into /opt/sstpd-venv...${NC}"
if [[ -x /opt/sstpd-venv/bin/sstpd ]]; then
    echo -e "${YELLOW}↪ Existing sstpd venv found — keeping it.${NC}"
else
    rm -rf /opt/sstpd-venv
    uv venv --python 3.12 --seed /opt/sstpd-venv
    /opt/sstpd-venv/bin/pip install sstp-server
fi
if [[ ! -x /opt/sstpd-venv/bin/sstpd ]]; then
    echo -e "${RED}sstp-server binary not found after install — aborting.${NC}" >&2
    exit 1
fi
echo -e "${GREEN}✅ sstpd installed${NC}"
echo ""

echo -e "${CYAN}🔐 SSL certificate (/root/cert.pem)...${NC}"
if [[ -f /root/cert.pem ]] && [[ -f /root/key.pem ]]; then
    echo -e "${YELLOW}↪ Existing certificate found — keeping it.${NC}"
else
    openssl req -x509 -newkey rsa:2048 \
        -keyout /root/key.pem \
        -out /root/cert.pem \
        -days 3650 -nodes \
        -subj "/CN=${SERVER_IP}"
    echo -e "${GREEN}✅ SSL certificate generated (CN=${SERVER_IP})${NC}"
fi
echo ""

echo -e "${CYAN}⚙️  Writing /etc/ppp/options.sstpd...${NC}"
sudo bash -c 'cat > /etc/ppp/options.sstpd <<EOF
name sstpd
require-mschap-v2
nologfd
nodefaultroute
ms-dns 8.8.8.8
ms-dns 8.8.4.4
auth
debug
lock
proxyarp
EOF'
echo -e "${GREEN}✅ options.sstpd written${NC}"
echo ""

echo -e "${CYAN}🔑 Ensuring chap-secrets exists (shared with L2TP/OVPN)...${NC}"
if [[ -f /etc/ppp/chap-secrets ]] && grep -qvE '^\s*#|^\s*$' /etc/ppp/chap-secrets 2>/dev/null; then
    echo -e "${YELLOW}↪ Existing chap-secrets found with users — keeping it untouched.${NC}"
else
    sudo mkdir -p /etc/ppp
    sudo bash -c 'cat > /etc/ppp/chap-secrets <<EOF
# Secrets for authentication using CHAP
# client    server    secret           IP addresses
user1       *         ikasgfiuasgf     10.255.10.11
user2       *         segheregtyeb     10.255.10.12
user3       *         ba35rtyegbas     10.255.10.13
user4       *         rtyasergbrge     10.255.10.14
user5       *         vwehyaevwgfw     10.255.10.15
user6       *         bwrvwefbtbwf     10.255.10.16
user7       *         wlihfqbeuihf     10.255.10.17
EOF'
fi
sudo chown root:www-data /etc/ppp/chap-secrets
sudo chmod 660 /etc/ppp/chap-secrets
echo -e "${GREEN}✅ chap-secrets ready${NC}"
echo ""

echo -e "${CYAN}🌐 Enabling IP forwarding...${NC}"
sudo bash -c 'echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-sstp-forward.conf'
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo -e "${GREEN}✅ IP forwarding enabled${NC}"
echo ""

echo -e "${CYAN}📝 Writing sstpd.service (port ${SSTP_PORT})...${NC}"
printf '%s\n' \
    '[Unit]' \
    'Description=SSTP VPN Server' \
    'After=network.target' \
    '' \
    '[Service]' \
    "ExecStart=/opt/sstpd-venv/bin/sstpd -l 0.0.0.0 -p ${SSTP_PORT} -c /root/cert.pem -k /root/key.pem --local 10.200.10.1 --remote 10.200.0.0/16 --pppd-config /etc/ppp/options.sstpd -v 5 --ciphers DEFAULT:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:@SECLEVEL=1" \
    'Restart=always' \
    'RestartSec=3' \
    'User=root' \
    '' \
    '[Install]' \
    'WantedBy=multi-user.target' \
    | sudo tee /etc/systemd/system/sstpd.service >/dev/null

sudo systemctl daemon-reload
sudo systemctl enable sstpd >/dev/null 2>&1 || true
echo -e "${GREEN}✅ systemd unit written${NC}"
echo ""

echo -e "${CYAN}🔥 Firewall (TCP ${SSTP_PORT} + NAT 10.200.0.0/16)...${NC}"
sudo iptables -C INPUT -p tcp --dport "$SSTP_PORT" -j ACCEPT 2>/dev/null || \
    sudo iptables -A INPUT -p tcp --dport "$SSTP_PORT" -j ACCEPT
sudo iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -o "$WAN_IF" -j MASQUERADE
sudo iptables -C FORWARD -p tcp --syn -s 10.200.0.0/16 -j TCPMSS --set-mss 1356 2>/dev/null || \
    sudo iptables -A FORWARD -p tcp --syn -s 10.200.0.0/16 -j TCPMSS --set-mss 1356
sudo mkdir -p /etc/iptables
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
sudo netfilter-persistent save 2>/dev/null || true
echo -e "${GREEN}✅ Firewall persisted${NC}"
echo ""

echo -e "${CYAN}🔄 Starting sstpd...${NC}"
sudo systemctl restart sstpd
sleep 2
if sudo ss -tlnp 2>/dev/null | grep -q ":${SSTP_PORT}"; then
    echo -e "${GREEN}✅ sstpd is listening on TCP ${SSTP_PORT}${NC}"
else
    echo -e "${RED}❌ sstpd is NOT listening on TCP ${SSTP_PORT}. Check 'journalctl -u sstpd'.${NC}" >&2
    exit 1
fi
echo ""

echo -e "${CYAN}📝 Recording SSTP config in /etc/l2tp-manager/vpn.conf...${NC}"
set_vpn_conf SERVER_IP    "$SERVER_IP"
set_vpn_conf COA_PORT     1700
set_vpn_conf SSTP_ENABLED 1
set_vpn_conf SSTP_PORT    "$SSTP_PORT"
set_vpn_conf SSTP_RADIUS  10.200.10.1
echo -e "${GREEN}✅ vpn.conf updated${NC}"
echo ""

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   SSTP VPN Server Installation Complete!${NC}"
echo -e "${GREEN}==============================================${NC}"
echo ""

# Shared panel (l2tp-manager). Skip if already present so we never wipe
# an existing L2TP/OVPN dashboard (sas4-install.sh rm -rf's the tree).
if [[ "${SKIP_GUI:-0}" == "1" ]] || [[ -d /opt/sas4/site/l2tp-manager ]]; then
    echo -e "${YELLOW}↪ Shared panel already at /opt/sas4/site/l2tp-manager (or SKIP_GUI=1) — not reinstalling.${NC}"
else
    echo -e "${BLUE}🚀 Installing shared Web Management Interface (/l2tp-manager/)...${NC}"
    TMP_GUI="$(mktemp)"
    if curl -fsSL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-install.sh -o "$TMP_GUI"; then
        sudo bash "$TMP_GUI"
        rm -f "$TMP_GUI"
    else
        rm -f "$TMP_GUI"
        echo -e "${RED}❌ Failed to download the web interface installer. SSTP server is up; re-run sas4-install.sh later.${NC}" >&2
        exit 1
    fi
fi
