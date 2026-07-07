#!/bin/bash

# ==============================================================================
# 🚀 SAS4 L2TP/IPSec Server - Full Installation Script
# ==============================================================================

# Fail fast: stop on any error, unset variable, or failed pipe stage so a
# partial install can never masquerade as a successful one.
set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Report the line that failed instead of dying silently.
trap 'echo -e "${RED}❌ Installation FAILED at line $LINENO. The server may be half-configured — re-run this script after fixing the error above.${NC}" >&2' ERR

# Upsert a single key into the shared dual-VPN state file. Both the L2TP and the
# OVPN installers write here key-by-key so running one never clobbers the other's
# keys — the l2tp-manager panel reads this to know which VPNs are live.
set_vpn_conf() {   # usage: set_vpn_conf KEY VALUE
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

# Require root (the script uses sudo throughout, but bail early if sudo is missing).
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo -e "${RED}This script needs root. Run with: sudo $0${NC}" >&2
    exit 1
fi

# Artwork
echo -e "${CYAN}"
echo " █████╗ ██████╗  █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗██████╗ "
echo "██╔══██╗██╔══██╗██╔══██╗████╗  ██║██╔═══██╗██║   ██║██╔══██╗"
echo "███████║██████╔╝███████║██╔██╗ ██║██║   ██║██║   ██║██████╔╝"
echo "██╔══██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██╗"
echo "██║  ██║██████╔╝██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██████╔╝"
echo "╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═════╝ "
echo "                                                    "
echo " █████╗  ██████╗ ███╗   ██╗██████╗  ██████╗ ██╗   ██╗"
echo "██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔═══██╗╚██╗ ██╔╝"
echo "███████║██║   ██║██╔██╗ ██║██████╔╝██║   ██║ ╚████╔╝ "
echo "██╔══██║██║   ██║██║╚██╗██║██╔══██╗██║   ██║  ╚██╔╝  "
echo "██║  ██║╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝   ██║   "
echo "╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝    ╚═╝   "
echo "                                                    "
echo "                    By Abanoub                   "
echo -e "${NC}"

echo -e "${BLUE}==============================================${NC}"
echo -e "${BLUE}   L2TP/IPSec Server - Full Installation${NC}"
echo -e "${BLUE}==============================================${NC}"
echo ""

echo -e "${YELLOW}⚠️  WARNING: This will remove all existing L2TP configurations and users${NC}"
echo -e "${YELLOW}   Please backup any important data before proceeding!${NC}"
echo ""

# ---------------------------------------------------------------------------
# Detect the WAN/uplink interface instead of assuming eth0. On modern Ubuntu
# the NIC is often ens3/enp1s0/etc, and a hardcoded eth0 silently breaks NAT
# (clients connect but get no internet).
# ---------------------------------------------------------------------------
WAN_IF="$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1 || true)"
if [[ -z "$WAN_IF" ]]; then
    WAN_IF="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true)"
fi
if [[ -z "$WAN_IF" ]]; then
    echo -e "${RED}Could not auto-detect the uplink interface. Set it manually with WAN_IF=<iface> before running.${NC}" >&2
    exit 1
fi
echo -e "${CYAN}🌐 Detected uplink interface: ${GREEN}${WAN_IF}${NC}"

# IPsec pre-shared key. Override with: L2TP_PSK="yourkey" sudo -E bash installer.sh
# NOTE: the historical default is "123456" — every public install shares it, so
# clients keep working but anyone can guess it. Set L2TP_PSK in production.
PSK="${L2TP_PSK:-123456}"
echo ""

# Update the system
echo -e "${CYAN}🔄 Updating system packages...${NC}"
sudo apt update -y

# Install required packages (iptables-persistent makes firewall rules survive reboot)
echo -e "${CYAN}📦 Installing L2TP/IPSec packages...${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo -E apt install -y strongswan xl2tpd iptables-persistent

echo -e "${GREEN}✅ Required packages installed${NC}"
echo ""

# Configure strongSwan
echo -e "${CYAN}⚙️  Configuring strongSwan...${NC}"
sudo bash -c 'cat > /etc/ipsec.conf <<EOF
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    authby=secret
    keyexchange=ikev1
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!

conn L2TP-PSK
    keyexchange=ikev1
    left=%any
    leftprotoport=17/1701
    leftfirewall=yes
    right=%any
    rightprotoport=17/%any
    auto=add
EOF'

echo -e "${GREEN}✅ strongSwan configured${NC}"
echo ""

# Configure IPsec secrets
echo -e "${CYAN}🔑 Configuring IPsec secrets...${NC}"
sudo bash -c "cat > /etc/ipsec.secrets <<EOF
: PSK \"${PSK}\"
EOF"
sudo chmod 600 /etc/ipsec.secrets
if [[ "$PSK" == "123456" ]]; then
    echo -e "${YELLOW}⚠️  Using the default IPsec PSK '123456'. Set L2TP_PSK to a strong value in production.${NC}"
fi

echo -e "${GREEN}✅ IPsec secrets configured${NC}"
echo ""

# Configure xl2tpd
echo -e "${CYAN}⚙️  Configuring xl2tpd...${NC}"
sudo bash -c 'cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
ipsec saref = yes

[lns default]
ip range = 10.255.10.11-10.255.255.254
local ip = 10.255.10.10
require chap = yes
refuse pap = yes
require authentication = yes
name = L2TP-VPN
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF'

# Verify the LNS section actually landed — the package default is an all-commented
# sample with no [lns default], which makes xl2tpd reject every tunnel with
# "No Authorization". Fail loudly here rather than ship a dead server.
if ! grep -q '^\[lns default\]' /etc/xl2tpd/xl2tpd.conf; then
    echo -e "${RED}xl2tpd.conf is missing the [lns default] section — refusing to continue.${NC}" >&2
    exit 1
fi

echo -e "${GREEN}✅ xl2tpd configured${NC}"
echo ""

# Configure PPP
echo -e "${CYAN}⚙️  Configuring PPP options...${NC}"
sudo bash -c 'cat > /etc/ppp/options.xl2tpd <<EOF
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
auth
mtu 1200
mru 1200
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
EOF'

echo -e "${GREEN}✅ PPP options configured${NC}"
echo ""

# Configure chap-secrets (preserve existing users on re-run — the l2tp-manager
# panel writes real users here; clobbering would log everyone out).
echo -e "${CYAN}🔑 Configuring default users...${NC}"
if [[ -f /etc/ppp/chap-secrets ]] && grep -qvE '^\s*#|^\s*$' /etc/ppp/chap-secrets 2>/dev/null; then
    echo -e "${YELLOW}↪ Existing chap-secrets found with users — keeping it untouched.${NC}"
else
    sudo bash -c 'cat > /etc/ppp/chap-secrets <<EOF
# Secrets for authentication using CHAP
# client    server    secret    IP addresses
user1       *         ikasgfiuasgf  10.255.10.11
user2       *         segheregtyeb  10.255.10.12
user3       *         ba35rtyegbas  10.255.10.13
user4       *         rtyasergbrge  10.255.10.14
user5       *         vwehyaevwgfw  10.255.10.15
user6       *         bwrvwefbtbwf  10.255.10.16
user7       *         wlihfqbeuihf  10.255.10.17
EOF'
fi

# Ensure the l2tp-manager panel (Apache, runs as www-data) can read AND write
# chap-secrets. Owner root so pppd reads it; group www-data so the panel does too;
# mode 660. NOT 600 — that locks out the panel: readUsers() fails so every user
# vanishes from the UI and every new user collides on 10.255.10.11. NOT world-
# readable 666 either. Run unconditionally (covers both the preserved and the
# freshly-created file).
sudo chown root:www-data /etc/ppp/chap-secrets
sudo chmod 660 /etc/ppp/chap-secrets

echo -e "${GREEN}✅ Default users configured${NC}"
echo ""

# Enable IP forwarding (drop-in guarantees it regardless of how sysctl.conf is
# formatted, and persists across reboots).
echo -e "${CYAN}🌐 Enabling IP forwarding...${NC}"
sudo bash -c 'echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-l2tp-forward.conf'
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo -e "${GREEN}✅ IP forwarding enabled${NC}"
echo ""

# Configure firewall rules (idempotent: -C checks before -A so re-runs don't
# stack duplicate rules).
echo -e "${CYAN}🔥 Configuring firewall rules...${NC}"
sudo iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
sudo iptables -C FORWARD -p tcp --syn -s 10.255.0.0/16 -j TCPMSS --set-mss 1356 2>/dev/null || \
    sudo iptables -A FORWARD -p tcp --syn -s 10.255.0.0/16 -j TCPMSS --set-mss 1356

# Persist for reboot via netfilter-persistent (installed above). Also keep the
# legacy path for compatibility with anything that reads /etc/iptables.rules.
sudo mkdir -p /etc/iptables
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
sudo sh -c "iptables-save > /etc/iptables.rules"
sudo netfilter-persistent save 2>/dev/null || true

echo -e "${GREEN}✅ Firewall rules configured (uplink: ${WAN_IF}, persisted for reboot)${NC}"
echo ""

# Restart services. strongSwan's unit is "strongswan-starter" on Ubuntu 18.04
# and "strongswan" on some builds — restart whichever exists.
echo -e "${CYAN}🔄 Restarting L2TP services...${NC}"
if systemctl list-unit-files | grep -q '^strongswan-starter\.service'; then
    sudo systemctl restart strongswan-starter
else
    sudo systemctl restart strongswan
fi
sudo systemctl enable xl2tpd >/dev/null 2>&1 || true
sudo systemctl restart xl2tpd

echo -e "${GREEN}✅ L2TP services restarted${NC}"
echo ""

# Verify service status (|| true so a non-zero status code doesn't trip set -e)
echo -e "${CYAN}🔍 Checking service status...${NC}"
sudo systemctl status xl2tpd --no-pager || true

# Hard verification: xl2tpd must actually be listening on UDP 1701, otherwise
# the install is broken no matter what the steps above printed.
echo ""
echo -e "${CYAN}🔍 Verifying xl2tpd is listening on UDP 1701...${NC}"
sleep 2
if sudo ss -lunp 2>/dev/null | grep -q ':1701'; then
    echo -e "${GREEN}✅ xl2tpd is listening on UDP 1701${NC}"
else
    echo -e "${RED}❌ xl2tpd is NOT listening on UDP 1701 — install is incomplete. Check 'journalctl -u xl2tpd'.${NC}" >&2
    exit 1
fi

# Record this L2TP install into the shared dual-VPN state file so the panel (and
# any OVPN install that ran, or runs later) knows L2TP is live. Detect the public
# server IP the same way all-in-one-installer.sh does.
echo ""
echo -e "${CYAN}📝 Recording L2TP config in /etc/l2tp-manager/vpn.conf...${NC}"
SERVER_IP=$(hostname -I | awk '{print $1}')
[ -z "$SERVER_IP" ] && SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
[ -z "$SERVER_IP" ] && SERVER_IP=$(ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1)
[ -z "$SERVER_IP" ] && SERVER_IP="your-server-ip"

set_vpn_conf SERVER_IP    "$SERVER_IP"
set_vpn_conf COA_PORT     1700
set_vpn_conf L2TP_ENABLED 1
set_vpn_conf L2TP_PSK     "$PSK"
set_vpn_conf L2TP_RADIUS  10.255.10.10
echo -e "${GREEN}📝 Recorded L2TP config in /etc/l2tp-manager/vpn.conf${NC}"

echo ""
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   L2TP/IPSec Server Installation Complete!${NC}"
echo -e "${GREEN}==============================================${NC}"
echo ""

echo -e "${BLUE}🚀 Now installing Web Management Interface...${NC}"
TMP_GUI="$(mktemp)"
if curl -fsSL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-install.sh -o "$TMP_GUI"; then
    sudo bash "$TMP_GUI"
    rm -f "$TMP_GUI"
else
    rm -f "$TMP_GUI"
    echo -e "${RED}❌ Failed to download the web interface installer. L2TP server is up; re-run sas4-install.sh later.${NC}" >&2
    exit 1
fi
