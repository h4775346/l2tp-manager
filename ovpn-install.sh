#!/bin/bash

# ==============================================================================
# 🚀 SAS4 OpenVPN (TCP) Server - Full Installation Script
# ==============================================================================
# Cert-less (username/password) OpenVPN server for MikroTik routers, authenticating
# against the SAME /etc/ppp/chap-secrets the L2TP manager panel maintains — so one
# panel manages both L2TP and OVPN users. Coexists with L2TP: this script MUST NOT
# touch xl2tpd, strongswan, ipsec.conf, ipsec.secrets, or xl2tpd.conf.

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

# Require root (the script uses sudo throughout, but bail early if sudo is missing).
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    echo -e "${RED}This script needs root. Run with: sudo $0${NC}" >&2
    exit 1
fi

# OpenVPN listen port. Override with: OVPN_PORT=1194 sudo -E bash ovpn-install.sh
OVPN_PORT="${OVPN_PORT:-8443}"

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
echo -e "${BLUE}   OpenVPN (TCP) Server - Full Installation${NC}"
echo -e "${BLUE}==============================================${NC}"
echo ""

echo -e "${YELLOW}ℹ️  This installs a cert-less OpenVPN server that authenticates against${NC}"
echo -e "${YELLOW}   /etc/ppp/chap-secrets. It coexists with L2TP and will NOT touch it.${NC}"
echo ""

# ---------------------------------------------------------------------------
# Coexistence contract with the L2TP installer. Write ONLY our own OVPN keys
# (+ SERVER_IP) into /etc/l2tp-manager/vpn.conf so the L2TP installer's keys
# survive. Never rewrite the whole file.
# ---------------------------------------------------------------------------
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
echo ""

# Detect the primary server IP (for the vpn.conf record and final instructions).
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7}' | head -1)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1)
fi
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="your-server-ip"
fi

# Update the system
echo -e "${CYAN}🔄 Updating system packages...${NC}"
sudo apt update -y

# Install required packages (iptables-persistent makes NAT rules survive reboot).
# NOTE: no easy-rsa — we build the PKI with plain openssl (see below) because
# Ubuntu 18.04 ships easy-rsa 2.x, which has no ./easyrsa or make-cadir wrapper.
echo -e "${CYAN}📦 Installing OpenVPN packages...${NC}"
export DEBIAN_FRONTEND=noninteractive
sudo -E apt install -y openvpn openssl iptables-persistent

echo -e "${GREEN}✅ Required packages installed${NC}"
echo ""

# ---------------------------------------------------------------------------
# Build the PKI (CA + server cert only — clients are cert-less). Done with
# plain openssl rather than easy-rsa: Ubuntu 18.04 (every SAS box) ships
# easy-rsa 2.x, which has no ./easyrsa or make-cadir wrapper, so the 3.x flow
# dies with "./easyrsa: No such file or directory". openssl is always present.
# Idempotent: only build if the CA is missing, so re-runs never invalidate the
# running server certificate.
# ---------------------------------------------------------------------------
echo -e "${CYAN}🔐 Setting up PKI (server certificate only, via openssl)...${NC}"
PKI=/etc/openvpn/pki
if [[ ! -f "$PKI/ca.crt" ]]; then
    sudo mkdir -p "$PKI"
    cd "$PKI"
    # Certificate Authority
    sudo openssl genrsa -out ca.key 2048
    sudo openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
        -subj "/CN=sas-ovpn-ca" -out ca.crt
    # Server key + cert signed by our CA
    sudo openssl genrsa -out server.key 2048
    sudo openssl req -new -key server.key -subj "/CN=server" -out server.csr
    sudo openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 3650 -sha256 -out server.crt
    sudo rm -f server.csr
    # Diffie-Hellman params — the slow step (~1-2 min for 2048-bit).
    echo -e "${YELLOW}   Generating DH params (2048-bit, may take a minute)...${NC}"
    sudo openssl dhparam -out dh.pem 2048
    # Private keys root-only; OpenVPN reads them as root before dropping to nobody.
    sudo chmod 600 ca.key server.key
    echo -e "${GREEN}✅ PKI built (CA + server cert + DH) in $PKI${NC}"
else
    echo -e "${YELLOW}↪ Existing PKI found at $PKI — keeping it untouched.${NC}"
fi
echo ""

# ---------------------------------------------------------------------------
# Server configuration.
# ---------------------------------------------------------------------------
echo -e "${CYAN}⚙️  Writing /etc/openvpn/server.conf...${NC}"
sudo mkdir -p /var/log/openvpn
sudo bash -c "cat > /etc/openvpn/server.conf <<EOF
local 0.0.0.0
port ${OVPN_PORT}
proto tcp-server
dev tun
topology subnet
server 10.10.30.0 255.255.255.0
ca   /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/server.crt
key  /etc/openvpn/pki/server.key
dh   /etc/openvpn/pki/dh.pem
cipher AES-256-CBC
auth SHA1
keepalive 10 120
persist-key
persist-tun
# cert-less user/pass auth against chap-secrets:
verify-client-cert none
username-as-common-name
duplicate-cn
script-security 2
auth-user-pass-verify /etc/openvpn/auth.sh via-file
user nobody
group www-data
status /var/log/openvpn/status.log
verb 3
EOF"

echo -e "${GREEN}✅ server.conf written (port ${OVPN_PORT}/tcp)${NC}"
echo ""

# ---------------------------------------------------------------------------
# Auth helper: verify username/password against chap-secrets.
# ---------------------------------------------------------------------------
echo -e "${CYAN}🔑 Writing /etc/openvpn/auth.sh...${NC}"
sudo bash -c 'cat > /etc/openvpn/auth.sh <<'"'"'EOF'"'"'
#!/bin/bash
# OpenVPN auth-user-pass-verify (via-file): $1 is a temp file, line1=user line2=pass.
CHAP="/etc/ppp/chap-secrets"
user=$(head -1 "$1"); pass=$(sed -n '"'"'2p'"'"' "$1")
[ -z "$user" ] && exit 1
# chap-secrets columns: client server secret ip -> match client($1) + secret($3)
awk -v u="$user" -v p="$pass" '"'"'($1==u)&&($3==p){f=1} END{exit !f}'"'"' "$CHAP" && exit 0
exit 1
EOF'
sudo chmod 755 /etc/openvpn/auth.sh

echo -e "${GREEN}✅ auth.sh installed${NC}"
echo ""

# ---------------------------------------------------------------------------
# chap-secrets: shared with the L2TP panel. Preserve existing users on re-run;
# only seed a minimal file if it's absent/empty. Always fix ownership/mode so
# both pppd (root) and the panel (www-data) can read it.
# ---------------------------------------------------------------------------
echo -e "${CYAN}🔑 Ensuring chap-secrets exists (shared with L2TP)...${NC}"
if [[ -f /etc/ppp/chap-secrets ]] && grep -qvE '^\s*#|^\s*$' /etc/ppp/chap-secrets 2>/dev/null; then
    echo -e "${YELLOW}↪ Existing chap-secrets found with users — keeping it untouched.${NC}"
else
    sudo mkdir -p /etc/ppp
    sudo bash -c 'cat > /etc/ppp/chap-secrets <<EOF
# Secrets for authentication using CHAP
# client    server    secret    IP addresses
EOF'
fi
# Owner root so pppd reads it; group www-data so the panel does too; mode 660.
sudo chown root:www-data /etc/ppp/chap-secrets
sudo chmod 660 /etc/ppp/chap-secrets

echo -e "${GREEN}✅ chap-secrets ready${NC}"
echo ""

# Enable IP forwarding (drop-in guarantees it regardless of how sysctl.conf is
# formatted, and persists across reboots).
echo -e "${CYAN}🌐 Enabling IP forwarding...${NC}"
sudo bash -c 'echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ovpn-forward.conf'
sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo -e "${GREEN}✅ IP forwarding enabled${NC}"
echo ""

# ---------------------------------------------------------------------------
# NAT via a systemd oneshot so the MASQUERADE rule survives reboots even before
# netfilter-persistent runs, and re-applies on the correct uplink each boot.
# ---------------------------------------------------------------------------
echo -e "${CYAN}🔥 Installing NAT (systemd oneshot)...${NC}"
sudo bash -c "cat > /etc/systemd/system/ovpn-nat.service <<EOF
[Unit]
Description=OpenVPN NAT masquerade for 10.10.30.0/24
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s 10.10.30.0/24 -o ${WAN_IF} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.10.30.0/24 -o ${WAN_IF} -j MASQUERADE'

[Install]
WantedBy=multi-user.target
EOF"

sudo systemctl daemon-reload
sudo systemctl enable ovpn-nat >/dev/null 2>&1 || true
sudo systemctl restart ovpn-nat

# Persist for reboot via netfilter-persistent as well.
sudo mkdir -p /etc/iptables
sudo sh -c "iptables-save > /etc/iptables/rules.v4"
sudo netfilter-persistent save 2>/dev/null || true

echo -e "${GREEN}✅ NAT configured (uplink: ${WAN_IF}, persisted for reboot)${NC}"
echo ""

# ---------------------------------------------------------------------------
# Enable + (re)start the OpenVPN server. Use restart so re-runs pick up config
# changes.
# ---------------------------------------------------------------------------
echo -e "${CYAN}🔄 Starting OpenVPN server...${NC}"
sudo systemctl enable openvpn@server >/dev/null 2>&1 || true
sudo systemctl restart openvpn@server

echo -e "${GREEN}✅ openvpn@server started${NC}"
echo ""

# Hard verification: OpenVPN must actually be listening on the configured TCP
# port, otherwise the install is broken no matter what printed above.
echo -e "${CYAN}🔍 Verifying OpenVPN is listening on TCP ${OVPN_PORT}...${NC}"
sleep 2
if sudo ss -tlnp 2>/dev/null | grep -q ":${OVPN_PORT}"; then
    echo -e "${GREEN}✅ OpenVPN is listening on TCP ${OVPN_PORT}${NC}"
else
    echo -e "${RED}❌ OpenVPN is NOT listening on TCP ${OVPN_PORT} — install is incomplete. Check 'journalctl -u openvpn@server'.${NC}" >&2
    exit 1
fi
echo ""

# ---------------------------------------------------------------------------
# Record what we installed into the shared coexistence file.
# ---------------------------------------------------------------------------
echo -e "${CYAN}📝 Recording OVPN config in /etc/l2tp-manager/vpn.conf...${NC}"
set_vpn_conf SERVER_IP    "$SERVER_IP"
set_vpn_conf COA_PORT     1700
set_vpn_conf OVPN_ENABLED 1
set_vpn_conf OVPN_PORT    "$OVPN_PORT"
set_vpn_conf OVPN_PROTO   tcp
set_vpn_conf OVPN_RADIUS  10.10.30.1

echo -e "${GREEN}✅ vpn.conf updated${NC}"
echo ""

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   OpenVPN (TCP) Server Installation Complete!${NC}"
echo -e "${GREEN}==============================================${NC}"
echo ""

# ---------------------------------------------------------------------------
# Chain the web management interface (same as the L2TP full installer).
# ---------------------------------------------------------------------------
echo -e "${BLUE}🚀 Now installing Web Management Interface...${NC}"
TMP_GUI="$(mktemp)"
if curl -fsSL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-install.sh -o "$TMP_GUI"; then
    sudo bash "$TMP_GUI"
    rm -f "$TMP_GUI"
else
    rm -f "$TMP_GUI"
    echo -e "${RED}❌ Failed to download the web interface installer. OVPN server is up; re-run sas4-install.sh later.${NC}" >&2
    exit 1
fi
