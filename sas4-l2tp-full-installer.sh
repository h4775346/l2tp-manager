#!/bin/bash

# ==============================================================================
# 🚀 SAS4 L2TP/IPSec Server - Full Installation Script
# ==============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

# Update the system
echo -e "${CYAN}🔄 Updating system packages...${NC}"
sudo apt update -y

# Install required packages
echo -e "${CYAN}📦 Installing L2TP/IPSec packages...${NC}"
sudo apt install strongswan xl2tpd -y

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
sudo bash -c 'cat > /etc/ipsec.secrets <<EOF
: PSK "123456"
EOF'

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

# Configure chap-secrets
echo -e "${CYAN}🔑 Configuring default users...${NC}"
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

echo -e "${GREEN}✅ Default users configured${NC}"
echo ""

# Enable IP forwarding
echo -e "${CYAN}🌐 Enabling IP forwarding...${NC}"
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p

echo -e "${GREEN}✅ IP forwarding enabled${NC}"
echo ""

# Configure firewall rules
echo -e "${CYAN}🔥 Configuring firewall rules...${NC}"
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -p tcp --syn -s 10.255.0.0/16 -j TCPMSS --set-mss 1356
sudo sh -c "iptables-save > /etc/iptables.rules"

echo -e "${GREEN}✅ Firewall rules configured${NC}"
echo ""

# Restart services
echo -e "${CYAN}🔄 Restarting L2TP services...${NC}"
sudo systemctl restart strongswan
sudo systemctl restart xl2tpd

echo -e "${GREEN}✅ L2TP services restarted${NC}"
echo ""

# Verify service status
echo -e "${CYAN}🔍 Checking service status...${NC}"
sudo systemctl status strongswan
sudo systemctl status xl2tpd

echo ""
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   L2TP/IPSec Server Installation Complete!${NC}"
echo -e "${GREEN}==============================================${NC}"
echo ""

echo -e "${BLUE}🚀 Now installing Web Management Interface...${NC}"
curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-install.sh | sudo bash