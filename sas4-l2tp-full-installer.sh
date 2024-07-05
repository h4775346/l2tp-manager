#!/bin/bash

# Update the system
sudo apt update -y

# Install required packages
sudo apt install strongswan xl2tpd -y

# Configure strongSwan
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

# Configure IPsec secrets
sudo bash -c 'cat > /etc/ipsec.secrets <<EOF
: PSK "123456"
EOF'

# Configure xl2tpd
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

# Configure PPP
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

# Configure chap-secrets
sudo bash -c 'cat > /etc/ppp/chap-secrets <<EOF
# Secrets for authentication using CHAP
# client    server    secret    IP addresses
user1       *         ikasgfiuasgf  10.255.10.11
EOF'

# Enable IP forwarding
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p

# Configure firewall rules
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -p tcp --syn -s 10.255.0.0/16 -j TCPMSS --set-mss 1356
sudo sh -c "iptables-save > /etc/iptables.rules"

# Restart services
sudo systemctl restart strongswan
sudo systemctl restart xl2tpd

# Verify service status
sudo systemctl status strongswan
sudo systemctl status xl2tpd

echo "L2TP/IPsec setup is complete."

curl -sL https://raw.githubusercontent.com/h4775346/l2tp-manager/master/sas4-install.sh | sudo bash

