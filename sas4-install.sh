#!/bin/bash

# ==============================================================================
# 🚀 SAS4 L2TP Manager - Web Interface Installer
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
echo ""
# Variables
REPO_URL="https://github.com/h4775346/l2tp-manager.git"
TARGET_DIR="/opt/sas4/site/l2tp-manager/"
CHAP_SECRETS="/etc/ppp/chap-secrets"
PORTS_CONF="/etc/apache2/ports.conf"
CERT_PATH="/etc/ssl/certs/l2tp-manager.pem"
KEY_PATH="/etc/ssl/private/l2tp-manager.key"
HTTP_PORT=8090
HTTPS_PORT=8099
HTTP_CONF="/etc/apache2/sites-available/l2tp-manager-http.conf"
SSL_CONF="/etc/apache2/sites-available/l2tp-manager-ssl.conf"

echo -e "${YELLOW}🚀 Starting L2TP Manager Web Interface Installation...${NC}"
echo ""

# Install Apache & dependencies
echo -e "${CYAN}📦 Installing required packages...${NC}"
apt-get update
apt-get install -y git unzip curl apache2 openssl libapache2-mod-php
a2enmod ssl

echo -e "${GREEN}✅ Required packages installed${NC}"
echo ""

# Clone the project
echo -e "${CYAN}📥 Cloning L2TP Manager repository...${NC}"
if [ ! -d "$TARGET_DIR" ]; then
    echo -e "${YELLOW}Cloning repository to $TARGET_DIR${NC}"
    git clone $REPO_URL $TARGET_DIR
else
    echo -e "${YELLOW}Directory $TARGET_DIR already exists. Pulling latest changes.${NC}"
    git config --global --add safe.directory $TARGET_DIR
    cd $TARGET_DIR
    git stash
    git pull
fi

echo -e "${GREEN}✅ Repository cloned/updated successfully${NC}"
echo ""

# Permissions
echo -e "${CYAN}🔐 Setting up permissions...${NC}"
chmod 666 $CHAP_SECRETS
chown -R www-data:www-data $TARGET_DIR
chmod -R 755 $TARGET_DIR

echo -e "${GREEN}✅ Permissions configured${NC}"
echo ""

# Ensure Apache listens on both ports
echo -e "${CYAN}🌐 Configuring Apache ports...${NC}"
for port in $HTTP_PORT $HTTPS_PORT; do
    if ! grep -q "Listen $port" "$PORTS_CONF"; then
        echo "Listen $port" >> "$PORTS_CONF"
        echo -e "${YELLOW}Added port $port to Apache configuration${NC}"
    else
        echo -e "${GREEN}Port $port already configured${NC}"
    fi
done

echo -e "${GREEN}✅ Apache ports configured${NC}"
echo ""

# Generate self-signed SSL certificate if needed
echo -e "${CYAN}🔒 Generating SSL certificate...${NC}"
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_PATH" \
        -out "$CERT_PATH" \
        -subj "/C=EG/ST=Cairo/L=Cairo/O=SAS4/OU=IT/CN=sas4group.net"
    echo -e "${GREEN}✅ New SSL certificate generated${NC}"
else
    echo -e "${GREEN}✅ SSL certificate already exists${NC}"
fi
echo ""

# HTTP VirtualHost (for /l2tp-manager only)
echo -e "${CYAN}⚙️  Configuring HTTP VirtualHost...${NC}"
if [ ! -f "$HTTP_CONF" ]; then
cat <<EOL > "$HTTP_CONF"
<VirtualHost *:$HTTP_PORT>
    Alias /l2tp-manager $TARGET_DIR
    <Directory $TARGET_DIR>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/l2tp-http-error.log
    CustomLog \${APACHE_LOG_DIR}/l2tp-http-access.log combined
</VirtualHost>
EOL
    a2ensite l2tp-manager-http.conf
    echo -e "${GREEN}✅ HTTP VirtualHost created and enabled${NC}"
else
    echo -e "${GREEN}✅ HTTP VirtualHost already configured${NC}"
fi
echo ""

# HTTPS VirtualHost (for /l2tp-manager only)
echo -e "${CYAN}⚙️  Configuring HTTPS VirtualHost...${NC}"
if [ ! -f "$SSL_CONF" ]; then
cat <<EOL > "$SSL_CONF"
<VirtualHost *:$HTTPS_PORT>
    SSLEngine on
    SSLCertificateFile $CERT_PATH
    SSLCertificateKeyFile $KEY_PATH

    Alias /l2tp-manager $TARGET_DIR
    <Directory $TARGET_DIR>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/l2tp-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/l2tp-ssl-access.log combined
</VirtualHost>
EOL
    a2ensite l2tp-manager-ssl.conf
    echo -e "${GREEN}✅ HTTPS VirtualHost created and enabled${NC}"
else
    echo -e "${GREEN}✅ HTTPS VirtualHost already configured${NC}"
fi
echo ""

# Reload Apache to apply changes
echo -e "${CYAN}🔄 Reloading Apache configuration...${NC}"
systemctl reload apache2

echo ""
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   Installation Complete! 🎉${NC}"
echo -e "${GREEN}==============================================${NC}"
echo ""
echo -e "${BLUE}🌐 Access your L2TP Manager:${NC}"
echo -e "  🔓 HTTP : http://your-ip:$HTTP_PORT/l2tp-manager/"
echo -e "  🔐 HTTPS: https://your-ip:$HTTPS_PORT/l2tp-manager/"
echo ""
echo -e "${YELLOW}📝 Default Credentials:${NC}"
echo -e "  👤 Username: admin"
echo -e "  🔑 Password: change@me (Please change this immediately)"
echo ""
echo -e "${PURPLE}💡 Tip: For security, access via HTTPS and change the default password!${NC}"
echo ""