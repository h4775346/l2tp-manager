#!/bin/bash

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

# Install Apache & dependencies
apt-get update
apt-get install -y git unzip curl apache2 openssl libapache2-mod-php
a2enmod ssl

# Clone the project
if [ ! -d "$TARGET_DIR" ]; then
    git clone $REPO_URL $TARGET_DIR
else
    echo "Directory $TARGET_DIR already exists. Pulling latest changes."
    git config --global --add safe.directory $TARGET_DIR
    cd $TARGET_DIR
    git stash
    git pull
fi

# Permissions
chmod 666 $CHAP_SECRETS
chown -R www-data:www-data $TARGET_DIR
chmod -R 755 $TARGET_DIR

# Ensure Apache listens on both ports
for port in $HTTP_PORT $HTTPS_PORT; do
    if ! grep -q "Listen $port" "$PORTS_CONF"; then
        echo "Listen $port" >> "$PORTS_CONF"
    fi
done

# Generate self-signed SSL certificate if needed
if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_PATH" \
        -out "$CERT_PATH" \
        -subj "/C=EG/ST=Cairo/L=Cairo/O=SAS4/OU=IT/CN=sas4group.net"
fi

# HTTP VirtualHost (for /l2tp-manager only)
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
fi

# HTTPS VirtualHost (for /l2tp-manager only)
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
fi

# Reload Apache to apply changes
systemctl reload apache2

echo "✅ Site is now available:"
echo " - HTTP : http://your-ip:$HTTP_PORT/l2tp-manager/"
echo " - HTTPS: https://your-ip:$HTTPS_PORT/l2tp-manager/"
