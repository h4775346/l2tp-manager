#!/bin/bash

# Variables
REPO_URL="https://github.com/h4775346/l2tp-manager.git"
TARGET_DIR="/opt/sas4/site/l2tp-manager/"
CHAP_SECRETS="/etc/ppp/chap-secrets"
APACHE_CONF="/etc/apache2/sites-available/l2tp-manager.conf"
PORTS_CONF="/etc/apache2/ports.conf"

# Update and install packages
apt update
apt install -y git unzip curl apache2 libapache2-mod-php

# Clone the repo
if [ ! -d "$TARGET_DIR" ]; then
    git clone $REPO_URL $TARGET_DIR
else
    echo "Directory $TARGET_DIR already exists. Pulling latest changes..."
    git config --global --add safe.directory $TARGET_DIR
    cd $TARGET_DIR
    git stash
    git pull
fi

# Set permissions
chmod 666 $CHAP_SECRETS
chown -R www-data:www-data $TARGET_DIR
chmod -R 755 $TARGET_DIR

# Ensure Apache listens on port 8090
if ! grep -q "Listen 8090" $PORTS_CONF; then
    echo "Listen 8090" >> $PORTS_CONF
fi

# Create Apache VirtualHost config
if [ ! -f "$APACHE_CONF" ]; then
cat <<EOL > $APACHE_CONF
<VirtualHost *:8090>
    ServerAdmin admin@localhost
    DocumentRoot $TARGET_DIR

    <Directory $TARGET_DIR>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/l2tp-error.log
    CustomLog \${APACHE_LOG_DIR}/l2tp-access.log combined
</VirtualHost>
EOL
    a2ensite l2tp-manager.conf
fi

# Restart Apache
systemctl reload apache2

echo "✅ Apache is now serving /l2tp-manager on http://your-server-ip:8090/"
