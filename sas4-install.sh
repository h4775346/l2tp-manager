#!/bin/bash

# Define variables
REPO_URL="https://github.com/h4775346/l2tp-manager.git"
TARGET_DIR="/opt/sas4/site/l2tp-manager/"
APACHE_CONF="/etc/apache2/sites-enabled/sas4.conf"
CHAP_SECRETS="/etc/ppp/chap-secrets"

# Update package list and install necessary packages
apt-get update
apt-get install -y git unzip curl apache2

# Clone the GitHub repository
if [ ! -d "$TARGET_DIR" ]; then
    git clone $REPO_URL $TARGET_DIR
else
    echo "Directory $TARGET_DIR already exists. Stashing local changes and pulling the latest changes."
    cd $TARGET_DIR
    git config --global --add safe.directory $TARGET_DIR
    git stash
    git pull
fi

# Ensure /etc/ppp/chap-secrets is writable
chmod 666 $CHAP_SECRETS

# Ensure the target directory is writable by the web server
chown -R www-data:www-data $TARGET_DIR
chmod -R 755 $TARGET_DIR

# Define the Alias and Directory block
ALIAS_BLOCK=$(cat <<EOT
Alias /l2tp-manager $TARGET_DIR
<Directory $TARGET_DIR>
    Order allow,deny
    Allow from all
    AllowOverride All
    Require all granted
</Directory>
EOT
)

# Add the new Alias and Directory block above the existing Alias /user/api block
if ! grep -q "/l2tp-manager/" $APACHE_CONF; then
    awk -v insert="$ALIAS_BLOCK" '/Alias \/user\/api \/opt\/sas4\/site\/user\/backend\/public\// {print insert; print} !/Alias \/user\/api \/opt\/sas4\/site\/user\/backend\/public\// {print}' $APACHE_CONF > /tmp/sas4.conf && mv /tmp/sas4.conf $APACHE_CONF
fi

# Restart Apache to apply the changes
systemctl restart apache2

echo "l2tp-manager installed and Apache configuration updated."
