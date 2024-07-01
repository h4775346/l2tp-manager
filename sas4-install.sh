#!/bin/bash

# Define variables
DOWNLOAD_URL="https://downloads.pro-service.link/l2tp-manager.zip"
TARGET_DIR="/opt/sas4/site/l2tp-manager/"
APACHE_CONF="/etc/apache2/sites-enabled/sas4.conf"
CHAP_SECRETS="/etc/ppp/chap-secrets"

# Create the target directory if it does not exist
mkdir -p $TARGET_DIR

# Download the ZIP file using curl
curl -o /tmp/l2tp-manager.zip $DOWNLOAD_URL

# Unzip the downloaded file into the target directory
unzip -o /tmp/l2tp-manager.zip -d $TARGET_DIR

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

# Add the new Alias and Directory block to the Apache configuration if it does not already exist
if ! grep -q "/l2tp-manager/" $APACHE_CONF; then
    awk -v insert="$ALIAS_BLOCK" '/ProxyRequests off/ {print; print insert; next}1' $APACHE_CONF > /tmp/sas4.conf && mv /tmp/sas4.conf $APACHE_CONF
fi

# Allow writing to the chap-secrets file
chmod 666 $CHAP_SECRETS

# Restart Apache to apply the changes
systemctl restart apache2

# Cleanup
rm /tmp/l2tp-manager.zip

echo "l2tp-manager installed and Apache configuration updated."
