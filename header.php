<?php
// Define default config values
$defaultConfig = [
    'chap_secrets_path' => '/etc/ppp/chap-secrets',
    'admin_username' => 'admin',
    'admin_password' => password_hash('change@me', PASSWORD_DEFAULT),
];

// Create config.php if it doesn't exist
if (!file_exists('config.php')) {
    file_put_contents('config.php', '<?php return ' . var_export($defaultConfig, true) . ';');
}
