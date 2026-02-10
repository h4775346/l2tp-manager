<?php
/**
 * Security utility functions for L2TP Manager
 * Provides input validation, CSRF protection, and security utilities
 */

/**
 * Enforce HTTPS connection (optional - call at start of pages if needed)
 * @param bool $enforce Whether to enforce HTTPS redirect
 */
function enforceHTTPS($enforce = false) {
    if ($enforce && empty($_SERVER['HTTPS']) && $_SERVER['HTTP_HOST'] !== 'localhost' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
        $redirectUrl = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        header('Location: ' . $redirectUrl, true, 301);
        exit();
    }
}

/**
 * Set security headers
 */
function setSecurityHeaders() {
    // Prevent clickjacking
    header('X-Frame-Options: SAMEORIGIN');
    // Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    // Enable XSS filter
    header('X-XSS-Protection: 1; mode=block');
    // Referrer policy
    header('Referrer-Policy: strict-origin-when-cross-origin');
    // Content Security Policy (adjust as needed)
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com;");
}

/**
 * Ensure session is started with secure cookie parameters
 * This must be called before any output is sent
 */
function ensureSessionStarted() {
    if (session_status() === PHP_SESSION_NONE) {
        // Set secure session cookie parameters before starting the session
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            session_set_cookie_params([
                'lifetime' => $params['lifetime'],
                'path'     => $params['path'],
                'domain'   => $params['domain'],
                'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
        }

        session_start();
    }
}

/**
 * Validate IP address format
 * @param string $ip IP address to validate
 * @return bool True if valid IP address
 */
function validateIP($ip) {
    if (empty($ip) || !is_string($ip)) {
        return false;
    }
    
    // Check length (max 15 characters for IPv4)
    if (strlen($ip) > 15) {
        return false;
    }
    
    // Use filter_var for strict IP validation
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

/**
 * Validate CIDR notation (e.g., 192.168.1.0/24)
 * @param string $cidr CIDR notation to validate
 * @return bool True if valid CIDR
 */
function validateCIDR($cidr) {
    if (empty($cidr) || !is_string($cidr)) {
        return false;
    }
    
    // Check length (max 18 characters for IPv4 CIDR)
    if (strlen($cidr) > 18) {
        return false;
    }
    
    // Check format: IP/prefix
    if (!preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[12][0-9]|3[0-2])$/', $cidr)) {
        return false;
    }
    
    list($ip, $prefix) = explode('/', $cidr);
    
    // Validate IP part
    if (!validateIP($ip)) {
        return false;
    }
    
    // Validate prefix length (0-32 for IPv4)
    $prefix = (int)$prefix;
    if ($prefix < 0 || $prefix > 32) {
        return false;
    }
    
    return true;
}

/**
 * Validate username
 * @param string $username Username to validate
 * @return bool True if valid username
 */
function validateUsername($username) {
    if (empty($username) || !is_string($username)) {
        return false;
    }
    
    // Length check (1-64 characters)
    if (strlen($username) < 1 || strlen($username) > 64) {
        return false;
    }
    
    // Allow alphanumeric, underscore, hyphen, dot, and @ (common in L2TP/PPP usernames)
    // Reject dangerous characters: spaces, quotes, backticks, semicolons, pipes, etc.
    if (preg_match('/[\s\'"`;\|\\\\$()<>{}]/', $username)) {
        return false;
    }
    
    // Must contain at least one alphanumeric character
    if (!preg_match('/[a-zA-Z0-9]/', $username)) {
        return false;
    }
    
    return true;
}

/**
 * Validate password
 * @param string $password Password to validate
 * @return bool True if valid password
 */
function validatePassword($password) {
    if (empty($password) || !is_string($password)) {
        return false;
    }
    
    // Length check (minimum 1, maximum 128 characters) - L2TP passwords can be short
    if (strlen($password) < 1 || strlen($password) > 128) {
        return false;
    }
    
    // Check for null bytes (prevent null byte injection)
    if (strpos($password, "\0") !== false) {
        return false;
    }
    
    // Reject dangerous shell characters
    if (preg_match('/[\'"`;\|\\\\$()<>{}]/', $password)) {
        return false;
    }
    
    return true;
}

/**
 * Sanitize input for safe display
 * @param string $input Input to sanitize
 * @return string Sanitized input
 */
function sanitizeInput($input) {
    if (!is_string($input)) {
        return '';
    }
    
    // Remove null bytes
    $input = str_replace("\0", '', $input);
    
    // Trim whitespace
    $input = trim($input);
    
    return $input;
}

/**
 * Sanitize output for HTML display
 * @param string $output Output to sanitize
 * @return string Sanitized output
 */
function sanitizeOutput($output) {
    return htmlspecialchars($output, ENT_QUOTES, 'UTF-8');
}

/**
 * Sanitize output for JavaScript/JSON
 * @param string $output Output to sanitize
 * @return string Sanitized output
 */
function sanitizeForJS($output) {
    return json_encode($output, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
}

/**
 * Generate CSRF token
 * @return string CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token
 * @param string $token Token to validate
 * @return bool True if token is valid
 */
function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    if (empty($token) || !is_string($token)) {
        return false;
    }
    
    // Use hash_equals for timing-safe comparison
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Regenerate CSRF token
 */
function regenerateCSRFToken() {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/**
 * Configure secure session settings
 */
function secureSession() {
    // Ensure the session is started with secure settings
    ensureSessionStarted();

    // Regenerate session ID periodically to prevent session fixation
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } else if (time() - $_SESSION['created'] > 1800) {
        // Regenerate every 30 minutes
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
    
    // Set secure session cookie parameters
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        session_set_cookie_params([
            'lifetime' => $params['lifetime'],
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
            'httponly' => true,
            'samesite' => 'Strict'
        ]);
    }
}

/**
 * Check if session has expired
 * @param int $timeout Timeout in seconds (default 3600 = 1 hour)
 * @return bool True if session is still valid
 */
function checkSessionTimeout($timeout = 3600) {
    if (!isset($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
        return true;
    }
    
    if (time() - $_SESSION['last_activity'] > $timeout) {
        // Session expired
        session_destroy();
        return false;
    }
    
    $_SESSION['last_activity'] = time();
    return true;
}

/**
 * Rate limit login attempts
 * @param string $ip Client IP address
 * @param int $maxAttempts Maximum attempts allowed (default 5)
 * @param int $lockoutTime Lockout time in seconds (default 900 = 15 minutes)
 * @return array ['allowed' => bool, 'remaining' => int, 'lockout_until' => int|null]
 */
function rateLimitLogin($ip, $maxAttempts = 5, $lockoutTime = 900) {
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = [];
    }
    
    $now = time();
    $ipKey = md5($ip);
    
    // Clean old attempts
    foreach ($_SESSION['login_attempts'] as $key => $attempt) {
        if ($now - $attempt['time'] > $lockoutTime) {
            unset($_SESSION['login_attempts'][$key]);
        }
    }
    
    // Get attempts for this IP
    $attempts = [];
    foreach ($_SESSION['login_attempts'] as $attempt) {
        if ($attempt['ip'] === $ipKey) {
            $attempts[] = $attempt;
        }
    }
    
    // Check if locked out
    $recentAttempts = array_filter($attempts, function($attempt) use ($now, $lockoutTime) {
        return ($now - $attempt['time']) < $lockoutTime;
    });
    
    if (count($recentAttempts) >= $maxAttempts) {
        $oldestAttempt = min(array_column($recentAttempts, 'time'));
        $lockoutUntil = $oldestAttempt + $lockoutTime;
        
        return [
            'allowed' => false,
            'remaining' => 0,
            'lockout_until' => $lockoutUntil,
            'wait_seconds' => max(0, $lockoutUntil - $now)
        ];
    }
    
    return [
        'allowed' => true,
        'remaining' => $maxAttempts - count($recentAttempts),
        'lockout_until' => null
    ];
}

/**
 * Record failed login attempt
 * @param string $ip Client IP address
 */
function recordFailedLogin($ip) {
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = [];
    }
    
    $_SESSION['login_attempts'][] = [
        'ip' => md5($ip),
        'time' => time()
    ];
}

/**
 * Clear login attempts for IP
 * @param string $ip Client IP address
 */
function clearLoginAttempts($ip) {
    if (!isset($_SESSION['login_attempts'])) {
        return;
    }
    
    $ipKey = md5($ip);
    $_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'], function($attempt) use ($ipKey) {
        return $attempt['ip'] !== $ipKey;
    });
}

/**
 * Get client IP address
 * @return string Client IP address
 */
function getClientIP() {
    $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'];
    
    foreach ($ipKeys as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = $_SERVER[$key];
            // Handle comma-separated IPs (from proxies)
            if (strpos($ip, ',') !== false) {
                $ip = trim(explode(',', $ip)[0]);
            }
            if (validateIP($ip)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Validate file path to prevent directory traversal
 * @param string $path File path to validate
 * @param string $baseDir Base directory (must be absolute path)
 * @return bool|string False if invalid, normalized path if valid
 */
function validateFilePath($path, $baseDir) {
    // Resolve to absolute path
    $realBase = realpath($baseDir);
    if ($realBase === false) {
        return false;
    }
    
    $realPath = realpath($baseDir . DIRECTORY_SEPARATOR . $path);
    if ($realPath === false) {
        return false;
    }
    
    // Check if path is within base directory
    if (strpos($realPath, $realBase) !== 0) {
        return false;
    }
    
    return $realPath;
}

/**
 * Safe error message for user display
 * @param string $message Error message
 * @return string Safe error message
 */
function safeErrorMessage($message) {
    // Log the full error server-side
    error_log("L2TP Manager Error: " . $message);
    
    // Return generic message to user
    return "An error occurred. Please try again.";
}

/**
 * Validate gateway IP (optional, can be null)
 * @param string|null $gateway Gateway IP to validate
 * @return bool True if valid or null
 */
function validateGateway($gateway) {
    if ($gateway === null || $gateway === '') {
        return true; // Gateway is optional
    }
    return validateIP($gateway);
}

/**
 * Audit log for tracking user actions
 * @param string $action The action performed (e.g., 'user_add', 'user_delete', 'route_add')
 * @param array $details Additional details about the action
 */
function auditLog($action, $details = []) {
    $logFile = '/var/log/l2tp-manager-audit.log';
    $timestamp = date('Y-m-d H:i:s');
    $clientIP = getClientIP();
    $username = $_SESSION['admin_user'] ?? 'unknown';
    
    $logEntry = [
        'timestamp' => $timestamp,
        'ip' => $clientIP,
        'user' => $username,
        'action' => $action,
        'details' => $details
    ];
    
    $logLine = json_encode($logEntry) . "\n";
    
    // Try to write to log file, silently fail if not writable
    @file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
}

/**
 * Check if password meets strength requirements
 * @param string $password Password to check
 * @return array ['valid' => bool, 'errors' => array]
 */
function checkPasswordStrength($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter';
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one number';
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors
    ];
}

