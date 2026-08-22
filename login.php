<?php
include 'header.php';

// Check session timeout
if (!checkSessionTimeout()) {
    session_destroy();
    header('Location: login.php?expired=1');
    exit();
}

$error = '';
$clientIP = getClientIP();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Check CSRF token
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!validateCSRFToken($csrfToken)) {
        $error = 'Invalid security token. Please try again.';
    } else {
        // Check rate limiting
        $rateLimit = rateLimitLogin($clientIP);
        if (!$rateLimit['allowed']) {
            $waitMinutes = ceil($rateLimit['wait_seconds'] / 60);
            $error = "Too many login attempts. Please try again in {$waitMinutes} minute(s).";
        } else {
            $config = include 'config.php';
            $username = sanitizeInput($_POST['username'] ?? '');
            $password = $_POST['password'] ?? '';

            // Validate inputs
            if (empty($username) || empty($password)) {
                $error = 'Username and password are required';
                recordFailedLogin($clientIP);
            } elseif ($username === $config['admin_username'] && password_verify($password, $config['admin_password'])) {
                // Clear failed login attempts
                clearLoginAttempts($clientIP);
                
                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);
                
                $_SESSION['loggedin'] = true;
                $_SESSION['last_activity'] = time();
                $_SESSION['created'] = time();
                
                // Regenerate CSRF token after successful login
                regenerateCSRFToken();
                
                header('Location: index.php');
                exit();
            } else {
                $error = 'Invalid username or password';
                recordFailedLogin($clientIP);
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPN Manager · Sign in</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;510;590&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/dashboard.css">
    <style>
        html, body.login-page {
            margin: 0;
            min-height: 100%;
        }
        body.login-page {
            background: var(--canvas);
            color: var(--text);
            font-family: Inter, system-ui, sans-serif;
            font-feature-settings: "cv01", "ss03";
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 24px;
            box-sizing: border-box;
        }
        .login-card {
            width: 380px;
            max-width: 100%;
            background: var(--surface);
            border: var(--border);
            border-radius: 8px;
            padding: 32px 28px 28px;
            box-sizing: border-box;
        }
        .login-wordmark {
            margin: 0 0 4px;
            font-size: 20px;
            font-weight: 590;
            letter-spacing: -0.02em;
            color: var(--text);
        }
        .login-sub {
            margin: 0 0 24px;
            font-size: 13px;
            font-weight: 400;
            color: var(--text-3);
        }
        .login-card .field {
            margin-bottom: 14px;
        }
        .login-card label {
            display: block;
            margin-bottom: 6px;
            font-size: 12px;
            font-weight: 510;
            color: var(--text-2);
        }
        .login-card input[type="text"],
        .login-card input[type="password"] {
            width: 100%;
            box-sizing: border-box;
            background: var(--raised);
            color: var(--text);
            border: var(--border);
            border-radius: 6px;
            padding: 9px 12px;
            font: inherit;
            font-size: 14px;
        }
        .login-card input:focus {
            outline: none;
            border-color: #7170ff;
        }
        .login-card .btn.btn-primary {
            width: 100%;
            margin-top: 8px;
        }
        .login-card .alert {
            margin: 0 0 16px;
        }
    </style>
</head>
<body class="login-page">
    <main class="login-card">
        <h1 class="login-wordmark">VPN Manager</h1>
        <p class="login-sub">Sign in to continue</p>
        <?php if (!empty($error)): ?>
            <div class="alert alert-error"><?php echo sanitizeOutput($error); ?></div>
        <?php endif; ?>
        <?php if (isset($_GET['expired'])): ?>
            <div class="alert alert-warn"><?php echo sanitizeOutput('Your session has expired. Please login again.'); ?></div>
        <?php endif; ?>
        <form method="post" action="login.php">
            <input type="hidden" name="csrf_token" value="<?php echo sanitizeOutput(generateCSRFToken()); ?>">
            <div class="field">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            <div class="field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn btn-primary">Sign in</button>
        </form>
    </main>
</body>
</html>
