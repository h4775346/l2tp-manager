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
<html>
<head>
    <title>Login</title>
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            <h2 class="text-center mb-4">Login</h2>
            <?php if (!empty($error)): ?>
                <div class="alert alert-danger"><?php echo sanitizeOutput($error); ?></div>
            <?php endif; ?>
            <?php if (isset($_GET['expired'])): ?>
                <div class="alert alert-warning"><?php echo sanitizeOutput('Your session has expired. Please login again.'); ?></div>
            <?php endif; ?>
            <form method="post" action="login.php">
                <input type="hidden" name="csrf_token" value="<?php echo sanitizeOutput(generateCSRFToken()); ?>">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="username" name="username" required placeholder="Enter username" autocomplete="username">
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required placeholder="Enter password" autocomplete="current-password">
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
        </div>
    </div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
