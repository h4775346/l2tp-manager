<?php
include 'header.php';

// Check session timeout
if (!checkSessionTimeout()) {
    session_destroy();
    header('Location: login.php?expired=1');
    exit();
}

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit();
}

// Update last activity
$_SESSION['last_activity'] = time();

$config = include 'config.php';
$file = $config['chap_secrets_path'];

// Read the file into an array
function readUsers($file) {
    $users = [];
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '#') === 0 || strpos($line, 'tunnel') === 0) continue; // Skip comments and tunnel line
        $parts = preg_split('/\s+/', $line);
        if (count($parts) == 4) {
            $users[] = [
                'client' => $parts[0],
                'server' => $parts[1],
                'secret' => $parts[2],
                'ip' => $parts[3]
            ];
        }
    }
    return $users;
}

// Write the array back to the file
function writeUsers($file, $users) {
    // Validate file path to prevent directory traversal
    $baseDir = dirname($file);
    $validatedPath = validateFilePath(basename($file), $baseDir);
    if ($validatedPath === false) {
        throw new Exception('Invalid file path');
    }
    
    $content = "# Secrets for authentication using CHAP\n";
    $content .= "# client server secret IP addresses\n";
    $content .= "tunnel tunnel tunnel *\n";
    foreach ($users as $user) {
        // Sanitize user data before writing
        $client = preg_replace('/[^a-zA-Z0-9_-]/', '', $user['client']);
        $server = preg_replace('/[^*a-zA-Z0-9_-]/', '', $user['server']);
        $secret = preg_replace('/[\x00-\x1F\x7F]/', '', $user['secret']); // Remove control characters
        $ip = preg_replace('/[^0-9.*]/', '', $user['ip']);
        
        // Validate IP format
        if (!validateIP($ip) && $ip !== '*') {
            continue; // Skip invalid IPs
        }
        
        $content .= "{$client} {$server} {$secret} {$ip}\n";
    }
    file_put_contents($validatedPath, $content);
}

// Generate random password
function generateRandomPassword($length = 12) {
    return bin2hex(random_bytes($length / 2));
}

// Generate unique username
function generateUniqueUsername($users) {
    do {
        $username = 'user' . bin2hex(random_bytes(4));
        $unique = true;
        foreach ($users as $user) {
            if ($user['client'] === $username) {
                $unique = false;
                break;
            }
        }
    } while (!$unique);
    return $username;
}

// Get the next available IP address
function getNextIp($users) {
    if (empty($users)) {
        return '10.255.10.11';
    }

    $lastIp = end($users)['ip'];
    $lastIpLong = ip2long($lastIp);
    $nextIpLong = $lastIpLong + 1;

    // Define the current and next range boundaries
    $currentRangeStart = ip2long('10.255.' . explode('.', $lastIp)[2] . '.2');
    $currentRangeEnd = ip2long('10.255.' . explode('.', $lastIp)[2] . '.254');

    // Check if the next IP exceeds the current range, move to the next range if necessary
    if ($nextIpLong > $currentRangeEnd) {
        $nextRangeStart = ip2long('10.255.' . (explode('.', $lastIp)[2] + 1) . '.2');
        $nextRangeEnd = ip2long('10.255.' . (explode('.', $lastIp)[2] + 1) . '.254');

        // Ensure the next range does not exceed the defined ranges
        if ($nextRangeStart <= ip2long('10.255.255.254')) {
            $nextIpLong = $nextRangeStart;
        } else {
            // Handle the case when all ranges are exhausted (optional)
            // For simplicity, you might want to stop here or handle the wraparound
            die('No more IP addresses available in the defined ranges.');
        }
    }

    return long2ip($nextIpLong);
}

// Function to execute l2tp-routectl command
function executeRouteCommand($command) {
    // Validate command structure - only allow specific commands
    $allowedCommands = ['list', 'add', 'del', 'apply'];
    $commandParts = explode(' ', trim($command));
    $mainCommand = $commandParts[0] ?? '';
    
    if (!in_array($mainCommand, $allowedCommands)) {
        return [
            'output' => 'Invalid command',
            'returnCode' => 1
        ];
    }
    
    // Additional validation: ensure command doesn't contain dangerous characters
    if (preg_match('/[;&|`$(){}]/', $command)) {
        return [
            'output' => 'Invalid characters in command',
            'returnCode' => 1
        ];
    }
    
    $fullCommand = "sudo /usr/local/sbin/l2tp-routectl " . escapeshellcmd($command) . " 2>&1";
    exec($fullCommand, $output, $returnCode);
    return [
        'output' => implode("\n", $output),
        'returnCode' => $returnCode
    ];
}

// Function to get routes for a peer
function getPeerRoutes($peerIp = null) {
    $command = "list";
    if ($peerIp) {
        $command .= " --peer " . escapeshellarg($peerIp);
    }
    
    $result = executeRouteCommand($command);
    if ($result['returnCode'] === 0) {
        return $result['output'];
    }
    return "";
}

// Function to get routes for a peer and return them as an array
function getPeerRoutesArray($peerIp) {
    $command = "list --peer " . escapeshellarg($peerIp);
    $result = executeRouteCommand($command);
    
    $routes = [];
    if ($result['returnCode'] === 0) {
        $output = $result['output'];
        // Parse the output to extract routes
        $lines = explode("\n", $output);
        foreach ($lines as $line) {
            // Skip header lines and empty lines
            if (empty(trim($line)) || strpos($line, 'Routes for peer') !== false || strpos($line, 'Peer:') !== false) {
                continue;
            }
            // Add valid route lines (lines containing network routes)
            // A route line typically looks like: "192.168.1.0/24 via 10.255.10.11"
            if (preg_match('/^\d+\.\d+\.\d+\.\d+\/\d+/', trim($line))) {
                $routes[] = trim($line);
            }
        }
    }
    return $routes;
}

// Function to extract destination from a route string
function getRouteDestination($route) {
    // A route string looks like: "192.168.1.0/24 via 10.255.10.11"
    // We want to extract just the destination part: "192.168.1.0/24"
    $parts = explode(' ', $route);
    return $parts[0];
}

// Function to get a formatted string of routes for display
function getPeerRoutesFormatted($peerIp) {
    $routes = getPeerRoutesArray($peerIp);
    if (empty($routes)) {
        return "No routes";
    }
    
    // Limit the display to first 3 routes with a "+X more" if there are more
    $displayRoutes = array_slice($routes, 0, 3);
    $formatted = implode("\n", $displayRoutes);
    
    if (count($routes) > 3) {
        $formatted .= "\n... and " . (count($routes) - 3) . " more";
    }
    
    return $formatted;
}

// Function to add a route
function addPeerRoute($peerIp, $destination, $gateway = null) {
    // Validate all inputs before processing
    if (!validateIP($peerIp)) {
        return [
            'output' => 'Invalid peer IP address',
            'returnCode' => 1
        ];
    }
    
    if (!validateCIDR($destination)) {
        return [
            'output' => 'Invalid destination CIDR format',
            'returnCode' => 1
        ];
    }
    
    if ($gateway !== null && !validateGateway($gateway)) {
        return [
            'output' => 'Invalid gateway IP address',
            'returnCode' => 1
        ];
    }
    
    $command = "add --peer " . escapeshellarg($peerIp) . " --dst " . escapeshellarg($destination);
    if ($gateway) {
        $command .= " --gw " . escapeshellarg($gateway);
    }
    
    return executeRouteCommand($command);
}

// Function to delete a route
function deletePeerRoute($peerIp, $destination) {
    // Validate inputs before processing
    if (!validateIP($peerIp)) {
        return [
            'output' => 'Invalid peer IP address',
            'returnCode' => 1
        ];
    }
    
    // Validate destination (can be CIDR or 'all')
    if ($destination !== 'all' && !validateCIDR($destination)) {
        return [
            'output' => 'Invalid destination format',
            'returnCode' => 1
        ];
    }
    
    // First delete from the file
    $command = "del --peer " . escapeshellarg($peerIp) . " --dst " . escapeshellarg($destination);
    $result = executeRouteCommand($command);
    
    // Then delete from the actual routing table
    if ($result['returnCode'] === 0 && $destination !== 'all') {
        // Get the PPP interface for this peer
        $pppInterface = getPPPInterfaceForPeer($peerIp);
        if ($pppInterface) {
            // Validate CIDR before using in command
            if (validateCIDR($destination)) {
                // Delete the route from the actual routing table
                $deleteCommand = "sudo ip route del " . escapeshellarg($destination) . " dev " . escapeshellarg($pppInterface) . " 2>&1";
                exec($deleteCommand, $output, $returnCode);
                // We don't return this result as the main operation (deleting from file) was successful
            }
        }
    }
    
    return $result;
}

// Function to get PPP interface for a peer IP
function getPPPInterfaceForPeer($peerIp) {
    // Validate IP before using in command
    if (!validateIP($peerIp)) {
        return null;
    }
    
    $command = "ip link show | grep ppp | cut -d: -f2 | tr -d ' '";
    exec($command, $interfaces, $returnCode);
    
    if ($returnCode === 0 && !empty($interfaces)) {
        foreach ($interfaces as $interface) {
            // Sanitize interface name (should only contain alphanumeric and specific chars)
            $interface = preg_replace('/[^a-zA-Z0-9]/', '', $interface);
            if (empty($interface)) {
                continue;
            }
            
            // Check if this interface has the peer IP
            $addrCommand = "ip addr show " . escapeshellarg($interface) . " | grep 'peer " . escapeshellarg($peerIp) . "'";
            exec($addrCommand, $output, $addrReturnCode);
            if ($addrReturnCode === 0) {
                return $interface;
            }
        }
    }
    
    return null;
}

// Function to apply routes for a peer
function applyPeerRoutes($peerIp) {
    // Validate IP before processing
    if (!validateIP($peerIp)) {
        return [
            'output' => 'Invalid peer IP address',
            'returnCode' => 1
        ];
    }
    
    $command = "apply --peer " . escapeshellarg($peerIp);
    return executeRouteCommand($command);
}

// Function to delete all routes for a peer
function deleteAllPeerRoutes($peerIp) {
    // Validate IP before processing
    if (!validateIP($peerIp)) {
        return [
            'output' => 'Invalid peer IP address',
            'returnCode' => 1
        ];
    }
    
    $command = "del --peer " . escapeshellarg($peerIp) . " --dst all";
    return executeRouteCommand($command);
}

$users = readUsers($file);

// Add routes information to each user
foreach ($users as &$user) {
    $user['routes'] = getPeerRoutesFormatted($user['ip']);
}
unset($user); // Break the reference

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF protection - check token for all POST requests except logout
    if (!isset($_POST['logout'])) {
        $csrfToken = $_POST['csrf_token'] ?? '';
        if (!validateCSRFToken($csrfToken)) {
            http_response_code(403);
            echo json_encode(['error' => safeErrorMessage('Invalid security token')]);
            exit();
        }
    }
    
    // Handle logout
    if (isset($_POST['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit();
    }

    // Handle add user
    if (isset($_POST['add'])) {
        $client = sanitizeInput($_POST['client'] ?? '');
        $ip = sanitizeInput($_POST['ip'] ?? '');
        $secret = $_POST['secret'] ?? '';

        // Validate input
        if (empty($client)) {
            echo json_encode(['error' => safeErrorMessage('Username is required')]);
            exit();
        }
        
        if (!validateUsername($client)) {
            echo json_encode(['error' => safeErrorMessage('Invalid username format')]);
            exit();
        }
        
        if (empty($secret)) {
            echo json_encode(['error' => safeErrorMessage('Password is required')]);
            exit();
        }
        
        // Validate password length
        if (strlen($secret) > 128) {
            echo json_encode(['error' => safeErrorMessage('Password is too long')]);
            exit();
        }
        
        // Validate IP if provided
        if (!empty($ip)) {
            if (!validateIP($ip)) {
                echo json_encode(['error' => safeErrorMessage('Invalid IP address format')]);
                exit();
            }
        } else {
            $ip = getNextIp($users);
        }

        // Check for duplicate username and IP
        foreach ($users as $user) {
            if ($user['client'] === $client) {
                echo json_encode(['error' => safeErrorMessage('Username already exists')]);
                exit();
            }
            if ($user['ip'] === $ip) {
                echo json_encode(['error' => safeErrorMessage('IP address already exists')]);
                exit();
            }
        }

        $newUser = [
            'client' => $client,
            'server' => '*',
            'secret' => $secret,
            'ip' => $ip
        ];
        $users[] = $newUser;
        try {
            writeUsers($file, $users);
            echo json_encode(['ip' => sanitizeOutput($newUser['ip'])]);
        } catch (Exception $e) {
            echo json_encode(['error' => safeErrorMessage('Failed to save user')]);
        }
        exit();
    } elseif (isset($_POST['delete'])) {
        $index = (int)($_POST['index'] ?? -1);
        
        // Validate index
        if ($index < 0 || $index >= count($users)) {
            echo json_encode(['error' => safeErrorMessage('Invalid user index')]);
            exit();
        }
        
        // Get the IP of the user being deleted
        $userIp = $users[$index]['ip'];
        
        // Validate IP before deletion
        if (validateIP($userIp)) {
            // Delete all routes associated with this user
            deleteAllPeerRoutes($userIp);
        }
        
        // Delete the user
        array_splice($users, $index, 1);
        try {
            writeUsers($file, $users);
            echo json_encode(['success' => true]);
        } catch (Exception $e) {
            echo json_encode(['error' => safeErrorMessage('Failed to delete user')]);
        }
        exit();
    } elseif (isset($_POST['addMultiple'])) {
        $numUsers = (int)($_POST['numUsers'] ?? 0);
        
        // Validate input
        if ($numUsers <= 0) {
            echo json_encode(['error' => safeErrorMessage('Number of users must be greater than 0')]);
            exit();
        }
        
        if ($numUsers > 100) {
            echo json_encode(['error' => safeErrorMessage('Number of users cannot exceed 100')]);
            exit();
        }

        $ipRangeFromInput = sanitizeInput($_POST['ipRangeFrom'] ?? '');
        $ipRangeToInput = sanitizeInput($_POST['ipRangeTo'] ?? '');
        
        // Validate IP addresses if provided
        if (!empty($ipRangeFromInput)) {
            if (!validateIP($ipRangeFromInput)) {
                echo json_encode(['error' => safeErrorMessage('Invalid IP address format')]);
                exit();
            }
            $ipRangeFrom = ip2long($ipRangeFromInput);
        } else {
            $ipRangeFrom = ip2long(getNextIp($users));
        }
        
        if (!empty($ipRangeToInput)) {
            if (!validateIP($ipRangeToInput)) {
                echo json_encode(['error' => safeErrorMessage('Invalid IP address format')]);
                exit();
            }
            $ipRangeTo = ip2long($ipRangeToInput);
        } else {
            $ipRangeTo = $ipRangeFrom + $numUsers - 1;
        }

        // Validate IP range
        if ($ipRangeFrom === false || $ipRangeTo === false) {
            echo json_encode(['error' => safeErrorMessage('Invalid IP address format')]);
            exit();
        }
        
        if ($ipRangeFrom > $ipRangeTo) {
            echo json_encode(['error' => safeErrorMessage('IP range from must be less than or equal to IP range to')]);
            exit();
        }
        
        // Check if range is large enough for requested number of users
        $rangeSize = $ipRangeTo - $ipRangeFrom + 1;
        if ($rangeSize < $numUsers) {
            echo json_encode(['error' => safeErrorMessage('IP range is too small for the requested number of users')]);
            exit();
        }

        $newUsers = [];
        $addedUsers = 0;

        for ($i = 0; $addedUsers < $numUsers; $i++) {
            $username = generateUniqueUsername(array_merge($users, $newUsers));
            $userIp = long2ip($ipRangeFrom + $i);

            // Check for duplicate IP within existing and new users
            $isDuplicateIp = false;
            foreach (array_merge($users, $newUsers) as $user) {
                if ($user['ip'] === $userIp) {
                    $isDuplicateIp = true;
                    break;
                }
            }

            if ($isDuplicateIp) {
                continue;
            }

            // Ensure the IP range does not exceed the defined ranges
            if ($ipRangeFrom + $i > ip2long('10.255.255.254')) {
                echo json_encode(['error' => safeErrorMessage('IP range exhausted. Please start a new range.')]);
                exit();
            }
            
            // Validate generated IP
            if (!validateIP($userIp)) {
                continue; // Skip invalid IPs
            }

            $newUsers[] = [
                'client' => $username,
                'server' => '*',
                'secret' => generateRandomPassword(),
                'ip' => $userIp
            ];
            $addedUsers++;
        }

        $users = array_merge($users, $newUsers);
        try {
            writeUsers($file, $users);
            echo json_encode(['success' => true]);
        } catch (Exception $e) {
            echo json_encode(['error' => safeErrorMessage('Failed to save users')]);
        }
        exit();
    } elseif (isset($_POST['changePassword'])) {
        $oldPassword = $_POST['oldPassword'] ?? '';
        $newPassword = $_POST['newPassword'] ?? '';
        $confirmPassword = $_POST['confirmPassword'] ?? '';

        // Validate inputs
        if (empty($oldPassword) || empty($newPassword) || empty($confirmPassword)) {
            echo json_encode(['error' => safeErrorMessage('All password fields are required')]);
            exit();
        }
        
        // Validate new password
        if (!validatePassword($newPassword)) {
            echo json_encode(['error' => safeErrorMessage('Password must be between 8 and 128 characters')]);
            exit();
        }
        
        if ($newPassword !== $confirmPassword) {
            echo json_encode(['error' => safeErrorMessage('New password and confirmation do not match')]);
            exit();
        }

        // Read the config file
        $config = include 'config.php';
        
        // Verify old password
        if (!password_verify($oldPassword, $config['admin_password'])) {
            echo json_encode(['error' => safeErrorMessage('Current password is incorrect')]);
            exit();
        }
        
        // Check if new password is same as old password
        if (password_verify($newPassword, $config['admin_password'])) {
            echo json_encode(['error' => safeErrorMessage('New password must be different from current password')]);
            exit();
        }

        // Update the password in the config file
        $config['admin_password'] = password_hash($newPassword, PASSWORD_DEFAULT);

        // Validate config file path
        $configPath = __DIR__ . '/config.php';
        $validatedPath = validateFilePath('config.php', __DIR__);
        if ($validatedPath === false) {
            echo json_encode(['error' => safeErrorMessage('Invalid config file path')]);
            exit();
        }

        // Write the updated config back to the file
        try {
            file_put_contents($validatedPath, '<?php return ' . var_export($config, true) . ';');
            echo json_encode(['success' => true]);
        } catch (Exception $e) {
            echo json_encode(['error' => safeErrorMessage('Failed to update password')]);
        }
        exit();
    } elseif (isset($_POST['addRoute'])) {
        $peerIp = sanitizeInput($_POST['peerIp'] ?? '');
        $destination = sanitizeInput($_POST['destination'] ?? '');
        $gateway = !empty($_POST['gateway']) ? sanitizeInput($_POST['gateway']) : null;

        // Validate inputs
        if (empty($peerIp) || empty($destination)) {
            echo json_encode(['error' => safeErrorMessage('Peer IP and destination are required')]);
            exit();
        }
        
        $result = addPeerRoute($peerIp, $destination, $gateway);
        
        // If route was added successfully, automatically apply it
        if ($result['returnCode'] === 0) {
            $applyResult = applyPeerRoutes($peerIp);
            // Combine the results
            $result['applyOutput'] = $applyResult['output'];
            $result['applyReturnCode'] = $applyResult['returnCode'];
        }
        
        // Sanitize output before returning
        $result['output'] = sanitizeOutput($result['output'] ?? '');
        if (isset($result['applyOutput'])) {
            $result['applyOutput'] = sanitizeOutput($result['applyOutput']);
        }
        
        echo json_encode($result);
        exit();
    } elseif (isset($_POST['deleteRoute'])) {
        $peerIp = sanitizeInput($_POST['peerIp'] ?? '');
        $destination = sanitizeInput($_POST['destination'] ?? '');

        // Validate inputs
        if (empty($peerIp) || empty($destination)) {
            echo json_encode(['error' => safeErrorMessage('Peer IP and destination are required')]);
            exit();
        }

        $result = deletePeerRoute($peerIp, $destination);
        
        // Sanitize output before returning
        $result['output'] = sanitizeOutput($result['output'] ?? '');
        
        echo json_encode($result);
        exit();
    } elseif (isset($_POST['applyRoutes'])) {
        $peerIp = sanitizeInput($_POST['peerIp'] ?? '');
        
        // Validate input
        if (empty($peerIp)) {
            echo json_encode(['error' => safeErrorMessage('Peer IP is required')]);
            exit();
        }
        
        $result = applyPeerRoutes($peerIp);
        
        // Sanitize output before returning
        $result['output'] = sanitizeOutput($result['output'] ?? '');
        
        echo json_encode($result);
        exit();
    } elseif (isset($_POST['listRoutes'])) {
        $allRoutes = getPeerRoutes();
        echo sanitizeOutput($allRoutes);
        exit();
    } elseif (isset($_POST['getUserRoutes'])) {
        $peerIp = sanitizeInput($_POST['peerIp'] ?? '');
        
        // Validate input
        if (empty($peerIp) || !validateIP($peerIp)) {
            echo json_encode(['error' => safeErrorMessage('Invalid peer IP')]);
            exit();
        }
        
        $routes = getPeerRoutesFormatted($peerIp);
        echo json_encode(['routes' => sanitizeOutput($routes)]);
        exit();
    } elseif (isset($_POST['getAllUsersRoutes'])) {
        $allRoutes = [];
        foreach ($users as $user) {
            if (validateIP($user['ip'])) {
                $allRoutes[sanitizeOutput($user['ip'])] = sanitizeOutput(getPeerRoutesFormatted($user['ip']));
            }
        }
        echo json_encode($allRoutes);
        exit();
    } elseif (isset($_POST['getUserRoutesArray'])) {
        $peerIp = sanitizeInput($_POST['peerIp'] ?? '');
        
        // Validate input
        if (empty($peerIp) || !validateIP($peerIp)) {
            echo json_encode(['error' => safeErrorMessage('Invalid peer IP')]);
            exit();
        }
        
        $routes = getPeerRoutesArray($peerIp);
        // Sanitize each route
        $routes = array_map('sanitizeOutput', $routes);
        echo json_encode(['routes' => $routes]);
        exit();
    } elseif (isset($_POST['getAllUsersRoutesArray'])) {
        $allRoutes = [];
        foreach ($users as $user) {
            if (validateIP($user['ip'])) {
                $routes = getPeerRoutesArray($user['ip']);
                // Sanitize each route
                $routes = array_map('sanitizeOutput', $routes);
                $allRoutes[sanitizeOutput($user['ip'])] = ['routes' => $routes];
            }
        }
        echo json_encode($allRoutes);
        exit();
    }
}

// Get routes for all users
$allRoutes = getPeerRoutes();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Manage L2TP Users</title>
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <style>
        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }

        @keyframes fadeOut {
            from {
                opacity: 1;
            }
            to {
                opacity: 0;
            }
        }

        .fade-in {
            animation: fadeIn 0.5s;
        }

        .fade-out {
            animation: fadeOut 0.5s;
        }

        .table-responsive {
            overflow-x: auto;
        }
        
        .routes-cell {
            text-align: left;
            max-width: 250px;
            word-wrap: break-word;
            font-size: 0.85em;
            position: relative;
        }
        
        .routes-content {
            max-height: 100px;
            overflow-y: auto;
            padding: 8px;
            background-color: #f8f9fa;
            border-radius: 4px;
            margin-bottom: 8px;
            font-family: monospace;
        }
        
        .route-actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
        }
        
        .route-item {
            background-color: #e9ecef;
            padding: 4px 8px;
            margin: 2px 0;
            border-radius: 4px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .route-text {
            flex-grow: 1;
            word-break: break-all;
        }
        
        .route-delete-btn {
            margin-left: 5px;
            padding: 0 5px;
            font-size: 0.8em;
        }
        
        .user-actions {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        
        .table th {
            background-color: #343a40;
            color: white;
        }
        
        .table-hover tbody tr:hover {
            background-color: rgba(0,0,0,.075);
        }
        
        .btn-sm {
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
        }
        
        .refresh-btn {
            background-color: #6c757d;
            border: none;
            color: white;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        
        .refresh-btn:hover {
            background-color: #5a6268;
        }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
    <div class="container-fluid">
        <a class="navbar-brand" href="#">L2TP User Manager</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item">
                    <button class="btn btn-primary nav-link" data-bs-toggle="modal" data-bs-target="#changePasswordModal">Change Password</button>
                </li>
                <li class="nav-item">
                    <form method="post" action="index.php" class="d-inline">
                        <input type="hidden" name="csrf_token" value="<?php echo sanitizeOutput(generateCSRFToken()); ?>">
                        <button type="submit" name="logout" class="btn btn-danger nav-link">Logout</button>
                    </form>
                </li>
            </ul>
        </div>
    </div>
</nav>
<div class="container mt-5">


    <h2 class="mb-4 text-center">Manage L2TP Users</h2>
     <div class="table-responsive">
        <table class="table table-hover table-bordered text-center">
            <thead class="table-dark">
            <tr>
                <th>Username</th>
                <th>Server</th>
                <th>Password</th>
                <th>IP Address</th>
                <th>Routes <button class="refresh-btn" onclick="refreshAllRoutes()" title="Refresh all routes">↻</button></th>
                <th>Actions</th>
            </tr>
            </thead>
            <tbody id="userTable">
            <?php foreach ($users as $index => $user): ?>
                <tr id="user-<?php echo $index; ?>">
                    <td><?php echo sanitizeOutput($user['client']); ?></td>
                    <td><?php echo sanitizeOutput($user['server']); ?></td>
                    <td><?php echo sanitizeOutput($user['secret']); ?></td>
                    <td><?php echo sanitizeOutput($user['ip']); ?></td>
                    <td class="routes-cell">
                        <div class="routes-content" id="routes-content-<?php echo $index; ?>">
                            <?php 
                            $routes = getPeerRoutesArray($user['ip']);
                            if (empty($routes)): 
                            ?>
                                <div class="text-muted">No routes configured</div>
                            <?php else: ?>
                                <?php foreach ($routes as $route): ?>
                                    <div class="route-item">
                                        <span class="route-text"><?php echo sanitizeOutput($route); ?></span>
                                        <button class="btn btn-danger btn-sm route-delete-btn" 
                                                data-peer-ip="<?php echo sanitizeOutput($user['ip']); ?>" 
                                                data-route="<?php echo sanitizeOutput($route); ?>" 
                                                data-row-index="<?php echo (int)$index; ?>"
                                                onclick="deleteRoute(this)" title="Delete route">×</button>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                        <div class="route-actions">
                            <button class="btn btn-sm btn-outline-primary" 
                                    data-peer-ip="<?php echo sanitizeOutput($user['ip']); ?>" 
                                    data-username="<?php echo sanitizeOutput($user['client']); ?>"
                                    onclick="openAddRouteModal(this)" title="Add route">+ Add Route</button>
                            <button class="btn btn-sm btn-outline-secondary" 
                                    data-peer-ip="<?php echo sanitizeOutput($user['ip']); ?>" 
                                    data-row-index="<?php echo (int)$index; ?>"
                                    onclick="applyRoutes(this)" title="Apply routes">▶ Apply</button>
                            <button class="btn btn-sm btn-outline-info" 
                                    data-peer-ip="<?php echo sanitizeOutput($user['ip']); ?>" 
                                    data-row-index="<?php echo (int)$index; ?>"
                                    onclick="refreshUserRoutes(this)" title="Refresh routes">↻</button>
                        </div>
                    </td>
                    <td>
                        <div class="user-actions">
                            <button class="btn btn-danger btn-sm" 
                                    data-user-index="<?php echo (int)$index; ?>" 
                                    onclick="confirmDelete(this)" 
                                    data-bs-toggle="modal" 
                                    data-bs-target="#confirmDeleteModal">Delete User</button>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div class="d-flex justify-content-center flex-wrap">
        <button class="btn btn-success me-2 mb-2" data-bs-toggle="modal" data-bs-target="#userModal">Add User</button>
        <button class="btn btn-secondary mb-2" data-bs-toggle="modal" data-bs-target="#multipleUsersModal">Add Multiple Users</button>
        <button class="btn btn-info mb-2 ms-2" data-bs-toggle="modal" data-bs-target="#routesModal">Manage Routes</button>
    </div>

    <!-- Add User Modal -->
    <div class="modal fade" id="userModal" tabindex="-1" aria-labelledby="userModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="userModalLabel">Add New User</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="addUserForm">
                        <div class="mb-3">
                            <label for="client" class="form-label">Username</label>
                            <input type="text" class="form-control" id="client" name="client" required>
                        </div>
                        <div class="mb-3">
                            <label for="server" class="form-label">Server</label>
                            <input type="text" class="form-control" id="server" name="server" value="*" readonly>
                        </div>
                        <div class="mb-3">
                            <label for="secret" class="form-label">Password</label>
                            <input type="text" class="form-control" id="secret" name="secret" required>
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="manualIpCheck" onchange="toggleManualIp('single')">
                            <label class="form-check-label" for="manualIpCheck">Set IP manually</label>
                        </div>
                        <div class="mb-3" id="ipInputSingle" style="display: none;">
                            <label for="ip" class="form-label">IP Address</label>
                            <input type="text" class="form-control" id="ip" name="ip">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="addUserButton">Add User</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Multiple Users Modal -->
    <div class="modal fade" id="multipleUsersModal" tabindex="-1" aria-labelledby="multipleUsersModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="multipleUsersModalLabel">Add Multiple Users</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="addMultipleUsersForm">
                        <div class="mb-3">
                            <label for="numUsers" class="form-label">Number of Users</label>
                            <input type="number" class="form-control" id="numUsers" name="numUsers" min="1" max="100" required>
                        </div>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="manualIpCheckMultiple" onchange="toggleManualIp('multiple')">
                            <label class="form-check-label" for="manualIpCheckMultiple">Set IP range manually</label>
                        </div>
                        <div class="mb-3" id="ipInputMultiple" style="display: none;">
                            <label for="ipRangeFrom" class="form-label">IP Range From</label>
                            <input type="text" class="form-control" id="ipRangeFrom" name="ipRangeFrom">
                            <label for="ipRangeTo" class="form-label">IP Range To</label>
                            <input type="text" class="form-control" id="ipRangeTo" name="ipRangeTo">
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-primary" id="addMultipleUsersButton">Add Users</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Confirm Delete Modal -->
    <div class="modal fade" id="confirmDeleteModal" tabindex="-1" aria-labelledby="confirmDeleteModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="confirmDeleteModalLabel">Confirm Delete</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete this user?</p>
                    <input type="hidden" id="deleteIndex" value="">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-danger" id="confirmDeleteButton">Delete User</button>
                </div>
            </div>
        </div>
    </div>

<!-- Routes Modal -->
<div class="modal fade" id="routesModal" tabindex="-1" aria-labelledby="routesModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="routesModalLabel">User Routes Management</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6">
                        <h5>Add New Route</h5>
                        <form id="addRouteForm">
                            <div class="mb-3">
                                <label for="routePeerIp" class="form-label">Peer IP</label>
                                <select class="form-control" id="routePeerIp" name="peerIp" required>
                                    <option value="">Select a user</option>
                                    <?php foreach ($users as $user): ?>
                                        <option value="<?php echo sanitizeOutput($user['ip']); ?>">
                                            <?php echo sanitizeOutput($user['client'] . ' (' . $user['ip'] . ')'); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="routeDestination" class="form-label">Destination (CIDR)</label>
                                <input type="text" class="form-control" id="routeDestination" name="destination" required placeholder="e.g., 192.168.1.0/24">
                            </div>
                            <div class="mb-3">
                                <label for="routeGateway" class="form-label">Gateway (optional, defaults to Peer IP)</label>
                                <input type="text" class="form-control" id="routeGateway" name="gateway" placeholder="e.g., 10.255.10.1">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Add Route</button>
                        </form>
                    </div>
                    <div class="col-md-6">
                        <h5>Current Routes</h5>
                        <div class="routes-list-container" style="max-height: 300px; overflow-y: auto;">
                            <pre id="routesList"><?php echo sanitizeOutput($allRoutes); ?></pre>
                        </div>
                        <div class="mt-3">
                            <button class="btn btn-secondary" onclick="refreshRoutes()">Refresh Routes</button>
                            <button class="btn btn-warning" onclick="applyAllRoutes()">Apply All Routes</button>
                        </div>
                    </div>
                </div>
                <div class="row mt-3">
                    <div class="col-12">
                        <div class="alert alert-info">
                            <h6>Route Management Commands:</h6>
                            <ul>
                                <li>Add routes for specific users - they will be applied automatically when the user connects</li>
                                <li>Routes are stored persistently and will be reapplied on system reboot</li>
                                <li>Use "Apply All Routes" to manually apply all configured routes</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Confirm Delete Route Modal -->
<div class="modal fade" id="confirmDeleteRouteModal" tabindex="-1" aria-labelledby="confirmDeleteRouteModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="confirmDeleteRouteModalLabel">Confirm Delete Route</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p>Are you sure you want to delete this route?</p>
                <p><strong>Destination:</strong> <span id="deleteRouteDestination"></span></p>
                <p><strong>Peer IP:</strong> <span id="deleteRoutePeer"></span></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger" id="confirmDeleteRouteButton">Delete</button>
            </div>
        </div>
    </div>
</div>

<!-- Error Modal -->
<div class="modal fade" id="errorModal" tabindex="-1" aria-labelledby="errorModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="errorModalLabel">Error</h5>
            </div>
            <div class="modal-body">
                <p id="errorMessage"></p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" id="errorModalClose" aria-label="Close">Close</button>
            </div>
        </div>
    </div>
</div>

<!-- Change Password Modal -->
<div class="modal fade" id="changePasswordModal" tabindex="-1" aria-labelledby="changePasswordModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="changePasswordModalLabel">Change Password</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="changePasswordForm">
                    <div class="mb-3">
                        <label for="oldPassword" class="form-label">Current Password</label>
                        <input type="password" class="form-control" id="oldPassword" name="oldPassword" required placeholder="Enter current password" autocomplete="current-password">
                    </div>
                    <div class="mb-3">
                        <label for="newPassword" class="form-label">New Password</label>
                        <input type="password" class="form-control" id="newPassword" name="newPassword" required placeholder="Enter new password" autocomplete="new-password" minlength="8" maxlength="128">
                    </div>
                    <div class="mb-3">
                        <label for="confirmPassword" class="form-label">Confirm Password</label>
                        <input type="password" class="form-control" id="confirmPassword" name="confirmPassword" required placeholder="Confirm new password" autocomplete="new-password" minlength="8" maxlength="128">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Change Password</button>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
    // Retrieve CSRF token from hidden input on the page
    function getCSRFToken() {
        const tokenInput = document.querySelector('input[name="csrf_token"]');
        return tokenInput ? tokenInput.value : '';
    }

    // Handle user form submission
    const addUserForm = document.getElementById('addUserForm');
    const addUserButton = document.getElementById('addUserButton');
    if (addUserForm && addUserButton) {
        addUserButton.addEventListener('click', function() {
            const client = document.getElementById('client').value;
            const server = document.getElementById('server').value;
            const secret = document.getElementById('secret').value;
            const ip = document.getElementById('manualIpCheck').checked ? document.getElementById('ip').value : '';

            // Client-side validation for username and IP uniqueness
            // Note: This is just for immediate feedback; server-side validation is still required
            const existingUsers = Array.from(document.querySelectorAll('#userTable tr')).slice(1); // Skip header row
            let usernameExists = false;
            let ipExists = false;
            
            for (const row of existingUsers) {
                const cells = row.querySelectorAll('td');
                if (cells.length >= 4) {
                    const existingUsername = cells[0].textContent.trim();
                    const existingIp = cells[3].textContent.trim();
                    
                    if (existingUsername === client) {
                        usernameExists = true;
                    }
                    if (existingIp === ip && ip !== '') {
                        ipExists = true;
                    }
                }
            }

            if (usernameExists) {
                document.getElementById('errorMessage').textContent = 'Username already exists';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            if (ipExists) {
                document.getElementById('errorMessage').textContent = 'IP address already exists';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            const formData = new FormData();
            formData.append('add', '1');
            formData.append('client', client);
            formData.append('server', server);
            formData.append('secret', secret);
            if (ip) formData.append('ip', ip);
            formData.append('csrf_token', getCSRFToken());

            // Show loading indicator
            const originalButtonText = addUserButton.textContent;
            addUserButton.textContent = 'Adding...';
            addUserButton.disabled = true;

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('errorMessage').textContent = data.error;
                        document.getElementById('errorModal').classList.add('show');
                        document.getElementById('errorModal').style.display = 'block';
                    } else {
                        const newRow = document.createElement('tr');
                        newRow.classList.add('fade-in');
                        const newIndex = document.getElementById('userTable').rows.length;
                        newRow.id = `user-${newIndex}`;
                        newRow.innerHTML = `
                      <td>${client}</td>
                      <td>${server}</td>
                      <td>${secret}</td>
                      <td>${data.ip}</td>  <!-- Use the IP returned from the server -->
                      <td class="routes-cell">
                        <div class="routes-content" id="routes-content-${newIndex}">
                            <div class="text-muted">No routes configured</div>
                        </div>
                        <div class="route-actions">
                            <button class="btn btn-sm btn-outline-primary" onclick="openAddRouteModal('${data.ip}', '${client}')" title="Add route">+ Add Route</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="applyRoutes('${data.ip}', ${newIndex})" title="Apply routes">▶ Apply</button>
                            <button class="btn btn-sm btn-outline-info" onclick="refreshUserRoutes('${data.ip}', ${newIndex})" title="Refresh routes">↻</button>
                        </div>
                      </td>
                      <td>
                          <div class="user-actions">
                              <button class="btn btn-danger btn-sm" onclick="confirmDelete(${newIndex})" data-bs-toggle="modal" data-bs-target="#confirmDeleteModal">Delete User</button>
                          </div>
                      </td>
                  `;
                        document.getElementById('userTable').appendChild(newRow);
                        document.getElementById('addUserForm').reset();
                        document.querySelector('#userModal .btn-close').click();
                        // Hide manual IP input if it was shown
                        document.getElementById('ipInputSingle').style.display = 'none';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('errorMessage').textContent = 'Network error: ' + error.message;
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                })
                .finally(() => {
                    // Restore button state
                    addUserButton.textContent = originalButtonText;
                    addUserButton.disabled = false;
                });
        });
    }

    // Close error modal on button click
    const errorModalClose = document.getElementById('errorModalClose');
    if (errorModalClose) {
        errorModalClose.addEventListener('click', function() {
            document.getElementById('errorModal').classList.remove('show');
            document.getElementById('errorModal').style.display = 'none';
        });
    }

    const addMultipleUsersForm = document.getElementById('addMultipleUsersForm');
    const addMultipleUsersButton = document.getElementById('addMultipleUsersButton');
    if (addMultipleUsersForm && addMultipleUsersButton) {
        addMultipleUsersButton.addEventListener('click', function() {
            const numUsers = document.getElementById('numUsers').value;
            const ipRangeFrom = document.getElementById('manualIpCheckMultiple').checked ? document.getElementById('ipRangeFrom').value : '';
            const ipRangeTo = document.getElementById('manualIpCheckMultiple').checked ? document.getElementById('ipRangeTo').value : '';

            // Validate inputs
            if (numUsers <= 0) {
                document.getElementById('errorMessage').textContent = 'Number of users must be greater than 0';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            if (document.getElementById('manualIpCheckMultiple').checked) {
                if (!ipRangeFrom || !ipRangeTo) {
                    document.getElementById('errorMessage').textContent = 'Please provide both IP range from and to values';
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                    return;
                }
                
                // Basic IP validation
                const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
                if (!ipRegex.test(ipRangeFrom) || !ipRegex.test(ipRangeTo)) {
                    document.getElementById('errorMessage').textContent = 'Please provide valid IP addresses';
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                    return;
                }
            }

            const formData = new FormData();
            formData.append('addMultiple', '1');
            formData.append('numUsers', numUsers);
            if (ipRangeFrom && ipRangeTo) {
                formData.append('ipRangeFrom', ipRangeFrom);
                formData.append('ipRangeTo', ipRangeTo);
            }
            formData.append('csrf_token', getCSRFToken());

            // Show loading indicator
            const originalButtonText = addMultipleUsersButton.textContent;
            addMultipleUsersButton.textContent = 'Adding...';
            addMultipleUsersButton.disabled = true;

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.json())
                .then(data => {
                    if (data.error) {
                        document.getElementById('errorMessage').textContent = data.error;
                        document.getElementById('errorModal').classList.add('show');
                        document.getElementById('errorModal').style.display = 'block';
                    } else {
                        location.reload();
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('errorMessage').textContent = 'Network error: ' + error.message;
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                })
                .finally(() => {
                    // Restore button state
                    addMultipleUsersButton.textContent = originalButtonText;
                    addMultipleUsersButton.disabled = false;
                });
        });
    }

    const deleteUserForm = document.getElementById('deleteUserForm');
    if (deleteUserForm) {
        deleteUserForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const index = document.getElementById('deleteIndex').value;

            const formData = new FormData();
            formData.append('delete', '1');
            formData.append('index', index);
            formData.append('csrf_token', getCSRFToken());

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.text())
                .then(data => {
                    const row = document.getElementById(`user-${index}`);
                    row.classList.add('fade-out');
                    setTimeout(() => {
                        if (row) row.remove();
                        document.querySelector('#confirmDeleteModal .btn-close').click();
                    }, 500);
                });
        });
    }

    function resetForm() {
        document.getElementById('client').value = '';
        document.getElementById('server').value = '*';
        document.getElementById('secret').value = '';
        document.getElementById('ip').value = '';
        document.getElementById('manualIpCheck').checked = false;
        document.getElementById('ipInputSingle').style.display = 'none';
    }

    function toggleManualIp(formType) {
        if (formType === 'single') {
            const isChecked = document.getElementById('manualIpCheck').checked;
            document.getElementById('ipInputSingle').style.display = isChecked ? 'block' : 'none';
        } else if (formType === 'multiple') {
            const isChecked = document.getElementById('manualIpCheckMultiple').checked;
            document.getElementById('ipInputMultiple').style.display = isChecked ? 'block' : 'none';
        }
    }

    function confirmDelete(index) {
        document.getElementById('deleteIndex').value = index;
    }

    // Handle user deletion
    const confirmDeleteButton = document.getElementById('confirmDeleteButton');
    if (confirmDeleteButton) {
        confirmDeleteButton.addEventListener('click', function() {
            const index = document.getElementById('deleteIndex').value;

            const formData = new FormData();
            formData.append('delete', '1');
            formData.append('index', index);
            formData.append('csrf_token', getCSRFToken());

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.text())
                .then(data => {
                    const row = document.getElementById(`user-${index}`);
                    row.classList.add('fade-out');
                    setTimeout(() => {
                        if (row) row.remove();
                        document.querySelector('#confirmDeleteModal .btn-close').click();
                    }, 500);
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error deleting user');
                });
        });
    }

    // Handle password change
    const changePasswordForm = document.getElementById('changePasswordForm');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const oldPassword = document.getElementById('oldPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            if (!oldPassword) {
                document.getElementById('errorMessage').textContent = 'Current password is required';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            if (newPassword !== confirmPassword) {
                document.getElementById('errorMessage').textContent = 'Passwords do not match';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            const formData = new FormData();
            formData.append('changePassword', '1');
            formData.append('oldPassword', document.getElementById('oldPassword').value);
            formData.append('newPassword', newPassword);
            formData.append('confirmPassword', confirmPassword);
            formData.append('csrf_token', getCSRFToken());

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Password changed successfully');
                        document.getElementById('newPassword').value = '';
                        document.getElementById('confirmPassword').value = '';
                        document.querySelector('#changePasswordModal .btn-close').click();
                    } else {
                        document.getElementById('errorMessage').textContent = 'Failed to change password';
                        document.getElementById('errorModal').classList.add('show');
                        document.getElementById('errorModal').style.display = 'block';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('errorMessage').textContent = 'Network error: ' + error.message;
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                });
        });
    }

    // Handle route management
    const addRouteForm = document.getElementById('addRouteForm');
    if (addRouteForm) {
        addRouteForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const peerIp = document.getElementById('routePeerIp').value;
            const destination = document.getElementById('routeDestination').value;
            const gateway = document.getElementById('routeGateway').value;

            if (!peerIp || !destination) {
                document.getElementById('errorMessage').textContent = 'Peer IP and Destination are required';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            // First, add the route
            const formData = new FormData();
            formData.append('addRoute', '1');
            formData.append('peerIp', peerIp);
            formData.append('destination', destination);
            if (gateway) formData.append('gateway', gateway);
            formData.append('csrf_token', getCSRFToken());

            // Show loading indicator
            const submitButton = document.querySelector('#addRouteForm button[type="submit"]');
            const originalButtonText = submitButton.textContent;
            submitButton.textContent = 'Adding...';
            submitButton.disabled = true;

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.json())
                .then(data => {
                    if (data.returnCode === 0) {
                        // Success - refresh the routes display
                        document.getElementById('addRouteForm').reset();
                        refreshRoutes();
                        // Refresh the routes in the table as well
                        refreshAllRoutes();
                        
                        // Show success message
                        document.getElementById('errorMessage').textContent = 'Route added and applied successfully';
                        document.getElementById('errorModal').classList.add('show');
                        document.getElementById('errorModal').style.display = 'block';
                        document.getElementById('errorModalClose').onclick = function() {
                            document.getElementById('errorModal').classList.remove('show');
                            document.getElementById('errorModal').style.display = 'none';
                        };
                    } else {
                        // Error
                        let errorMessage = 'Error adding route: ' + data.output;
                        if (data.applyOutput) {
                            errorMessage += '\nApply result: ' + data.applyOutput;
                        }
                        document.getElementById('errorMessage').textContent = errorMessage;
                        document.getElementById('errorModal').classList.add('show');
                        document.getElementById('errorModal').style.display = 'block';
                    }
                })
                .catch(error => {
                    // Error
                    document.getElementById('errorMessage').textContent = 'Network error: ' + error.message;
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                })
                .finally(() => {
                    // Restore button state
                    submitButton.textContent = originalButtonText;
                    submitButton.disabled = false;
                });
        });
    }

    function refreshRoutes() {
        // Check if routesList element exists
        const routesList = document.getElementById('routesList');
        if (!routesList) {
            console.error('Routes list element not found');
            return;
        }
        
        const formData = new FormData();
        formData.append('listRoutes', '1');
        formData.append('csrf_token', getCSRFToken());
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.text())
            .then(data => {
                document.getElementById('routesList').textContent = data;
            })
            .catch(error => {
                console.error('Error refreshing routes:', error);
                routesList.textContent = 'Error loading routes';
            });
    }

    function applyAllRoutes() {
        const formData = new FormData();
        formData.append('applyRoutes', '1');
        formData.append('peerIp', 'all');
        formData.append('csrf_token', getCSRFToken());

        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                if (data.returnCode === 0) {
                    document.getElementById('errorMessage').textContent = 'All routes applied successfully';
                } else {
                    document.getElementById('errorMessage').textContent = 'Error applying routes: ' + data.output;
                }
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
            })
            .catch(error => {
                console.error('Error applying routes:', error);
                document.getElementById('errorMessage').textContent = 'Network error applying routes: ' + error.message;
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
            });
    }

    // Function to open the add route modal with pre-filled peer IP
    function openAddRouteModal(peerIp, username) {
        // Set the peer IP in the route modal
        const peerSelect = document.getElementById('routePeerIp');
        for (let i = 0; i < peerSelect.options.length; i++) {
            if (peerSelect.options[i].value === peerIp) {
                peerSelect.selectedIndex = i;
                break;
            }
        }
        
        // Update the modal title to show which user we're adding routes for
        const modalTitle = document.querySelector('#routesModalLabel');
        const originalTitle = "User Routes Management";
        modalTitle.textContent = originalTitle + ' - ' + username + ' (' + peerIp + ')';
        
        // Show the modal
        const routesModal = new bootstrap.Modal(document.getElementById('routesModal'));
        routesModal.show();
    }
    
    // Function to delete a specific route
    function deleteRoute(button) {
        const peerIp = button.getAttribute('data-peer-ip');
        const route = button.getAttribute('data-route');
        const rowIndex = button.getAttribute('data-row-index');
        
        if (!peerIp || !route || rowIndex === null) {
            alert('Error: Missing route information');
            return;
        }
        
        // Extract destination from route (first part before space)
        const destination = route.split(' ')[0];
        
        // Check if confirmation is needed
        if (!confirm('Are you sure you want to delete this route?\n' + escapeHtml(destination))) {
            return;
        }
        
        const formData = new FormData();
        formData.append('deleteRoute', '1');
        formData.append('peerIp', peerIp);
        formData.append('destination', destination);
        formData.append('csrf_token', getCSRFToken());
        
        // Check if routes content element exists
        const contentElement = document.getElementById('routes-content-' + rowIndex);
        if (!contentElement) {
            console.error('Routes content element not found for row index:', rowIndex);
            alert('Error: Could not find routes display element');
            return;
        }
        
        // Show loading indicator
        const originalContent = contentElement.innerHTML;
        contentElement.innerHTML = '<div class="text-muted">Deleting route...</div>';
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                if (data.returnCode === 0) {
                    // Refresh the routes display
                    refreshUserRoutesByButton(button);
                    // Also refresh the routes modal if it's open
                    refreshRoutes();
                    
                    // Show success message
                    const successElement = document.createElement('div');
                    successElement.className = 'text-success mt-1';
                    successElement.textContent = 'Route deleted successfully';
                    contentElement.parentNode.insertBefore(successElement, contentElement.nextSibling);
                    setTimeout(() => {
                        if (successElement.parentNode) {
                            successElement.parentNode.removeChild(successElement);
                        }
                    }, 3000);
                } else {
                    contentElement.innerHTML = originalContent;
                    alert('Error deleting route: ' + escapeHtml(data.output || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error:', error);
                contentElement.innerHTML = originalContent;
                alert('Error deleting route');
            });
    }
    
    // Function to apply routes for a specific user
    function applyRoutes(button) {
        const peerIp = button.getAttribute('data-peer-ip');
        const rowIndex = button.getAttribute('data-row-index');
        
        if (!peerIp || rowIndex === null) {
            alert('Error: Missing route information');
            return;
        }
        
        const contentElement = document.getElementById('routes-content-' + rowIndex);
        if (!contentElement) {
            console.error('Routes content element not found for row index:', rowIndex);
            alert('Error: Could not find routes display element');
            return;
        }
        
        const originalContent = contentElement.innerHTML;
        contentElement.innerHTML = '<div class="text-muted">Applying routes...</div>';
        
        const formData = new FormData();
        formData.append('applyRoutes', '1');
        formData.append('peerIp', peerIp);
        formData.append('csrf_token', getCSRFToken());
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                if (data.returnCode === 0) {
                    contentElement.innerHTML = originalContent;
                    // Show success message
                    const successElement = document.createElement('div');
                    successElement.className = 'text-success mt-1';
                    successElement.textContent = 'Routes applied successfully';
                    contentElement.parentNode.insertBefore(successElement, contentElement.nextSibling);
                    setTimeout(() => {
                        if (successElement.parentNode) {
                            successElement.parentNode.removeChild(successElement);
                        }
                    }, 3000);
                } else {
                    contentElement.innerHTML = originalContent;
                    alert('Error applying routes: ' + escapeHtml(data.output || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error:', error);
                contentElement.innerHTML = originalContent;
                alert('Error applying routes');
            });
    }
    
    // Function to refresh routes for a specific user (by button)
    function refreshUserRoutesByButton(button) {
        const peerIp = button.getAttribute('data-peer-ip');
        const rowIndex = button.getAttribute('data-row-index');
        if (peerIp && rowIndex !== null) {
            refreshUserRoutes(peerIp, rowIndex);
        }
    }
    
    // Function to refresh routes for a specific user
    function refreshUserRoutes(peerIp, rowIndex) {
        const contentElement = document.getElementById('routes-content-' + rowIndex);
        if (!contentElement) {
            console.error('Routes content element not found for row index:', rowIndex);
            return;
        }
        
        contentElement.innerHTML = '<div class="text-muted">Loading...</div>';
        
        // Get the actual routes array
        const formData = new FormData();
        formData.append('getUserRoutesArray', '1');
        formData.append('peerIp', peerIp);
        formData.append('csrf_token', getCSRFToken());
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                if (data.routes && Array.isArray(data.routes) && data.routes.length > 0) {
                    let html = '';
                    const escapedPeerIp = escapeHtml(peerIp);
                    for (const route of data.routes) {
                        const escapedRoute = escapeHtml(route);
                        html += `<div class="route-item">
                                    <span class="route-text">${escapedRoute}</span>
                                    <button class="btn btn-danger btn-sm route-delete-btn" 
                                            data-peer-ip="${escapedPeerIp}" 
                                            data-route="${escapedRoute}" 
                                            data-row-index="${rowIndex}"
                                            onclick="deleteRoute(this)" title="Delete route">×</button>
                                 </div>`;
                    }
                    contentElement.innerHTML = html;
                } else {
                    contentElement.innerHTML = '<div class="text-muted">No routes configured</div>';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                contentElement.innerHTML = '<div class="text-danger">Error loading routes</div>';
            });
    }
    
    // Function to refresh all routes in the table
    function refreshAllRoutes() {
        // Show a loading indicator
        const routeContentElements = document.querySelectorAll('.routes-cell .routes-content');
        routeContentElements.forEach(cell => {
            cell.innerHTML = '<div class="text-muted">Loading...</div>';
        });
        
        // Get updated routes for all users
        const formData = new FormData();
        formData.append('getAllUsersRoutesArray', '1');
        formData.append('csrf_token', getCSRFToken());
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                // Update each row with the new route information
                const rows = document.querySelectorAll('#userTable tr[id^="user-"]');
                rows.forEach(row => {
                    const rowIndex = row.id.split('-')[1];
                    const userIp = row.cells[3].textContent; // IP is in the 4th column (0-indexed)
                    const contentElement = document.getElementById('routes-content-' + rowIndex);
                    
                    if (contentElement && data[userIp]) {
                        if (data[userIp].routes && Array.isArray(data[userIp].routes) && data[userIp].routes.length > 0) {
                            let html = '';
                            for (const route of data[userIp].routes) {
                                html += `<div class="route-item">
                                            <span class="route-text">${route}</span>
                                            <button class="btn btn-danger btn-sm route-delete-btn" onclick="deleteRoute('${userIp}', '${route.replace(/'/g, "\\'")}', ${rowIndex})" title="Delete route">×</button>
                                         </div>`;
                            }
                            contentElement.innerHTML = html;
                        } else {
                            contentElement.innerHTML = '<div class="text-muted">No routes configured</div>';
                        }
                    }
                });
            })
            .catch(error => {
                console.error('Error refreshing routes:', error);
                // Restore original content on error
                routeContentElements.forEach(cell => {
                    cell.innerHTML = '<div class="text-danger">Error loading routes</div>';
                });
            });
    }
</script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
