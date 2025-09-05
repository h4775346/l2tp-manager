<?php
include 'header.php';
session_start();

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit();
}

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
    $content = "# Secrets for authentication using CHAP\n";
    $content .= "# client server secret IP addresses\n";
    $content .= "tunnel tunnel tunnel *\n";
    foreach ($users as $user) {
        $content .= "{$user['client']} {$user['server']} {$user['secret']} {$user['ip']}\n";
    }
    file_put_contents($file, $content);
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
    $fullCommand = "sudo /usr/local/sbin/l2tp-routectl " . $command . " 2>&1";
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
    $command = "add --peer " . escapeshellarg($peerIp) . " --dst " . escapeshellarg($destination);
    if ($gateway) {
        $command .= " --gw " . escapeshellarg($gateway);
    }
    
    return executeRouteCommand($command);
}

// Function to delete a route
function deletePeerRoute($peerIp, $destination) {
    // First delete from the file
    $command = "del --peer " . escapeshellarg($peerIp) . " --dst " . escapeshellarg($destination);
    $result = executeRouteCommand($command);
    
    // Then delete from the actual routing table
    if ($result['returnCode'] === 0) {
        // Get the PPP interface for this peer
        $pppInterface = getPPPInterfaceForPeer($peerIp);
        if ($pppInterface) {
            // Delete the route from the actual routing table
            $deleteCommand = "sudo ip route del " . escapeshellarg($destination) . " dev " . escapeshellarg($pppInterface) . " 2>&1";
            exec($deleteCommand, $output, $returnCode);
            // We don't return this result as the main operation (deleting from file) was successful
        }
    }
    
    return $result;
}

// Function to get PPP interface for a peer IP
function getPPPInterfaceForPeer($peerIp) {
    $command = "ip link show | grep ppp | cut -d: -f2 | tr -d ' '";
    exec($command, $interfaces, $returnCode);
    
    if ($returnCode === 0 && !empty($interfaces)) {
        foreach ($interfaces as $interface) {
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
    $command = "apply --peer " . escapeshellarg($peerIp);
    return executeRouteCommand($command);
}

// Function to delete all routes for a peer
function deleteAllPeerRoutes($peerIp) {
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
    // Handle logout
    if (isset($_POST['logout'])) {
        session_destroy();
        header('Location: login.php');
        exit();
    }

    // Handle add user
    if (isset($_POST['add'])) {
        $client = $_POST['client'];
        $ip = $_POST['ip'] ?? getNextIp($users);

        // Check for duplicate username and IP
        foreach ($users as $user) {
            if ($user['client'] === $client) {
                echo json_encode(['error' => 'Username already exists']);
                exit();
            }
            if ($user['ip'] === $ip) {
                echo json_encode(['error' => 'IP address already exists']);
                exit();
            }
        }

        $newUser = [
            'client' => $client,
            'server' => '*',
            'secret' => $_POST['secret'],
            'ip' => $ip
        ];
        $users[] = $newUser;
        writeUsers($file, $users);
        echo json_encode(['ip' => $newUser['ip']]);
        exit();
    } elseif (isset($_POST['delete'])) {
        $index = (int)$_POST['index'];
        
        // Get the IP of the user being deleted
        $userIp = $users[$index]['ip'];
        
        // Delete all routes associated with this user
        deleteAllPeerRoutes($userIp);
        
        // Delete the user
        array_splice($users, $index, 1);
        writeUsers($file, $users);
        exit();
    } elseif (isset($_POST['addMultiple'])) {
        $numUsers = (int)$_POST['numUsers'];
        $ipRangeFrom = !empty($_POST['ipRangeFrom']) ? ip2long($_POST['ipRangeFrom']) : ip2long(getNextIp($users));
        $ipRangeTo = !empty($_POST['ipRangeTo']) ? ip2long($_POST['ipRangeTo']) : $ipRangeFrom + $numUsers - 1;

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
                echo json_encode(['error' => 'IP range exhausted. Please start a new range.']);
                exit();
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
        writeUsers($file, $users);
        echo json_encode(['success' => true]);
        exit();
    } elseif (isset($_POST['changePassword'])) {
        $newPassword = password_hash($_POST['newPassword'], PASSWORD_DEFAULT);

        // Read the config file
        $config = include 'config.php';

        // Update the password in the config file
        $config['admin_password'] = $newPassword;

        // Write the updated config back to the file
        file_put_contents('config.php', '<?php return ' . var_export($config, true) . ';');

        echo json_encode(['success' => true]);
        exit();
    } elseif (isset($_POST['addRoute'])) {
        $peerIp = $_POST['peerIp'];
        $destination = $_POST['destination'];
        $gateway = !empty($_POST['gateway']) ? $_POST['gateway'] : null;

        
        $result = addPeerRoute($peerIp, $destination, $gateway);
        
        // If route was added successfully, automatically apply it
        if ($result['returnCode'] === 0) {
            $applyResult = applyPeerRoutes($peerIp);
            // Combine the results
            $result['applyOutput'] = $applyResult['output'];
            $result['applyReturnCode'] = $applyResult['returnCode'];
        }
        
        echo json_encode($result);
        exit();
    } elseif (isset($_POST['deleteRoute'])) {
        $peerIp = $_POST['peerIp'];
        $destination = $_POST['destination'];

        $result = deletePeerRoute($peerIp, $destination);
        echo json_encode($result);
        exit();
    } elseif (isset($_POST['applyRoutes'])) {
        $peerIp = $_POST['peerIp'];
        $result = applyPeerRoutes($peerIp);
        echo json_encode($result);
        exit();
    } elseif (isset($_POST['listRoutes'])) {
        $allRoutes = getPeerRoutes();
        echo $allRoutes;
        exit();
    } elseif (isset($_POST['getUserRoutes'])) {
        $peerIp = $_POST['peerIp'];
        $routes = getPeerRoutesFormatted($peerIp);
        echo json_encode(['routes' => $routes]);
        exit();
    } elseif (isset($_POST['getAllUsersRoutes'])) {
        $allRoutes = [];
        foreach ($users as $user) {
            $allRoutes[$user['ip']] = getPeerRoutesFormatted($user['ip']);
        }
        echo json_encode($allRoutes);
        exit();
    } elseif (isset($_POST['getUserRoutesArray'])) {
        $peerIp = $_POST['peerIp'];
        $routes = getPeerRoutesArray($peerIp);
        echo json_encode(['routes' => $routes]);
        exit();
    } elseif (isset($_POST['getAllUsersRoutesArray'])) {
        $allRoutes = [];
        foreach ($users as $user) {
            $allRoutes[$user['ip']] = ['routes' => getPeerRoutesArray($user['ip'])];
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
                    <td><?php echo htmlspecialchars($user['client']); ?></td>
                    <td><?php echo htmlspecialchars($user['server']); ?></td>
                    <td><?php echo htmlspecialchars($user['secret']); ?></td>
                    <td><?php echo htmlspecialchars($user['ip']); ?></td>
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
                                        <span class="route-text"><?php echo htmlspecialchars($route); ?></span>
                                        <button class="btn btn-danger btn-sm route-delete-btn" onclick="deleteRoute('<?php echo $user['ip']; ?>', '<?php echo htmlspecialchars(addslashes($route)); ?>', <?php echo $index; ?>)" title="Delete route">×</button>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                        <div class="route-actions">
                            <button class="btn btn-sm btn-outline-primary" onclick="openAddRouteModal('<?php echo $user['ip']; ?>', '<?php echo htmlspecialchars(addslashes($user['client'])); ?>')" title="Add route">+ Add Route</button>
                            <button class="btn btn-sm btn-outline-secondary" onclick="applyRoutes('<?php echo $user['ip']; ?>', <?php echo $index; ?>)" title="Apply routes">▶ Apply</button>
                            <button class="btn btn-sm btn-outline-info" onclick="refreshUserRoutes('<?php echo $user['ip']; ?>', <?php echo $index; ?>)" title="Refresh routes">↻</button>
                        </div>
                    </td>
                    <td>
                        <div class="user-actions">
                            <button class="btn btn-danger btn-sm" onclick="confirmDelete(<?php echo $index; ?>)" data-bs-toggle="modal" data-bs-target="#confirmDeleteModal">Delete User</button>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div class="d-flex justify-content-center flex-wrap">
        <button class="btn btn-success me-2 mb-2" data-bs-toggle="modal" data-bs-target="#userModal" onclick="resetForm()">Add User</button>
        <button class="btn btn-secondary mb-2" data-bs-toggle="modal" data-bs-target="#multipleUsersModal">Add Multiple Users</button>
        <button class="btn btn-info mb-2 ms-2" data-bs-toggle="modal" data-bs-target="#routesModal">Manage Routes</button>
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
                                        <option value="<?php echo htmlspecialchars($user['ip']); ?>">
                                            <?php echo htmlspecialchars($user['client'] . ' (' . $user['ip'] . ')'); ?>
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
                            <pre id="routesList"><?php echo htmlspecialchars($allRoutes); ?></pre>
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
                        <label for="newPassword" class="form-label">New Password</label>
                        <input type="password" class="form-control" id="newPassword" name="newPassword" required placeholder="Enter new password">
                    </div>
                    <div class="mb-3">
                        <label for="confirmPassword" class="form-label">Confirm Password</label>
                        <input type="password" class="form-control" id="confirmPassword" name="confirmPassword" required placeholder="Confirm new password">
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Change Password</button>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
    // Handle user form submission
    const addUserForm = document.getElementById('addUserForm');
    if (addUserForm) {
        addUserForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const client = document.getElementById('client').value;
            const server = document.getElementById('server').value;
            const secret = document.getElementById('secret').value;
            const ip = document.getElementById('manualIpCheck').checked ? document.getElementById('ip').value : '';

            const formData = new FormData();
            formData.append('add', '1');
            formData.append('client', client);
            formData.append('server', server);
            formData.append('secret', secret);
            if (ip) formData.append('ip', ip);

            fetch('', {
                method: 'POST',
                body: formData
            }).then(response => response.json())  // Expecting JSON response from the server
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
                      <td>No routes</td>
                      <td>
                          <button class="btn btn-danger btn-sm" onclick="confirmDelete(${newIndex})" data-bs-toggle="modal" data-bs-target="#confirmDeleteModal">Delete</button>
                      </td>
                  `;
                        document.getElementById('userTable').appendChild(newRow);
                        resetForm();
                        document.querySelector('#userModal .btn-close').click();
                    }
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
    if (addMultipleUsersForm) {
        addMultipleUsersForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const numUsers = document.getElementById('numUsers').value;
            const ipRangeFrom = document.getElementById('manualIpCheckMultiple').checked ? document.getElementById('ipRangeFrom').value : '';
            const ipRangeTo = document.getElementById('manualIpCheckMultiple').checked ? document.getElementById('ipRangeTo').value : '';

            const formData = new FormData();
            formData.append('addMultiple', '1');
            formData.append('numUsers', numUsers);
            if (ipRangeFrom && ipRangeTo) {
                formData.append('ipRangeFrom', ipRangeFrom);
                formData.append('ipRangeTo', ipRangeTo);
            }

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
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            if (newPassword !== confirmPassword) {
                document.getElementById('errorMessage').textContent = 'Passwords do not match';
                document.getElementById('errorModal').classList.add('show');
                document.getElementById('errorModal').style.display = 'block';
                return;
            }

            const formData = new FormData();
            formData.append('changePassword', '1');
            formData.append('newPassword', newPassword);

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
        
        fetch('', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'listRoutes=1'
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
    function deleteRoute(peerIp, route, rowIndex) {
        // Extract destination from route (first part before space)
        const destination = route.split(' ')[0];
        
        // Check if confirmation is needed
        if (!confirm('Are you sure you want to delete this route?\n' + destination)) {
            return;
        }
        
        const formData = new FormData();
        formData.append('deleteRoute', '1');
        formData.append('peerIp', peerIp);
        formData.append('destination', destination);
        
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
                    refreshUserRoutes(peerIp, rowIndex);
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
                    alert('Error deleting route: ' + data.output);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                contentElement.innerHTML = originalContent;
                alert('Error deleting route');
            });
    }
    
    // Function to apply routes for a specific user
    function applyRoutes(peerIp, rowIndex) {
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
                    alert('Error applying routes: ' + data.output);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                contentElement.innerHTML = originalContent;
                alert('Error applying routes');
            });
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
        
        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                if (data.routes && Array.isArray(data.routes) && data.routes.length > 0) {
                    let html = '';
                    for (const route of data.routes) {
                        html += `<div class="route-item">
                                    <span class="route-text">${route}</span>
                                    <button class="btn btn-danger btn-sm route-delete-btn" onclick="deleteRoute('${peerIp}', '${route.replace(/'/g, "\\'")}', ${rowIndex})" title="Delete route">×</button>
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
