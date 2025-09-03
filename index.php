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
    $command = "del --peer " . escapeshellarg($peerIp) . " --dst " . escapeshellarg($destination);
    return executeRouteCommand($command);
}

// Function to apply routes for a peer
function applyPeerRoutes($peerIp) {
    $command = "apply --peer " . escapeshellarg($peerIp);
    return executeRouteCommand($command);
}

$users = readUsers($file);

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
                    <td>
                        <button class="btn btn-danger btn-sm" onclick="confirmDelete(<?php echo $index; ?>)" data-bs-toggle="modal" data-bs-target="#confirmDeleteModal">Delete</button>
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
    document.getElementById('addUserForm').addEventListener('submit', function(event) {
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

    // Close error modal on button click
    document.getElementById('errorModalClose').addEventListener('click', function() {
        document.getElementById('errorModal').classList.remove('show');
        document.getElementById('errorModal').style.display = 'none';
    });

    document.getElementById('addMultipleUsersForm').addEventListener('submit', function(event) {
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

    document.getElementById('deleteUserForm').addEventListener('submit', function(event) {
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

    // Handle password change
    document.getElementById('changePasswordForm').addEventListener('submit', function(event) {
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

    // Handle route management
    document.getElementById('addRouteForm').addEventListener('submit', function(event) {
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

        const formData = new FormData();
        formData.append('addRoute', '1');
        formData.append('peerIp', peerIp);
        formData.append('destination', destination);
        if (gateway) formData.append('gateway', gateway);

        fetch('', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
            .then(data => {
                if (data.returnCode === 0) {
                    // Success
                    document.getElementById('addRouteForm').reset();
                    refreshRoutes();
                    // Show success message
                    document.getElementById('errorMessage').textContent = 'Route added successfully';
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                    document.getElementById('errorModalClose').onclick = function() {
                        document.getElementById('errorModal').classList.remove('show');
                        document.getElementById('errorModal').style.display = 'none';
                    };
                } else {
                    // Error
                    document.getElementById('errorMessage').textContent = 'Error adding route: ' + data.output;
                    document.getElementById('errorModal').classList.add('show');
                    document.getElementById('errorModal').style.display = 'block';
                }
            });
    });

    function refreshRoutes() {
        fetch('', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'listRoutes=1'
        }).then(response => response.text())
            .then(data => {
                document.getElementById('routesList').textContent = data;
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
            });
    }

    // Initialize the routes modal with current routes
    document.getElementById('routesModal').addEventListener('shown.bs.modal', function () {
        refreshRoutes();
    });
</script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
