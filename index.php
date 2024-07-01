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
    }
}
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
    </div>
</div>

<!-- User Modal -->
<div class="modal fade" id="userModal" tabindex="-1" aria-labelledby="userModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="userModalLabel">Add User</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="addUserForm">
                    <div class="mb-3">
                        <label for="client" class="form-label">Username</label>
                        <input type="text" class="form-control" id="client" name="client" required placeholder="Enter username">
                        <small class="form-text text-muted">Example: user123</small>
                    </div>
                    <div class="mb-3" style="display: none;">
                        <label for="server" class="form-label">Server</label>
                        <input type="text" class="form-control" id="server" name="server" value="*" required>
                    </div>
                    <div class="mb-3">
                        <label for="secret" class="form-label">Password</label>
                        <input type="text" class="form-control" id="secret" name="secret" required placeholder="Enter password">
                        <small class="form-text text-muted">Example: P@ssw0rd123</small>
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" class="form-check-input" id="manualIpCheck" onclick="toggleManualIp('single')">
                        <label class="form-check-label" for="manualIpCheck">Select IP Manually</label>
                    </div>
                    <div class="mb-3" id="ipInputSingle" style="display: none;">
                        <label for="ip" class="form-label">IP Address</label>
                        <input type="text" class="form-control" id="ip" name="ip" placeholder="Enter IP address">
                        <small class="form-text text-muted">Example: 10.255.10.15</small>
                    </div>
                    <button type="submit" class="btn btn-success w-100">Add User</button>
                </form>
            </div>
        </div>
    </div>
</div>

<!-- Multiple Users Modal -->
<div class="modal fade" id="multipleUsersModal" tabindex="-1" aria-labelledby="multipleUsersModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="multipleUsersModalLabel">Add Multiple Users</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="addMultipleUsersForm">
                    <div class="mb-3">
                        <label for="numUsers" class="form-label">Number of Users</label>
                        <input type="number" class="form-control" id="numUsers" name="numUsers" required placeholder="Enter number of users">
                    </div>
                    <div class="mb-3 form-check">
                        <input type="checkbox" class="form-check-input" id="manualIpCheckMultiple" onclick="toggleManualIp('multiple')">
                        <label class="form-check-label" for="manualIpCheckMultiple">Select IP Manually</label>
                    </div>
                    <div class="mb-3" id="ipInputMultiple" style="display: none;">
                        <label for="ipRangeFrom" class="form-label">IP Range From</label>
                        <input type="text" class="form-control" id="ipRangeFrom" name="ipRangeFrom" placeholder="Enter starting IP address">
                        <small class="form-text text-muted">Example: 10.255.10.15</small>
                        <label for="ipRangeTo" class="form-label mt-2">IP Range To</label>
                        <input type="text" class="form-control" id="ipRangeTo" name="ipRangeTo" placeholder="Enter ending IP address">
                        <small class="form-text text-muted">Example: 10.255.10.25</small>
                    </div>
                    <button type="submit" class="btn btn-success w-100">Add Users</button>
                </form>
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
            </div>
            <div class="modal-footer">
                <form id="deleteUserForm" method="POST" action="">
                    <input type="hidden" name="index" id="deleteIndex">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Delete</button>
                </form>
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
</script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
