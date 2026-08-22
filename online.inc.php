<?php
// Online VPN sessions — list + disconnect. Included from index.php.

function chapUserByIp($ip) {
    $file = '/etc/ppp/chap-secrets';
    if (!is_readable($file) || $ip === '') {
        return '';
    }
    foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $parsed = function_exists('parseChapLine') ? parseChapLine($line) : null;
        if ($parsed && isset($parsed['ip']) && $parsed['ip'] === $ip) {
            return (string)$parsed['client'];
        }
    }
    return '';
}

function listOvpnOnline() {
    $raw = shell_exec('sudo cat /var/log/openvpn/status.log 2>/dev/null');
    if (!is_string($raw) || $raw === '') {
        return [];
    }
    $clients = [];
    $section = '';
    $virt = [];
    foreach (preg_split("/\r\n|\n|\r/", $raw) as $line) {
        if ($line === 'OpenVPN CLIENT LIST' || strpos($line, 'CLIENT LIST') === 0) {
            $section = 'clients';
            continue;
        }
        if (strpos($line, 'ROUTING TABLE') === 0) {
            $section = 'routes';
            continue;
        }
        if (strpos($line, 'GLOBAL STATS') === 0 || $line === 'END') {
            $section = '';
            continue;
        }
        if ($line === '' || strpos($line, 'Updated,') === 0 || strpos($line, 'Common Name,') === 0 || strpos($line, 'Virtual Address,') === 0) {
            continue;
        }
        $cols = str_getcsv($line);
        if ($section === 'clients' && count($cols) >= 2) {
            $clients[] = [
                'type' => 'ovpn',
                'user' => $cols[0],
                'remote' => $cols[1],
                'since' => $cols[4] ?? '',
                'ip' => '',
                'iface' => 'tun0',
            ];
        }
        if ($section === 'routes' && count($cols) >= 2) {
            $virt[$cols[1]] = $cols[0];
        }
    }
    foreach ($clients as &$c) {
        if (isset($virt[$c['user']])) {
            $c['ip'] = $virt[$c['user']];
        }
    }
    unset($c);
    return $clients;
}

function listPppOnline() {
    $out = [];
    $raw = shell_exec("ip -o addr show 2>/dev/null");
    if (!is_string($raw) || $raw === '') {
        return $out;
    }
    foreach (explode("\n", $raw) as $line) {
        if (!preg_match('/^\d+:\s+(ppp\d+)\s+.*\binet\s+(\d+\.\d+\.\d+\.\d+).*peer\s+(\d+\.\d+\.\d+\.\d+)/', $line, $m)) {
            continue;
        }
        $iface = $m[1];
        $peer = $m[3];
        $type = (strpos($peer, '10.200.') === 0) ? 'sstp' : 'l2tp';
        $out[] = [
            'type' => $type,
            'user' => chapUserByIp($peer),
            'ip' => $peer,
            'remote' => '',
            'since' => '',
            'iface' => $iface,
        ];
    }
    return $out;
}

function listOnlineSessions() {
    return array_merge(listOvpnOnline(), listPppOnline());
}

function disconnectSession($type, $user, $ip, $iface) {
    $type = strtolower((string)$type);
    $user = (string)$user;
    $ip = (string)$ip;
    $iface = (string)$iface;

    if ($type === 'ovpn') {
        if ($user === '' || !preg_match('/^[A-Za-z0-9._@+-]+$/', $user)) {
            return ['success' => false, 'message' => 'Invalid OpenVPN user'];
        }
        $py = 'import socket,sys\n'
            . 's=socket.socket(socket.AF_UNIX)\n'
            . 's.settimeout(2)\n'
            . 's.connect("/var/run/openvpn-mgmt.sock")\n'
            . 's.recv(4096)\n'
            . 's.sendall(("kill %s\\n" % sys.argv[1]).encode())\n'
            . 'print(s.recv(4096).decode(errors="replace"))\n';
        $cmd = 'sudo python3 -c ' . escapeshellarg($py) . ' ' . escapeshellarg($user) . ' 2>&1';
        $out = (string)shell_exec($cmd);
        $ok = (stripos($out, 'SUCCESS') !== false);
        if (!$ok && strpos($out, 'No such file') !== false) {
            return ['success' => false, 'message' => 'OpenVPN management socket missing — restart openvpn after pull'];
        }
        return ['success' => $ok, 'message' => $ok ? "Disconnected $user (ovpn)" : trim($out)];
    }

    if ($type === 'l2tp' || $type === 'sstp') {
        if (!preg_match('/^ppp[0-9]+$/', $iface)) {
            return ['success' => false, 'message' => 'Invalid PPP interface'];
        }
        $pidFile = '/var/run/' . $iface . '.pid';
        $out = (string)shell_exec('sudo kill $(sudo cat ' . escapeshellarg($pidFile) . ' 2>/dev/null) 2>&1; echo $?');
        return ['success' => true, 'message' => "Disconnected $iface ($type $user $ip)"];
    }

    return ['success' => false, 'message' => 'Unknown session type'];
}
