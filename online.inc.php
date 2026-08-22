<?php
/** Online VPN sessions — list + disconnect. No HTML. No chap-secrets passwords. */

function onlineSanitize($s) {
    return trim(preg_replace('/[\x00-\x1F\x7F]/', '', (string)$s));
}

function onlineRow($type, $user, $ip, $remote, $since, $iface) {
    return [
        'type' => $type, 'user' => onlineSanitize($user), 'ip' => onlineSanitize($ip),
        'remote' => onlineSanitize($remote), 'since' => onlineSanitize($since), 'iface' => onlineSanitize($iface),
    ];
}

/** Match PPP peer to chap-secrets 4th column; never return the secret. */
function chapUserByPeer($peer) {
    $peer = onlineSanitize($peer);
    if ($peer === '' || !filter_var($peer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return '';
    }
    $want = [$peer];
    if (strpos($peer, '10.200.') === 0) {
        $o = explode('.', $peer);
        if (count($o) === 4) {
            $want[] = '10.255.10.' . $o[3];
        }
    }
    $file = '/etc/ppp/chap-secrets';
    if (is_readable($file)) {
        foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $p = function_exists('parseChapLine') ? parseChapLine($line) : null;
            if (is_array($p) && isset($p['ip'], $p['client']) && in_array($p['ip'], $want, true)) {
                return onlineSanitize($p['client']);
            }
        }
    }
    foreach ($want as $ip) {
        $awk = 'sudo awk -v ip=' . escapeshellarg($ip)
            . ' \'$0 !~ /^[[:space:]]*#/ && NF>=4 { u=$1; gsub(/^"|"$/, "", u);'
            . ' if ($4==ip || $NF==ip) { print u; exit } }\' '
            . escapeshellarg($file) . ' 2>/dev/null';
        $u = onlineSanitize((string)shell_exec($awk));
        if ($u !== '') {
            return $u;
        }
    }
    return '';
}

function pppSince($iface) {
    $f = '/var/run/' . $iface . '.pid';
    $mt = is_readable($f) ? @filemtime($f) : false;
    return $mt ? date('Y-m-d H:i:s', $mt) : '';
}

function pppRemoteFromPs($iface) {
    $cmd = '';
    $f = '/var/run/' . $iface . '.pid';
    if (is_readable($f)) {
        $pid = trim((string)@file_get_contents($f));
        if ($pid !== '' && ctype_digit($pid) && is_readable('/proc/' . $pid . '/cmdline')) {
            $cmd = str_replace("\0", ' ', (string)@file_get_contents('/proc/' . $pid . '/cmdline'));
        }
    }
    if ($cmd === '') {
        $cmd = (string)shell_exec('ps -ww -C pppd -o args= 2>/dev/null');
    }
    if (preg_match_all('/\b(\d{1,3}(?:\.\d{1,3}){3})\b/', $cmd, $mm)) {
        foreach ($mm[1] as $ip) {
            if (strpos($ip, '10.255.') === 0 || strpos($ip, '10.200.') === 0 || strpos($ip, '127.') === 0) {
                continue;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $ip;
            }
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
        if ($line === '' || strpos($line, 'Updated,') === 0
            || strpos($line, 'Common Name,') === 0 || strpos($line, 'Virtual Address,') === 0) {
            continue;
        }
        $cols = str_getcsv($line);
        if ($section === 'clients' && count($cols) >= 2) {
            $clients[] = onlineRow('ovpn', $cols[0], '', $cols[1], $cols[4] ?? '', 'tun0');
        }
        if ($section === 'routes' && count($cols) >= 2) {
            $virt[onlineSanitize($cols[1])] = onlineSanitize($cols[0]);
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
    $raw = shell_exec('ip -o addr show 2>/dev/null');
    if (!is_string($raw) || $raw === '') {
        return $out;
    }
    foreach (explode("\n", $raw) as $line) {
        if (!preg_match('/^\d+:\s+(ppp\d+)\s+.*\binet\s+\S+.*\bpeer\s+(\d+\.\d+\.\d+\.\d+)/', $line, $m)) {
            continue;
        }
        $iface = $m[1];
        $peer = $m[2];
        $type = (strpos($peer, '10.200.') === 0) ? 'sstp' : 'l2tp';
        $out[] = onlineRow($type, chapUserByPeer($peer), $peer, pppRemoteFromPs($iface), pppSince($iface), $iface);
    }
    return $out;
}

function listOnlineSessions() {
    return array_merge(listOvpnOnline(), listPppOnline());
}

function ovpnKillOk($out) {
    return (stripos($out, 'SUCCESS') !== false) || (stripos($out, 'killed') !== false);
}

function disconnectSession($type, $user, $ip, $iface) {
    $type = strtolower(onlineSanitize($type));
    $user = onlineSanitize($user);
    $ip = onlineSanitize($ip);
    $iface = onlineSanitize($iface);
    if ($type === 'ovpn') {
        if ($user === '' || !preg_match('/^[A-Za-z0-9._@+-]+$/', $user)) {
            return ['success' => false, 'message' => 'Invalid OpenVPN user'];
        }
        $sock = '/var/run/openvpn-mgmt.sock';
        $kill = 'kill ' . $user;
        $out = (string)shell_exec(
            'echo ' . escapeshellarg($kill) . ' | sudo socat - UNIX-CONNECT:' . escapeshellarg($sock) . ' 2>&1'
        );
        if (ovpnKillOk($out)) {
            return ['success' => true, 'message' => 'Disconnected ' . $user . ' (ovpn)'];
        }
        $out2 = (string)shell_exec(
            'printf %s ' . escapeshellarg($kill . "\n") . ' | sudo timeout 2 nc -U ' . escapeshellarg($sock) . ' 2>&1'
        );
        if (ovpnKillOk($out2)) {
            return ['success' => true, 'message' => 'Disconnected ' . $user . ' (ovpn)'];
        }
        $py = 'import socket,sys\n'
            . 's=socket.socket(socket.AF_UNIX)\n'
            . 's.settimeout(2)\n'
            . 's.connect("/var/run/openvpn-mgmt.sock")\n'
            . 's.recv(4096)\n'
            . 's.sendall(("kill %s\\n" % sys.argv[1]).encode())\n'
            . 'print(s.recv(4096).decode(errors="replace"))\n';
        $out3 = (string)shell_exec('sudo python3 -c ' . escapeshellarg($py) . ' ' . escapeshellarg($user) . ' 2>&1');
        if (ovpnKillOk($out3)) {
            return ['success' => true, 'message' => 'Disconnected ' . $user . ' (ovpn)'];
        }
        $err = onlineSanitize(trim($out !== '' ? $out : ($out2 !== '' ? $out2 : $out3)));
        if ($err === '' || stripos($err, 'No such file') !== false || stripos($err, 'Connection refused') !== false) {
            return ['success' => false, 'message' => 'OpenVPN management socket missing or unreachable'];
        }
        return ['success' => false, 'message' => $err];
    }
    if ($type === 'l2tp' || $type === 'sstp') {
        if (!preg_match('/^ppp[0-9]+$/', $iface)) {
            return ['success' => false, 'message' => 'Invalid PPP interface'];
        }
        $pidFile = '/var/run/' . $iface . '.pid';
        $script = 'if [ -r ' . $pidFile . ' ]; then kill "$(cat ' . $pidFile . ')"; else poff ' . $iface . '; fi';
        $out = [];
        $code = 1;
        exec('sudo sh -c ' . escapeshellarg($script) . ' 2>&1', $out, $code);
        $ok = ($code === 0);
        return [
            'success' => $ok,
            'message' => $ok ? ('Disconnected ' . $iface . ' (' . $type . ')') : ('Failed to disconnect ' . $iface),
        ];
    }
    return ['success' => false, 'message' => 'Unknown session type'];
}
