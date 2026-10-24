<?php
declare(strict_types=1);
/**
 * Kurage Security Check（kseccheck）— 判定の中身。
 *
 * URLを1つ受け取り、ふつうの訪問者がページを開くのと同じ範囲だけを見て、外から見える守りの弱さを判定する。
 *   - トップページ（http と https の両方）、リダイレクトの道筋、証明書、応答のヘッダー、HTML
 *   - /.well-known/security.txt（公開を前提にした決まった場所）
 *   - ページが読み込んでいる JavaScript の部品（ブラウザが読むのと同じもの）の版
 * 攻撃に近いこと（管理画面や隠しファイルを探す、パスワードを試す、弱い暗号で接続し直す）は一切しない。
 * 判定に生成AIは使わない（同じ状態なら何度測っても同じ結果）。外部APIも呼ばない。
 *
 * PHP 8.0 以上 / curl・openssl 拡張
 */

if (!defined('KSC_TIMEOUT'))      { define('KSC_TIMEOUT', 15); }
if (!defined('KSC_MAX_HTML'))     { define('KSC_MAX_HTML', 1500000); }
if (!defined('KSC_USER_AGENT'))   { define('KSC_USER_AGENT', 'Mozilla/5.0 (compatible; KurageSecurityCheck/1.0; +https://exbridge.jp/)'); }
if (!defined('KSC_ALLOW_PRIVATE')) { define('KSC_ALLOW_PRIVATE', false); }
// WordPress の新しい版の系列（これより2つ以上古い系列なら「古い」とする）。新しい版が出たら設定で上げる。
if (!defined('KSC_WP_LATEST'))    { define('KSC_WP_LATEST', '7.1'); }

/** PHP2Shell（CVE-2026-109618/109619）を直した版。これより古い 8.2〜8.5 と、8.1 以前は修正が無い。 */
const KSC_PHP_PATCHED = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
const KSC_BLOCKED_PORTS = [22, 23, 25, 445, 3306, 5432, 6379, 11211, 11434];

function ksc_categories(): array
{
    return [
        'https'    => '通信の暗号化（https・証明書）',
        'headers'  => 'ブラウザへの守りの指示',
        'exposure' => '版の見えすぎ・古い部品',
        'page'     => 'ページと入力欄',
    ];
}
function ksc_short_categories(): array
{
    return ['https' => '暗号化', 'headers' => '守りの指示', 'exposure' => '版・古い部品', 'page' => 'ページ・入力欄'];
}
const KSC_DEDUCT = ['critical' => 30, 'warning' => 10, 'info' => 3];

// ---------------------------------------------------------------------------
// URL の受け付け（内部のアドレスに向けさせない）
// ---------------------------------------------------------------------------

/** ホスト名を解決し、全部が公開アドレスなら最初のIPを返す。 @return array{0:bool,1:string} */
function ksc_public_ip(string $host): array
{
    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } else {
        $v4 = @gethostbynamel($host);
        if (is_array($v4)) { $ips = $v4; }
        $v6 = @dns_get_record($host, DNS_AAAA);
        if (is_array($v6)) { foreach ($v6 as $row) { if (!empty($row['ipv6'])) { $ips[] = $row['ipv6']; } } }
    }
    if (!$ips) { return [false, 'ホスト名を解決できませんでした: ' . $host]; }
    if (KSC_ALLOW_PRIVATE) { return [true, $ips[0]]; }
    foreach ($ips as $ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return [false, '内部ネットワークのアドレス(' . $ip . ')に解決されるURLは診断できません。'];
        }
    }
    return [true, $ips[0]];
}

/** 入力を https://ホスト/パス に整える。 @return array{0:bool,1:string} */
function ksc_validate_url(string $raw): array
{
    $v = trim($raw);
    if ($v === '') { return [false, 'URLを入力してください。']; }
    if (!str_contains($v, '://')) { $v = 'https://' . $v; }
    $p = parse_url($v);
    if ($p === false || empty($p['scheme']) || empty($p['host'])) { return [false, 'URLを読み取れませんでした。']; }
    if (!in_array(strtolower($p['scheme']), ['http', 'https'], true)) { return [false, 'http:// または https:// のURLを指定してください。']; }
    if (isset($p['port']) && in_array((int)$p['port'], KSC_BLOCKED_PORTS, true)) { return [false, 'そのポートへの接続は許可していません。']; }
    $host = strtolower($p['host']);
    [$ok, $msg] = ksc_public_ip($host);
    if (!$ok) { return [false, $msg]; }
    $path = $p['path'] ?? '/';
    if ($path === '') { $path = '/'; }
    return [true, 'https://' . $host . (isset($p['port']) ? ':' . (int)$p['port'] : '') . $path];
}

// ---------------------------------------------------------------------------
// 取得（リダイレクトは自分でたどり、1回ごとに宛先を確かめる）
// ---------------------------------------------------------------------------

/** 1回だけ取りに行く（リダイレクトは追わない）。宛先のIPは確かめたものに固定する。 */
function ksc_request(string $url, int $max = KSC_MAX_HTML): array
{
    $r = ['url' => $url, 'status' => 0, 'headers' => [], 'cookies' => [], 'body' => '', 'error' => '', 'cert_error' => '', 'location' => ''];
    $p = parse_url($url);
    if (!$p || empty($p['host'])) { $r['error'] = 'URLを読み取れませんでした'; return $r; }
    $host = strtolower($p['host']);
    $port = (int)($p['port'] ?? (($p['scheme'] ?? '') === 'http' ? 80 : 443));
    if (in_array($port, KSC_BLOCKED_PORTS, true)) { $r['error'] = 'そのポートへの接続は許可していません'; return $r; }
    [$ok, $ip] = ksc_public_ip($host);
    if (!$ok) { $r['error'] = $ip; return $r; }
    $headers = [];
    $verify = true;
    for ($try = 0; $try < 2; $try++) {
        $headers = [];
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => KSC_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_USERAGENT      => KSC_USER_AGENT,
            CURLOPT_HTTPHEADER     => ['Accept-Language: ja,en;q=0.8', 'Accept: text/html,application/xhtml+xml,*/*;q=0.8'],
            CURLOPT_ENCODING       => '',
            CURLOPT_RESOLVE        => [$host . ':' . $port . ':' . (str_contains($ip, ':') ? '[' . $ip . ']' : $ip)],
            CURLOPT_SSL_VERIFYPEER => $verify,
            CURLOPT_SSL_VERIFYHOST => $verify ? 2 : 0,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers) {
                $t = trim($line);
                if (preg_match('#^HTTP/\S+\s+\d{3}#', $t)) { $headers = []; }
                elseif (str_contains($t, ':')) { [$k, $v] = explode(':', $t, 2); $headers[] = [strtolower(trim($k)), trim($v)]; }
                return strlen($line);
            },
        ]);
        $body = curl_exec($ch);
        $errno = curl_errno($ch);
        $err = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body === false && $verify && in_array($errno, [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91], true)) {
            // 証明書が正しくない。中身は見たいので、確かめずにもう一度だけ取る（結果には「証明書の誤り」として出す）
            $r['cert_error'] = $err;
            $verify = false;
            continue;
        }
        if ($body === false) { $r['error'] = $err !== '' ? $err : '取得できませんでした'; return $r; }
        $r['status'] = $status;
        $r['body'] = substr((string)$body, 0, $max);
        break;
    }
    foreach ($headers as [$k, $v]) {
        if ($k === 'set-cookie') { $r['cookies'][] = $v; continue; }
        $r['headers'][$k] = isset($r['headers'][$k]) ? $r['headers'][$k] . ', ' . $v : $v;
    }
    if (isset($r['headers']['location'])) { $r['location'] = ksc_absolute($url, $r['headers']['location']); }
    return $r;
}

/** リダイレクトを最大6回たどる。 @return array{hops:array,final:array} */
function ksc_chain(string $url): array
{
    $hops = [];
    $cur = $url;
    for ($i = 0; $i < 7; $i++) {
        $res = ksc_request($cur);
        $hops[] = ['url' => $cur, 'status' => $res['status'], 'location' => $res['location'], 'error' => $res['error'], 'cert_error' => $res['cert_error']];
        if ($res['error'] !== '' || $res['status'] < 300 || $res['status'] >= 400 || $res['location'] === '') {
            return ['hops' => $hops, 'final' => $res];
        }
        $cur = $res['location'];
    }
    return ['hops' => $hops, 'final' => ['url' => $cur, 'status' => 0, 'headers' => [], 'cookies' => [], 'body' => '', 'error' => 'リダイレクトが多すぎます', 'cert_error' => '', 'location' => '']];
}

function ksc_absolute(string $base, string $href): string
{
    $href = trim(html_entity_decode($href, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    if ($href === '') { return ''; }
    if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $href)) { return $href; }
    $b = parse_url($base);
    if (!$b || empty($b['host'])) { return ''; }
    $root = ($b['scheme'] ?? 'https') . '://' . $b['host'] . (empty($b['port']) ? '' : ':' . $b['port']);
    if (str_starts_with($href, '//')) { return ($b['scheme'] ?? 'https') . ':' . $href; }
    if (str_starts_with($href, '/')) { return $root . $href; }
    $dir = $b['path'] ?? '/';
    $dir = str_ends_with($dir, '/') ? $dir : (rtrim(dirname($dir), '/') . '/');
    return $root . $dir . $href;
}

/** 証明書を受け取って読む（確かめはしない。期限・発行者・名前を見るため）。 */
function ksc_cert(string $host, int $port = 443): array
{
    [$ok, $ip] = ksc_public_ip($host);
    if (!$ok) { return ['error' => $ip]; }
    $ctx = stream_context_create(['ssl' => [
        'capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false,
        'peer_name' => $host, 'SNI_enabled' => true,
    ]]);
    $target = 'ssl://' . (str_contains($ip, ':') ? '[' . $ip . ']' : $ip) . ':' . $port;
    $fp = @stream_socket_client($target, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) { return ['error' => $errstr !== '' ? $errstr : '接続できませんでした']; }
    $meta = stream_get_meta_data($fp);
    $params = stream_context_get_params($fp);
    fclose($fp);
    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    $info = $cert ? openssl_x509_parse($cert) : false;
    if (!$info) { return ['error' => '証明書を読めませんでした']; }
    $names = [];
    if (!empty($info['extensions']['subjectAltName'])) {
        foreach (explode(',', $info['extensions']['subjectAltName']) as $n) {
            $n = trim($n);
            if (str_starts_with($n, 'DNS:')) { $names[] = strtolower(substr($n, 4)); }
        }
    }
    return [
        'error' => '',
        'valid_to' => (int)($info['validTo_time_t'] ?? 0),
        'issuer' => (string)($info['issuer']['O'] ?? ($info['issuer']['CN'] ?? '')),
        'names' => $names,
        'protocol' => (string)($meta['crypto']['protocol'] ?? ''),
    ];
}

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------

function ksc_add(array &$f, string $cat, string $sev, string $id, string $title, string $evidence, string $fix): void
{
    $f[] = compact('cat', 'sev', 'id', 'title', 'evidence', 'fix');
}

/** 診断する。返り値は保存してそのまま画面に出せる形。 */
function ksc_run(string $url): array
{
    $p = parse_url($url);
    $host = strtolower((string)$p['host']);
    $port = (int)($p['port'] ?? 443);
    $path = (string)($p['path'] ?? '/');
    $f = [];
    $facts = ['host' => $host];

    // 1. https で開けるか・証明書
    $https = ksc_chain('https://' . $host . ($port !== 443 ? ':' . $port : '') . $path);
    $hf = $https['final'];
    $https_ok = $hf['error'] === '' && $hf['status'] > 0;
    $cert_err = '';
    foreach ($https['hops'] as $h) { if ($h['cert_error'] !== '') { $cert_err = $h['cert_error']; break; } }
    // 2. http で開いたとき、https に切り替わるか
    $http = ksc_chain('http://' . $host . '/');
    $facts['http_hops'] = array_map(fn($h) => $h['status'] . ' ' . $h['url'], $http['hops']);
    $facts['https_hops'] = array_map(fn($h) => $h['status'] . ' ' . $h['url'], $https['hops']);

    $page = $https_ok ? $hf : $http['final'];
    if ($page['error'] !== '' || $page['status'] === 0) {
        return ['url' => $url, 'checked_at' => time(), 'error' => 'サイトを開けませんでした（' . ($page['error'] ?: '応答なし') . '）'];
    }
    $final_url = $page['url'];
    $final_https = str_starts_with(strtolower($final_url), 'https://');
    $facts['final_url'] = $final_url;
    $facts['status'] = $page['status'];

    if (!$https_ok) {
        ksc_add($f, 'https', 'critical', 'https.unavailable', 'https で開けません。通信が暗号化されず、入力した内容が途中で読まれるおそれがあります。',
            'https://' . $host . '/ : ' . ($hf['error'] ?: '応答なし'), 'サーバー会社の管理画面で、無料の証明書（Let\'s Encrypt など）を設定してください。');
    }
    if ($cert_err !== '') {
        ksc_add($f, 'https', 'critical', 'https.cert_invalid', '証明書が正しくありません。ブラウザに警告が出て、訪問者が離れます。',
            $cert_err, '証明書の期限・名前（ドメイン）・中間証明書の設定を、サーバー会社の管理画面で確かめてください。');
    }
    // http → https の切り替え
    $hlast = end($http['hops']);
    $http_final = (string)($http['final']['url'] ?? '');
    if ($https_ok) {
        if ($http['final']['error'] === '' && !str_starts_with(strtolower($http_final), 'https://')) {
            ksc_add($f, 'https', 'warning', 'https.no_redirect', 'http:// で開くと、https に切り替わりません。古いリンクやブックマークから来た人は暗号化されないまま見ています。',
                'http://' . $host . '/ → ' . ($hlast['status'] ?? '?') . ' ' . $http_final, 'http:// へのアクセスを https:// へ 301 で転送する設定を入れてください。');
        } elseif (!empty($http['hops'][0]) && in_array((int)$http['hops'][0]['status'], [302, 303, 307], true)) {
            ksc_add($f, 'https', 'info', 'https.temp_redirect', 'http から https への切り替えが「一時的な転送」になっています。',
                'http://' . $host . '/ → ' . $http['hops'][0]['status'], '恒久的な転送（301 か 308）にしてください。');
        }
    }
    // 証明書の期限・名前・通信の方式
    if ($https_ok) {
        $c = ksc_cert($host, $port);
        if (($c['error'] ?? '') === '') {
            $days = (int)floor(($c['valid_to'] - time()) / 86400);
            $facts['cert'] = ['issuer' => $c['issuer'], 'valid_to' => date('Y-m-d', $c['valid_to']), 'days' => $days, 'protocol' => $c['protocol']];
            if ($days < 0) {
                ksc_add($f, 'https', 'critical', 'https.cert_expired', '証明書の期限が切れています。', '期限: ' . date('Y-m-d', $c['valid_to']), '証明書を更新してください。');
            } elseif ($days < 14) {
                ksc_add($f, 'https', 'warning', 'https.cert_expiring', '証明書の期限が' . $days . '日後に切れます。', '期限: ' . date('Y-m-d', $c['valid_to']), '自動更新が動いているか確かめてください。');
            }
            if ($c['protocol'] !== '' && in_array($c['protocol'], ['TLSv1', 'TLSv1.1', 'SSLv3'], true)) {
                ksc_add($f, 'https', 'warning', 'https.old_tls', '古い暗号の方式（' . $c['protocol'] . '）で通信しています。', '通信の方式: ' . $c['protocol'], 'TLS 1.2 以上だけを使う設定にしてください。');
            }
        }
    }
    // HSTS
    $H = $page['headers'];
    if ($final_https) {
        $hsts = $H['strict-transport-security'] ?? '';
        if ($hsts === '') {
            ksc_add($f, 'https', 'warning', 'https.hsts_missing', '「必ず https で開く」指示（HSTS）がありません。最初の1回を http で開かれると、途中で書き換えられるおそれがあります。',
                'Strict-Transport-Security: なし', 'Strict-Transport-Security: max-age=31536000 を応答に付けてください。');
        } elseif (preg_match('/max-age\s*=\s*(\d+)/i', $hsts, $m) && (int)$m[1] < 15552000) {
            ksc_add($f, 'https', 'info', 'https.hsts_short', 'HSTS の期間が短く設定されています（' . (int)floor((int)$m[1] / 86400) . '日）。', 'Strict-Transport-Security: ' . $hsts, 'max-age を 180日（15552000）以上にしてください。');
        }
    }

    // 3. ブラウザへの守りの指示
    $csp = $H['content-security-policy'] ?? '';
    if ($csp === '') {
        ksc_add($f, 'headers', 'warning', 'headers.csp_missing', '読み込んでよいスクリプトの指定（CSP）がありません。改ざんや入力欄の穴から、悪いスクリプトを動かされやすくなります。',
            'Content-Security-Policy: なし', 'まず Content-Security-Policy-Report-Only で様子を見てから、読み込み元を絞る設定を入れてください。');
    } elseif (preg_match("/script-src[^;]*'unsafe-inline'/i", $csp) && !preg_match("/script-src[^;]*'(nonce-|sha256-)/i", $csp)) {
        ksc_add($f, 'headers', 'info', 'headers.csp_unsafe_inline', 'CSP はありますが、ページ内のスクリプトを無条件に許しています（unsafe-inline）。', 'Content-Security-Policy: ' . mb_strimwidth($csp, 0, 120, '…'), 'nonce か hash で、許すスクリプトを絞ってください。');
    }
    if (($H['x-frame-options'] ?? '') === '' && !preg_match('/frame-ancestors/i', $csp)) {
        ksc_add($f, 'headers', 'warning', 'headers.clickjacking', '他のサイトに、このページを枠の中に埋め込まれる設定のままです。偽の画面を重ねてボタンを押させる攻撃に使われます。',
            'X-Frame-Options: なし / CSP frame-ancestors: なし', 'X-Frame-Options: SAMEORIGIN（または CSP の frame-ancestors \'self\'）を付けてください。');
    }
    if (strtolower($H['x-content-type-options'] ?? '') !== 'nosniff') {
        ksc_add($f, 'headers', 'info', 'headers.nosniff', 'ファイルの種類をブラウザに推測させない指示（nosniff）がありません。', 'X-Content-Type-Options: ' . ($H['x-content-type-options'] ?? 'なし'), 'X-Content-Type-Options: nosniff を付けてください。');
    }
    if (($H['referrer-policy'] ?? '') === '') {
        ksc_add($f, 'headers', 'info', 'headers.referrer', 'ほかのサイトへ移るときに、どこまでURLを伝えるかの指定（Referrer-Policy）がありません。', 'Referrer-Policy: なし', 'Referrer-Policy: strict-origin-when-cross-origin を付けてください。');
    }
    if (($H['permissions-policy'] ?? '') === '') {
        ksc_add($f, 'headers', 'info', 'headers.permissions', 'カメラ・マイク・位置情報などを使わせない指定（Permissions-Policy）がありません。', 'Permissions-Policy: なし', '使わない機能を Permissions-Policy で止めてください（例: camera=(), microphone=(), geolocation=()）。');
    }
    // Cookie
    $weak_cookie = [];
    foreach ($page['cookies'] as $ck) {
        $name = strtolower(trim(explode('=', $ck, 2)[0]));
        $lc = strtolower($ck);
        $miss = [];
        if ($final_https && !str_contains($lc, 'secure')) { $miss[] = 'Secure'; }
        if (!str_contains($lc, 'httponly')) { $miss[] = 'HttpOnly'; }
        if (!str_contains($lc, 'samesite')) { $miss[] = 'SameSite'; }
        if ($miss) { $weak_cookie[] = $name . '（' . implode('・', $miss) . 'なし）'; }
    }
    if ($weak_cookie) {
        $session = (bool)preg_grep('/^(phpsessid|wordpress_|wp-|sess|session|jsessionid|laravel_session|ci_session)/', array_map(fn($s) => strtolower($s), $weak_cookie));
        ksc_add($f, 'headers', $session ? 'warning' : 'info', 'headers.cookie', 'Cookie の守りの属性が足りません' . ($session ? '（ログインや入力の状態を持つCookieです）' : '') . '。',
            implode(' / ', array_slice($weak_cookie, 0, 4)), 'Cookie に Secure・HttpOnly・SameSite=Lax を付けてください。');
    }

    // 4. 版の見えすぎ・古い部品
    $server = $H['server'] ?? '';
    if ($server !== '' && preg_match('#[a-z][a-z0-9_-]*/\d+(\.\d+)*#i', $server)) {
        ksc_add($f, 'exposure', 'info', 'exposure.server_version', 'サーバーのソフトの種類と版が外から見えます。', 'Server: ' . $server, '応答から版の番号を消す設定にしてください（Apache: ServerTokens Prod、nginx: server_tokens off）。');
    }
    $xpb = $H['x-powered-by'] ?? '';
    $facts['x_powered_by'] = $xpb;
    if ($xpb !== '' && preg_match('#PHP/(\d+)\.(\d+)\.(\d+)#i', $xpb, $m)) {
        $ver = $m[1] . '.' . $m[2] . '.' . $m[3];
        $branch = $m[1] . '.' . $m[2];
        if (version_compare($branch, '8.2', '<')) {
            ksc_add($f, 'exposure', 'critical', 'exposure.php_eol', 'サポートの切れたPHP（' . $ver . '）で動いています。2026年10月に公開された重大な脆弱性「PHP2Shell」の修正が出ない版です。',
                'X-Powered-By: ' . $xpb, 'PHP 8.2 以上の最新版に上げてください。上げたあと、問い合わせフォームやログインなど書き込む機能まで動くか確かめてください。');
        } elseif (isset(KSC_PHP_PATCHED[$branch]) && version_compare($ver, KSC_PHP_PATCHED[$branch], '<')) {
            ksc_add($f, 'exposure', 'critical', 'exposure.php_unpatched', 'PHP（' . $ver . '）に、重大な脆弱性「PHP2Shell」の修正が入っていません。',
                'X-Powered-By: ' . $xpb, 'PHP ' . KSC_PHP_PATCHED[$branch] . ' 以上に上げてください。');
        } else {
            ksc_add($f, 'exposure', 'warning', 'exposure.php_version', 'PHP の版（' . $ver . '）が外から見えます。穴が見つかったときに狙われやすくなります。', 'X-Powered-By: ' . $xpb, 'php.ini の expose_php = Off で、版を出さないようにしてください。');
        }
    } elseif ($xpb !== '') {
        ksc_add($f, 'exposure', 'info', 'exposure.powered_by', '使っているソフトの名前が応答に出ています。', 'X-Powered-By: ' . $xpb, 'X-Powered-By を応答から消してください。');
    }
    if (!empty($H['x-aspnet-version'])) {
        ksc_add($f, 'exposure', 'info', 'exposure.aspnet', 'ASP.NET の版が外から見えます。', 'X-AspNet-Version: ' . $H['x-aspnet-version'], 'web.config で enableVersionHeader="false" にしてください。');
    }

    $html = $page['body'];
    // CMS の版（generator）
    $gens = [];
    if (preg_match_all('#<meta[^>]+name=["\']generator["\'][^>]*>#i', $html, $mm)) {
        foreach ($mm[0] as $tag) { if (preg_match('#content=["\']([^"\']+)#i', $tag, $g)) { $gens[] = html_entity_decode($g[1]); } }
    }
    $facts['generator'] = $gens;
    $is_wp = str_contains($html, '/wp-content/') || str_contains($html, '/wp-includes/');
    $facts['wordpress'] = $is_wp;
    foreach ($gens as $g) {
        if (preg_match('#^WordPress\s+(\d+)\.(\d+)(\.\d+)?#i', $g, $m)) {
            $wv = $m[1] . '.' . $m[2] . ($m[3] ?? '');
            [$lm, $ln] = array_map('intval', explode('.', KSC_WP_LATEST));
            $behind = ($lm * 10 + $ln) - ((int)$m[1] * 10 + (int)$m[2]);
            if ((int)$m[1] < $lm - 1 || $behind >= 3) {
                ksc_add($f, 'exposure', 'critical', 'exposure.wp_old', 'WordPress 本体が古い版（' . $wv . '）のままです。古い版の穴は、攻撃の道具で自動的に狙われます。',
                    'generator: ' . $g, 'WordPress 本体・プラグイン・テーマを最新に更新し、自動更新を有効にしてください。');
            } else {
                ksc_add($f, 'exposure', 'info', 'exposure.wp_version', 'WordPress の版（' . $wv . '）がページに書かれています。', 'generator: ' . $g, '版を出さないようにしてください（テーマの functions.php で wp_generator を外す、またはSEOプラグインの設定）。');
            }
            break;
        }
    }

    // 古い JavaScript の部品
    $scripts = [];
    if (preg_match_all('#<script[^>]+src=["\']([^"\']+)["\']#i', $html, $sm)) {
        foreach ($sm[1] as $s) { $abs = ksc_absolute($final_url, $s); if ($abs !== '') { $scripts[] = $abs; } }
    }
    $scripts = array_values(array_unique($scripts));
    $facts['scripts'] = count($scripts);
    $libs = ksc_find_libs($scripts);
    foreach ($libs as $lib) {
        ksc_add($f, 'exposure', 'warning', 'exposure.js_' . $lib['key'], $lib['title'], $lib['evidence'], $lib['fix']);
    }
    $facts['libs'] = array_map(fn($l) => $l['name'] . ' ' . $l['version'], $libs);

    // 5. ページと入力欄
    if ($page['status'] >= 500) {
        ksc_add($f, 'page', 'critical', 'page.server_error', 'トップページがエラー（HTTP ' . $page['status'] . '）を返しています。訪問者にページが表示されていません。',
            $final_url . ' → ' . $page['status'], 'サーバーのエラーログを確かめ、表示できる状態に戻してください。');
    } elseif ($page['status'] >= 400) {
        ksc_add($f, 'page', 'warning', 'page.client_error', 'トップページが HTTP ' . $page['status'] . ' を返しています。', $final_url . ' → ' . $page['status'], '正しいページを返すように直してください。');
    }
    if (preg_match('#(Fatal error|Warning|Notice|Deprecated|Parse error)</b>:\s#i', $html) || preg_match('#\b(Fatal error|Warning|Notice|Deprecated): .{0,200} in /[^ ]+\.php on line \d+#i', $html)) {
        ksc_add($f, 'page', 'warning', 'page.php_error_shown', 'PHP のエラーがページにそのまま表示されています。サーバー内部のファイルの場所が外から見えます。',
            'ページ内に「Warning / Notice / Fatal error … on line」の表示', 'php.ini の display_errors = Off にし、エラーはログにだけ残してください。');
    }
    if ($final_https) {
        $mixed = [];
        if (preg_match_all('#<(script|iframe|link|img|source|embed)[^>]+(src|href)=["\']http://[^"\']+#i', $html, $xm)) {
            foreach ($xm[1] as $i => $tag) {
                $tag = strtolower($tag);
                if ($tag === 'link' && !preg_match('#rel=["\']?(stylesheet|preload|modulepreload)#i', $xm[0][$i])) { continue; }
                $mixed[] = $tag;
            }
        }
        if ($mixed) {
            $active = array_intersect($mixed, ['script', 'iframe', 'link', 'embed']);
            ksc_add($f, 'page', $active ? 'warning' : 'info', 'page.mixed', 'https のページの中で、暗号化されない http:// の部品を' . count($mixed) . '件読み込んでいます' . ($active ? '（スクリプトなど、書き換えられると危ないもの）' : '') . '。',
                implode('・', array_count_values($mixed) ? array_map(fn($k, $v) => $k . ' ' . $v . '件', array_keys(array_count_values($mixed)), array_count_values($mixed)) : []), '読み込み先の URL を https:// に直してください。');
        }
    }
    // 入力欄の送り先
    if (preg_match_all('#<form[^>]*>#i', $html, $fm)) {
        $insecure = 0;
        foreach ($fm[0] as $tag) {
            if (preg_match('#action=["\'](http://[^"\']+)#i', $tag)) { $insecure++; }
        }
        if ($insecure > 0) {
            ksc_add($f, 'page', 'critical', 'page.form_http', '入力欄の送り先が http:// になっています。入力した内容が暗号化されずに送られます。', 'form action="http://…" が' . $insecure . '件', '送り先を https:// に直してください。');
        }
    }
    if (!$final_https && preg_match('#<input[^>]+type=["\']?password#i', $html)) {
        ksc_add($f, 'page', 'critical', 'page.password_http', 'パスワードの入力欄が、暗号化されない http のページにあります。', $final_url, 'サイト全体を https にしてください。');
    }
    // 外部のスクリプトに、改ざんを見分ける印（SRI）が無い
    $ext_no_sri = 0; $ext_hosts = [];
    if (preg_match_all('#<script[^>]+src=["\']([^"\']+)["\'][^>]*>#i', $html, $em)) {
        foreach ($em[0] as $i => $tag) {
            $abs = ksc_absolute($final_url, $em[1][$i]);
            $h = strtolower((string)parse_url($abs, PHP_URL_HOST));
            if ($h === '' || $h === $host || str_ends_with($h, '.' . preg_replace('/^www\./', '', $host))) { continue; }
            $ext_hosts[$h] = true;
            if (!preg_match('#integrity=#i', $tag) && preg_match('#(cdnjs|jsdelivr|unpkg|code\.jquery|bootstrapcdn|cloudflare|ajax\.googleapis)#i', $h)) { $ext_no_sri++; }
        }
    }
    $facts['external_script_hosts'] = array_keys($ext_hosts);
    if ($ext_no_sri > 0) {
        ksc_add($f, 'page', 'info', 'page.sri', '外部の配信元（CDN）から読むスクリプト' . $ext_no_sri . '件に、改ざんを見分ける印（integrity）がありません。', '配信元: ' . implode('・', array_slice(array_keys($ext_hosts), 0, 4)), 'script タグに integrity と crossorigin を付けてください。');
    }
    // security.txt（連絡先の公開）
    $st = ksc_request(($final_https ? 'https://' : 'http://') . $host . '/.well-known/security.txt', 20000);
    $has_st = $st['status'] === 200 && preg_match('/^\s*Contact\s*:/mi', $st['body']);
    $facts['security_txt'] = (bool)$has_st;
    if (!$has_st) {
        ksc_add($f, 'page', 'info', 'page.security_txt', '弱点を見つけた人が連絡する先（security.txt）を公開していません。', '/.well-known/security.txt: ' . ($st['status'] ?: 'なし'), 'Contact: mailto:… を書いた /.well-known/security.txt を置いてください。');
    }

    return ['url' => $url, 'checked_at' => time(), 'error' => '', 'facts' => $facts, 'findings' => ksc_sort($f), 'score' => ksc_score($f)];
}

/** 読み込んでいるスクリプトから、既知の脆弱性がある古い部品を探す。ファイル名・?ver= で分からなければ、先頭を少しだけ読む（ブラウザが読むのと同じ）。 */
function ksc_find_libs(array $scripts): array
{
    $rules = [
        'jquery' => ['jQuery', '#(?:^|/)jquery(?:\.min)?(?:[-.]?(\d+\.\d+\.\d+))?(?:\.min)?\.js#i', '3.5.0', 'jQuery の古い版（%s）を使っています。既知の脆弱性（CVE-2020-11022 など）があります。', 'jQuery を 3.5.0 以上（できれば最新の 3.7 系）に上げてください。WordPress なら本体の更新で上がります。'],
        'jqueryui' => ['jQuery UI', '#jquery-ui(?:\.min)?(?:[-.]?(\d+\.\d+\.\d+))?(?:\.min)?\.js#i', '1.13.2', 'jQuery UI の古い版（%s）を使っています。既知の脆弱性（CVE-2022-31160 など）があります。', 'jQuery UI を 1.13.2 以上に上げてください。'],
        'bootstrap' => ['Bootstrap', '#bootstrap(?:\.bundle)?(?:\.min)?(?:[-.]?(\d+\.\d+\.\d+))?(?:\.min)?\.js#i', '', 'Bootstrap の古い版（%s）を使っています。既知の脆弱性（CVE-2019-8331 など）があります。', 'Bootstrap を 3.4.1 / 4.3.1 以上に上げてください。'],
        'angularjs' => ['AngularJS', '#angular(?:\.min)?(?:[-.]?(1\.\d+\.\d+))?(?:\.min)?\.js#i', '9.9.9', 'サポートの終わった AngularJS（%s）を使っています。修正が出なくなった部品です。', '別の仕組みへの移し替えを検討してください。'],
        'lodash' => ['lodash', '#lodash(?:\.min)?(?:[-.]?(\d+\.\d+\.\d+))?(?:\.min)?\.js#i', '4.17.21', 'lodash の古い版（%s）を使っています。既知の脆弱性（CVE-2021-23337 など）があります。', 'lodash を 4.17.21 以上に上げてください。'],
    ];
    $found = [];
    $peeked = 0;
    foreach ($scripts as $src) {
        $file = (string)parse_url($src, PHP_URL_PATH);
        foreach ($rules as $key => [$name, $re, $min, $title, $fix]) {
            if (isset($found[$key]) || !preg_match($re, $file, $m)) { continue; }
            if ($key === 'jquery' && stripos($file, 'jquery-ui') !== false) { continue; }
            if ($key === 'jquery' && preg_match('#jquery[-.](migrate|ui|cookie|easing|validate|form|lazy|colorbox|fancybox|slick|bxslider)#i', $file)) { continue; }
            $ver = $m[1] ?? '';
            // CDN は版をフォルダ名に持つ（/ajax/libs/jquery/3.5.1/jquery.min.js）。?ver= はテーマ側の都合で付く値のことがあるので後回し
            if ($ver === '' && preg_match('#/(\d+\.\d+\.\d+)/[^/]+$#', $file, $dm)) { $ver = $dm[1]; }
            if ($ver === '' && preg_match('#[?&]ver=(\d+\.\d+\.\d+)#', $src, $vm)) { $ver = $vm[1]; }
            if ($ver === '' && $peeked < 6) {
                $peeked++;
                $r = ksc_request($src, 3000);
                if ($r['error'] === '' && $r['status'] === 200 && preg_match('#(?:v|version[\s:\'"]*)\s*(\d+\.\d+\.\d+)#i', $r['body'], $bm)) { $ver = $bm[1]; }
            }
            if ($ver === '') { continue; }
            $old = match ($key) {
                'bootstrap' => (version_compare($ver, '3.4.1', '<')) || (str_starts_with($ver, '4.') && version_compare($ver, '4.3.1', '<')),
                'angularjs' => str_starts_with($ver, '1.'),
                default => version_compare($ver, $min, '<'),
            };
            if ($old) {
                $found[$key] = ['key' => $key, 'name' => $name, 'version' => $ver, 'title' => sprintf($title, $ver), 'evidence' => $src, 'fix' => $fix];
            }
        }
    }
    return array_values($found);
}

function ksc_sort(array $f): array
{
    $rank = ['critical' => 0, 'warning' => 1, 'info' => 2];
    usort($f, fn($a, $b) => [$rank[$a['sev']], $a['cat']] <=> [$rank[$b['sev']], $b['cat']]);
    return $f;
}

/** 点数。総合は 100 から重さに応じて引く（改善余地は合わせて15点まで）。分野ごとも同じ考え方。 */
function ksc_score(array $f): array
{
    $cats = array_fill_keys(array_keys(ksc_categories()), 100);
    $info_total = 0; $overall = 100;
    $count = ['critical' => 0, 'warning' => 0, 'info' => 0];
    foreach ($f as $x) {
        $d = KSC_DEDUCT[$x['sev']];
        $count[$x['sev']]++;
        $cats[$x['cat']] = max(0, $cats[$x['cat']] - ($x['sev'] === 'info' ? 5 : ($x['sev'] === 'warning' ? 20 : 50)));
        if ($x['sev'] === 'info') { if ($info_total >= 15) { continue; } $d = min($d, 15 - $info_total); $info_total += $d; }
        $overall -= $d;
    }
    return ['overall' => max(0, $overall), 'categories' => $cats, 'count' => $count];
}

function ksc_band(int $s): string
{
    if ($s >= 80) { return '良好'; }
    if ($s >= 60) { return 'まずまず'; }
    if ($s >= 40) { return '弱い'; }
    return '要対応';
}

/** Markdown の診断書。 */
function ksc_markdown(array $r): string
{
    $sev = ['critical' => '重大', 'warning' => '警告', 'info' => '改善余地'];
    $o = ['# Kurage Security Check 診断書', '', '- 対象: ' . $r['url'], '- 診断日時: ' . date('Y-m-d H:i', (int)$r['checked_at']) . '（日本時間）'];
    if (!empty($r['error'])) { $o[] = ''; $o[] = '診断できませんでした: ' . $r['error']; return implode("\n", $o); }
    $s = $r['score'];
    $o[] = '- 総合: ' . $s['overall'] . ' / 100（' . ksc_band((int)$s['overall']) . '）';
    $o[] = '- 指摘: 重大 ' . $s['count']['critical'] . '件 / 警告 ' . $s['count']['warning'] . '件 / 改善余地 ' . $s['count']['info'] . '件';
    $o[] = '';
    $o[] = '## 分野ごとの点';
    $o[] = '';
    foreach (ksc_categories() as $k => $label) { $o[] = '- ' . $label . ': ' . $s['categories'][$k]; }
    $o[] = '';
    $o[] = '## 指摘（重い順）';
    foreach ($r['findings'] as $i => $x) {
        $o[] = '';
        $o[] = '### ' . ($i + 1) . '. [' . $sev[$x['sev']] . '] ' . $x['title'];
        $o[] = '';
        $o[] = '- 分野: ' . ksc_categories()[$x['cat']];
        $o[] = '- 実測: ' . $x['evidence'];
        $o[] = '- 直し方: ' . $x['fix'];
        $o[] = '- 規則ID: `' . $x['id'] . '`';
    }
    if (!$r['findings']) { $o[] = ''; $o[] = '大きな問題は見つかりませんでした。'; }
    $o[] = '';
    $o[] = '## この診断が見ていないこと';
    $o[] = '';
    $o[] = 'ふつうの訪問者がページを開くのと同じ範囲だけを見ています。サーバーの中の設定、プラグインの一つひとつの脆弱性、管理画面のパスワードの強さ、社内のネットワークは見ていません。点数が高くても「安全が保証された」という意味ではありません。';
    $o[] = '';
    $o[] = '判定はすべて実測値にもとづく決まったチェックで、生成AIは使っていません。';
    return implode("\n", $o);
}
