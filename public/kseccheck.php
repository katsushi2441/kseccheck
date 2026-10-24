<?php
declare(strict_types=1);
/**
 * Kurage Security Check（kseccheck）— 入口の画面。
 *
 * URLを1回入れると、外から見える守りの弱さを診断し、重い順に直し方を出す。
 * 判定の中身は kseccheck_engine.php。ここは受け付け・保存・結果ページ・カード画像・診断書だけ。
 *
 * 結果ページの URL は、推測できない番号（診断ごとに作る）にする。
 * 他社のサイトの弱点を、URLを知らない人に見られないようにするため（URLのハッシュにすると誰でも引ける）。
 *
 * PHP 8.0 以上 / データベース不要 / Composer・npm 不要
 */

if (is_file(__DIR__ . '/kseccheck_config.php')) { require_once __DIR__ . '/kseccheck_config.php'; }
if (!defined('KSC_TITLE'))          { define('KSC_TITLE', 'Kurage Security Check'); }
if (!defined('KSC_PASSWORD_HASH'))  { define('KSC_PASSWORD_HASH', ''); }    // 空なら鍵なし
if (!defined('KSC_CACHE_HOURS'))    { define('KSC_CACHE_HOURS', 6); }       // 同じURLの結果を使い回す時間
if (!defined('KSC_RATE_PER_HOUR'))  { define('KSC_RATE_PER_HOUR', 20); }    // 1つのIPから1時間に新しく診断できる回数（0で無制限）
if (!defined('KSC_DATA_DIR'))       { define('KSC_DATA_DIR', __DIR__ . '/ksc_data'); }
if (!defined('KSC_KEEP_DAYS'))      { define('KSC_KEEP_DAYS', 30); }        // 結果ページを残す日数
if (!defined('KSC_CANONICAL'))      { define('KSC_CANONICAL', ''); }        // 公開URL（設定するとcanonical・OGPを出す）
if (!defined('KSC_OG_IMAGE'))       { define('KSC_OG_IMAGE', ''); }         // 入口のOGP画像のURL（1200×630）
if (!defined('KSC_DEMO_FOOTER'))    { define('KSC_DEMO_FOOTER', ''); }      // デモだけで出す案内（HTML）

require_once __DIR__ . '/kseccheck_engine.php';

date_default_timezone_set('Asia/Tokyo');
@set_time_limit(120);
session_start();

function ksc_h($v): string { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
function ksc_self(): string { return basename((string)($_SERVER['SCRIPT_NAME'] ?? 'kseccheck.php')); }
function ksc_base_url(): string
{
    if (KSC_CANONICAL !== '') { return KSC_CANONICAL; }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    return ($https ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost') . (string)($_SERVER['SCRIPT_NAME'] ?? '/kseccheck.php');
}

// --- 鍵（任意）
$locked = KSC_PASSWORD_HASH !== '';
if ($locked && isset($_POST['password'])) {
    if (password_verify((string)$_POST['password'], KSC_PASSWORD_HASH)) { $_SESSION['ksc_ok'] = 1; header('Location: ' . ksc_self()); exit; }
}
$authed = !$locked || !empty($_SESSION['ksc_ok']);

// --- 保存
function ksc_dir(): string { if (!is_dir(KSC_DATA_DIR)) { @mkdir(KSC_DATA_DIR, 0755, true); } return KSC_DATA_DIR; }
function ksc_urlkey(string $url): string { return substr(sha1('ksc|' . strtolower(rtrim($url, '/'))), 0, 16); }
function ksc_load(string $token): ?array
{
    $token = preg_replace('/[^0-9a-f]/', '', $token);
    if ($token === '') { return null; }
    $f = ksc_dir() . '/r-' . $token . '.json';
    if (!is_file($f)) { return null; }
    $d = json_decode((string)file_get_contents($f), true);
    return is_array($d) ? $d : null;
}
function ksc_save(array $r): string
{
    $token = bin2hex(random_bytes(10));
    $r['token'] = $token;
    file_put_contents(ksc_dir() . '/r-' . $token . '.json', json_encode($r, JSON_UNESCAPED_UNICODE));
    file_put_contents(ksc_dir() . '/u-' . ksc_urlkey($r['url']) . '.json', json_encode(['token' => $token, 'at' => $r['checked_at']]));
    ksc_prune();
    return $token;
}
/** 同じURLの新しい結果があれば返す。 */
function ksc_cached(string $url): ?array
{
    $f = ksc_dir() . '/u-' . ksc_urlkey($url) . '.json';
    if (!is_file($f)) { return null; }
    $u = json_decode((string)file_get_contents($f), true);
    if (!is_array($u) || time() - (int)($u['at'] ?? 0) >= KSC_CACHE_HOURS * 3600) { return null; }
    return ksc_load((string)$u['token']);
}
/** 古い結果を消す（たまに）。 */
function ksc_prune(): void
{
    if (random_int(1, 20) !== 1) { return; }
    $limit = time() - KSC_KEEP_DAYS * 86400;
    foreach (glob(ksc_dir() . '/{r,u,og}-*', GLOB_BRACE) ?: [] as $f) { if (filemtime($f) < $limit) { @unlink($f); } }
}
function ksc_rate_ok(): bool
{
    if (KSC_RATE_PER_HOUR <= 0) { return true; }
    $id = substr(sha1('ksc|' . ($_SERVER['REMOTE_ADDR'] ?? '') . '|' . __DIR__), 0, 16);
    $f = ksc_dir() . '/rate-' . $id . '.json';
    $now = time();
    $t = is_file($f) ? (json_decode((string)file_get_contents($f), true) ?: []) : [];
    $t = array_values(array_filter($t, fn($x) => is_int($x) && $x > $now - 3600));
    if (count($t) >= KSC_RATE_PER_HOUR) { return false; }
    $t[] = $now;
    file_put_contents($f, json_encode($t));
    return true;
}
function ksc_host(array $r): string { return preg_replace('/^www\./i', '', (string)parse_url((string)$r['url'], PHP_URL_HOST)); }

/** Xに貼る文（URLは別に付ける）。 */
function ksc_share_text(array $r): string
{
    $s = $r['score'];
    $host = str_replace('.', '．', ksc_host($r));   // 半角の「.」だと X がリンクにしてそのサイトのカードを出す
    return '【' . KSC_TITLE . "】\n" . $host . ' の外から見える守りを診断しました'
        . "\n総合 " . $s['overall'] . '点（' . ksc_band((int)$s['overall']) . '）・重大 ' . $s['count']['critical'] . '件・警告 ' . $s['count']['warning'] . '件'
        . "\nURLを入れるだけで、https・守りの設定・古い部品をチェックできます\n#セキュリティ #情報漏洩対策";
}

/** 結果カード（1200×630のPNG）。文字は ksc_assets/ の切り出しフォント（scripts/make_card_fonts.py）。 */
function ksc_card_png(array $r): string
{
    $W = 1200; $H = 630;
    $im = imagecreatetruecolor($W, $H);
    imagealphablending($im, true);
    $c = fn($hex) => imagecolorallocate($im, hexdec(substr($hex, 1, 2)), hexdec(substr($hex, 3, 2)), hexdec(substr($hex, 5, 2)));
    $paper = $c('#f4f7fb'); $ink = $c('#1b2a3a'); $muted = $c('#5d6b7a'); $line = $c('#dde5ef'); $white = $c('#ffffff');
    $navy = $c('#1f4e8c'); $red = $c('#c0392b'); $gold = $c('#8a5a00'); $teal = $c('#076f67');
    imagefilledrectangle($im, 0, 0, $W, $H, $paper);
    for ($x = 0; $x < $W; $x++) { $t = $x / $W; $col = imagecolorallocate($im, (int)(31 + (10 - 31) * $t), (int)(78 + (154 - 78) * $t), (int)(140 + (143 - 140) * $t)); imageline($im, $x, 0, $x, 9, $col); }
    $B = __DIR__ . '/ksc_assets/ksc-card-bold.otf';
    $K = __DIR__ . '/ksc_assets/ksc-card-black.otf';
    $text = function ($size, $x, $y, $col, $font, $str, $align = 'l') use ($im) {
        $bb = imagettfbbox($size, 0, $font, $str); $w = $bb[2] - $bb[0];
        if ($align === 'c') { $x -= (int)($w / 2); } elseif ($align === 'r') { $x -= $w; }
        imagettftext($im, $size, 0, (int)$x, (int)$y, $col, $font, $str);
        return $w;
    };
    $round = function ($x1, $y1, $x2, $y2, $rad, $fill, $border = null) use ($im) {
        foreach ([[$border, 0], [$fill, $border !== null ? 2 : 0]] as [$col, $in]) {
            if ($col === null) { continue; }
            $a = $x1 + $in; $b = $y1 + $in; $c2 = $x2 - $in; $d = $y2 - $in; $rr = max(1, $rad - $in);
            imagefilledrectangle($im, $a + $rr, $b, $c2 - $rr, $d, $col);
            imagefilledrectangle($im, $a, $b + $rr, $c2, $d - $rr, $col);
            foreach ([[$a + $rr, $b + $rr], [$c2 - $rr, $b + $rr], [$a + $rr, $d - $rr], [$c2 - $rr, $d - $rr]] as [$cx, $cy]) { imagefilledellipse($im, $cx, $cy, $rr * 2, $rr * 2, $col); }
        }
    };
    $text(26, 64, 74, $navy, $B, 'セキュリティ診断結果（外から見える守り）');
    $host = ksc_host($r);
    for ($size = 56; $size > 24; $size -= 2) { $bb = imagettfbbox($size, 0, $K, $host); if ($bb[2] - $bb[0] <= 1072) { break; } }
    $text($size, 64, 160, $ink, $K, $host);
    $s = $r['score'];
    $ov = (int)$s['overall'];
    $col = $ov >= 80 ? $teal : ($ov >= 60 ? $navy : ($ov >= 40 ? $gold : $red));
    $round(64, 200, 404, 520, 22, $white, $line);
    $text(24, 234, 252, $muted, $B, '総合', 'c');
    $text(110, 234, 400, $col, $K, (string)$ov, 'c');
    $text(20, 234, 440, $muted, $B, '/ 100', 'c');
    $text(26, 234, 492, $col, $B, ksc_band($ov), 'c');
    $short = ksc_short_categories();
    $i = 0;
    foreach (ksc_categories() as $k => $_) {
        $x = 432 + ($i % 2) * 300; $y = 200 + intdiv($i, 2) * 112;
        $round($x, $y, $x + 280, $y + 96, 18, $white, $line);
        $text(19, $x + 20, $y + 40, $muted, $B, $short[$k]);
        $v = (int)$s['categories'][$k];
        $text(40, $x + 260, $y + 80, $v >= 80 ? $teal : ($v >= 50 ? $navy : $red), $K, (string)$v, 'r');
        $i++;
    }
    $cnt = '重大 ' . $s['count']['critical'] . '件　警告 ' . $s['count']['warning'] . '件　改善余地 ' . $s['count']['info'] . '件';
    $text(22, 432, 470, $ink, $B, $cnt);
    $mascot = __DIR__ . '/ksc_assets/mascot.png';
    if (is_file($mascot) && ($m = @imagecreatefrompng($mascot))) { imagecopy($im, $m, $W - imagesx($m) - 24, $H - imagesy($m) - 14, 0, 0, imagesx($m), imagesy($m)); }
    $text(18, 64, 586, $muted, $B, 'Kurage Security Check で診断・' . date('Y年n月j日', (int)$r['checked_at']));
    ob_start(); imagepng($im, null, 6); imagedestroy($im);
    return (string)ob_get_clean();
}

// --- カード画像（?og=番号）と結果ページ（?r=番号）
$error = '';
$result = null;
$share = false;
if (isset($_GET['og'])) {
    $r = ksc_load((string)$_GET['og']);
    if (!$r || !empty($r['error']) || !function_exists('imagettftext')) { http_response_code(404); exit; }
    $png = ksc_dir() . '/og-' . $r['token'] . '.png';
    if (!is_file($png)) { file_put_contents($png, ksc_card_png($r)); }
    header('Content-Type: image/png');
    header('Cache-Control: public, max-age=86400');
    readfile($png);
    exit;
}
if (isset($_GET['r'])) {
    $result = ksc_load((string)$_GET['r']);
    if ($result) { $share = true; } else { http_response_code(404); $error = 'この診断結果は見つかりませんでした（30日を過ぎた結果は消えます）。もう一度診断してください。'; }
}

$url_in = trim((string)($_GET['url'] ?? $_POST['url'] ?? ''));
if ($authed && $url_in !== '' && !$share) {
    [$ok, $checked] = ksc_validate_url($url_in);
    if (!$ok) {
        $error = $checked;
    } else {
        $cached = ksc_cached($checked);
        if ($cached && empty($_POST['again'])) {
            $result = $cached;
        } elseif (!ksc_rate_ok()) {
            $error = '1時間に診断できる回数を超えました。しばらくしてからお試しください。';
            $result = $cached;
        } else {
            $result = ksc_run($checked);
            if (empty($result['error'])) { $result['token'] = ksc_save($result); }
        }
        if ($result && empty($result['error']) && ($_GET['format'] ?? '') === 'md') {
            $h = preg_replace('/[^a-z0-9.-]/i', '', ksc_host($result));
            header('Content-Type: text/markdown; charset=UTF-8');
            header('Content-Disposition: attachment; filename="kseccheck-' . $h . '-' . date('Ymd', (int)$result['checked_at']) . '.md"');
            echo ksc_markdown($result);
            exit;
        }
        // 結果は番号付きのページで見せる（共有も印刷もそのURLで）
        if ($result && empty($result['error']) && !empty($result['token']) && ($_GET['format'] ?? '') !== 'md') {
            header('Location: ' . ksc_self() . '?r=' . $result['token'] . '&new=1');
            exit;
        }
    }
}

$sev_label = ['critical' => '重大', 'warning' => '警告', 'info' => '改善余地'];
$self = ksc_self();
$page_url = $share && $result ? ksc_base_url() . '?r=' . $result['token'] : (KSC_CANONICAL !== '' ? KSC_CANONICAL : ksc_base_url());
$desc = 'URLを入れるだけで、ホームページの外から見える守りを診断。https と証明書、ブラウザへの守りの指示、PHP・WordPress・jQuery などの古い版、入力欄の送り先を調べ、重い順に直し方を出します。攻撃に近い検査はしません。';
?><!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<?php if ($share && $result && empty($result['error'])): $sh = ksc_host($result); $s = $result['score'];
  $st = $sh . 'のセキュリティ診断結果｜総合' . $s['overall'] . '点';
  $sd = $sh . ' の外から見える守り（https・守りの設定・古い部品・入力欄）を診断した結果です（' . date('Y年n月j日', (int)$result['checked_at']) . '）。あなたのサイトもURLを入れるだけで診断できます。';
  $si = ksc_base_url() . '?og=' . $result['token']; ?>
<title><?= ksc_h($st) ?></title>
<meta name="description" content="<?= ksc_h($sd) ?>">
<meta name="robots" content="noindex,nofollow">
<meta property="og:type" content="article">
<meta property="og:site_name" content="<?= ksc_h(KSC_TITLE) ?>">
<meta property="og:title" content="<?= ksc_h($st) ?>">
<meta property="og:description" content="<?= ksc_h($sd) ?>">
<meta property="og:url" content="<?= ksc_h($page_url) ?>">
<meta property="og:image" content="<?= ksc_h($si) ?>"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta property="og:locale" content="ja_JP">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="<?= ksc_h($si) ?>">
<?php else: ?>
<title><?= ksc_h(KSC_TITLE) ?>｜URLを入れるだけのセキュリティ診断</title>
<meta name="description" content="<?= ksc_h($desc) ?>">
<?php if (KSC_CANONICAL !== ''): ?>
<link rel="canonical" href="<?= ksc_h(KSC_CANONICAL) ?>">
<meta property="og:type" content="website">
<meta property="og:site_name" content="<?= ksc_h(KSC_TITLE) ?>">
<meta property="og:title" content="<?= ksc_h(KSC_TITLE) ?>｜URLを入れるだけのセキュリティ診断">
<meta property="og:description" content="<?= ksc_h($desc) ?>">
<meta property="og:url" content="<?= ksc_h(KSC_CANONICAL) ?>">
<meta property="og:locale" content="ja_JP">
<?php if (KSC_OG_IMAGE !== ''): ?><meta property="og:image" content="<?= ksc_h(KSC_OG_IMAGE) ?>"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:image" content="<?= ksc_h(KSC_OG_IMAGE) ?>"><?php endif; ?>
<meta name="twitter:card" content="summary_large_image">
<script type="application/ld+json"><?= json_encode(['@context' => 'https://schema.org', '@graph' => [
  ['@type' => 'WebApplication', 'name' => KSC_TITLE, 'url' => KSC_CANONICAL, 'applicationCategory' => 'SecurityApplication', 'operatingSystem' => 'Web', 'description' => $desc,
   'provider' => ['@type' => 'Organization', 'name' => '株式会社エクスブリッジ', 'url' => 'https://exbridge.jp/']],
  ['@type' => 'FAQPage', 'mainEntity' => [
    ['@type' => 'Question', 'name' => '他社のサイトを診断しても大丈夫ですか？', 'acceptedAnswer' => ['@type' => 'Answer', 'text' => 'この診断は、ふつうの訪問者がページを開くのと同じ範囲だけを見ます。管理画面を探す、パスワードを試すといった攻撃に近いことはしません。ただし、結果を相手をおとしめる目的で公開することはやめてください。']],
    ['@type' => 'Question', 'name' => '点数が高ければ安全ですか？', 'acceptedAnswer' => ['@type' => 'Answer', 'text' => '外から見える範囲で、よくある弱さが無いという意味です。サーバーの中の設定、プラグインごとの脆弱性、パスワードの強さは見ていないので、安全が保証されたという意味ではありません。']],
    ['@type' => 'Question', 'name' => '診断に生成AIを使いますか？', 'acceptedAnswer' => ['@type' => 'Answer', 'text' => '使いません。決まったチェックだけで判定するので、同じ状態なら何度測っても同じ結果になります。']],
  ]],
]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?></script>
<?php endif; ?>
<?php endif; ?>
<link rel="icon" href="ksc_assets/logo.png">
<style>
:root{--ink:#1b2a3a;--muted:#5d6b7a;--paper:#f4f7fb;--line:#dde5ef;--navy:#1f4e8c;--navy-d:#163a69;--teal:#0a9a8f;--teal-d:#076f67;--red:#c0392b;--gold:#8a5a00}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Hiragino Sans","Noto Sans JP",sans-serif;line-height:1.8;font-size:16px}
a{color:var(--navy)}
.wrap{width:min(1000px,calc(100% - 32px));margin:0 auto}
header{background:#fff;border-bottom:1px solid var(--line)}
header .wrap{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 0;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:900;color:var(--ink);text-decoration:none;font-size:17px;line-height:1.3}
.brand img{width:34px;height:34px;object-fit:contain;flex:none}
.brand small{display:block;font-size:12px;color:var(--muted);font-weight:700}
.hero{display:flex;gap:18px;align-items:center;margin:22px 0 10px}
.hero .mascot{width:110px;height:auto;object-fit:contain;flex:none}
h1{font-size:clamp(22px,4.6vw,34px);line-height:1.4;margin:0 0 6px}
.lead{color:var(--muted);margin:0}
.pshare{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0 16px}
.pshare .btn{padding:6px 14px;font-size:13px}
form.q{display:flex;gap:8px;flex-wrap:wrap;background:#fff;border:1px solid var(--line);border-radius:16px;padding:14px}
form.q input[type=text],form.q input[type=password]{flex:1 1 260px;min-width:0;font-size:16px;padding:12px 14px;border:1px solid #c8d4e3;border-radius:10px}
form.q button{background:var(--navy);color:#fff;border:0;border-radius:999px;padding:12px 24px;font-weight:900;font-size:16px;cursor:pointer}
.note{font-size:13px;color:var(--muted)}
.err{background:#fdecea;border:1px solid #f3b9b2;color:#8a2a1f;border-radius:12px;padding:10px 14px;margin:14px 0}
.top{display:grid;grid-template-columns:minmax(0,260px) minmax(0,1fr);gap:12px;margin:18px 0}
.ov{background:#fff;border:1px solid var(--line);border-radius:16px;padding:16px;text-align:center}
.ov .k{font-size:13px;color:var(--muted);font-weight:800}
.ov .v{font-size:64px;font-weight:900;line-height:1.1}
.ov .v small{font-size:18px;color:var(--muted)}
.ov .b{font-size:18px;font-weight:900}
.ov .n{font-size:13px;margin-top:6px}
.cats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.cat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px 14px;display:flex;justify-content:space-between;align-items:center;gap:8px;font-size:14px;font-weight:700}
.cat b{font-size:28px;line-height:1}
.c-good{color:var(--teal-d)} .c-mid{color:var(--navy)} .c-gold{color:var(--gold)} .c-bad{color:var(--red)}
h2{font-size:21px;margin:30px 0 8px}
.list{background:#fff;border:1px solid var(--line);border-radius:14px;padding:6px 16px}
.item{border-bottom:1px solid var(--line);padding:12px 0}
.item:last-child{border-bottom:0}
.item .t{font-weight:800}
.item .e,.item .a{font-size:13.5px;color:var(--muted);word-break:break-all}
.item .a{color:var(--ink)}
.tag{display:inline-block;font-size:11.5px;font-weight:900;border-radius:999px;padding:1px 9px;margin-right:6px;vertical-align:1px}
.tag.critical{background:#fdecea;color:var(--red)} .tag.warning{background:#fff4d6;color:var(--gold)} .tag.info{background:#e7f0fb;color:var(--navy)}
.tag.cat2{background:#eef2f7;color:var(--muted)}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--navy);background:#fff;color:var(--navy);border-radius:999px;padding:9px 18px;font-weight:900;text-decoration:none;font-size:14px;cursor:pointer;font-family:inherit}
.btn.main{background:var(--navy);color:#fff}
.btn.xb{background:#111;border-color:#111;color:#fff}
.box{background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.facts{font-size:13.5px;color:var(--muted)}
.facts b{color:var(--ink)}
.share{background:#fff;border:2px solid var(--navy);border-radius:16px;padding:16px;margin:22px 0}
.share h2{margin:0 0 10px;font-size:19px}
.share img{display:block;width:100%;max-width:600px;height:auto;border-radius:12px;border:1px solid var(--line)}
.share pre{white-space:pre-wrap;word-break:break-all;font-family:inherit;font-size:14px;background:var(--paper);border-radius:10px;padding:10px 12px;margin:12px 0}
.share .bt{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.ok{font-size:13px;color:var(--teal-d);font-weight:800}
.cta-diag{background:linear-gradient(135deg,#e9f0fa,#e6f6f3);border:2px solid var(--navy);border-radius:18px;padding:18px 18px 8px;margin:22px 0}
.cta-diag h2{margin:0 0 6px;font-size:21px;color:var(--navy-d)}
.cta-diag p{margin:0 0 12px;font-size:14.5px}
.what{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,220px),1fr));gap:10px;margin:14px 0}
.what div{background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px 14px;font-size:14px}
.what b{display:block;color:var(--navy-d);font-size:15px}
.running{display:none;align-items:center;gap:12px;background:#fff;border:2px solid var(--navy);border-radius:14px;padding:14px 16px;margin:14px 0;font-weight:800;color:var(--navy)}
.running.on{display:flex}
.running .spin{width:26px;height:26px;border:4px solid #d6e1f0;border-top-color:var(--navy);border-radius:50%;animation:ksc-spin .9s linear infinite;flex:none}
@keyframes ksc-spin{to{transform:rotate(360deg)}}
button[disabled]{opacity:.55;cursor:wait}
footer{margin-top:40px;padding:20px 0;border-top:1px solid var(--line);font-size:13px;color:var(--muted);background:#fff}
@media(max-width:640px){.top{grid-template-columns:1fr}.cats{grid-template-columns:1fr}.hero{align-items:flex-start;gap:12px}.hero .mascot{width:58px}h1{font-size:22px}}
@media print{header,form.q,.actions,.pshare,.share,.cta-diag,.demo{display:none}body{background:#fff}.list,.cat,.box,.ov{break-inside:avoid}}
</style>
</head>
<body>
<header><div class="wrap">
  <a class="brand" href="<?= ksc_h($self) ?>"><img src="ksc_assets/logo.png" alt="株式会社エクスブリッジ" width="34" height="34"><span><?= ksc_h(KSC_TITLE) ?><small>URLを入れるだけのセキュリティ診断</small></span></a>
</div></header>
<main class="wrap">
<?php if (!$authed): ?>
  <h1>ログイン</h1>
  <form class="q" method="post"><input type="password" name="password" placeholder="パスワード" required><button type="submit">開く</button></form>
<?php else: ?>
  <?php $is_result = $result && empty($result['error']); ?>
  <div class="hero">
    <img class="mascot" src="ksc_assets/mascot.png" alt="Kurage" width="110" height="110">
    <div>
      <h1><?= $is_result ? ksc_h(ksc_host($result)) . ' のセキュリティ診断結果' : 'URLを入れるだけで、ホームページの守りを診断' ?></h1>
      <p class="lead"><?= $is_result ? '外から見える守りの弱さを、重い順に並べました（' . ksc_h(date('Y年n月j日 H:i', (int)$result['checked_at'])) . '時点）。' : 'https と証明書、ブラウザへの守りの指示、PHP・WordPress・jQuery などの古い版、入力欄の送り先を調べ、直し方を重い順に出します。' ?></p>
    </div>
  </div>
  <?php // 共有・コピーは、システム名と概要の文をURLと一緒に渡す（URLだけでは何のページか伝わらない）
  $ptext = $is_result ? ksc_share_text($result) : '【' . KSC_TITLE . "】\nURLを入れるだけで、ホームページの外から見える守りを診断するシステムです。https と証明書、ブラウザへの守りの設定、古いPHP・WordPress・jQuery、入力欄の送り先を調べ、直し方を重い順に出します。\n#セキュリティ #情報漏洩対策";
  $purl = $page_url; ?>
  <div class="pshare">
    <a class="btn xb" target="_blank" rel="noopener" href="https://x.com/intent/post?<?= ksc_h(http_build_query(['text' => $ptext, 'url' => $purl . '#ref=x-share-ksc'])) ?>">𝕏 Xで共有</a>
    <button class="btn cp" type="button" data-copy="<?= ksc_h($ptext . "\n" . $purl . '#ref=copy-ksc') ?>">紹介文とURLをコピー</button>
    <span class="ok" hidden>コピーしました</span>
  </div>

<?php if (!$is_result): ?>
  <form class="q js-run" method="get" action="<?= ksc_h($self) ?>">
    <input type="text" name="url" inputmode="url" placeholder="https://example.co.jp/" value="<?= ksc_h($url_in) ?>" required aria-label="診断するURL">
    <button type="submit">診断する</button>
  </form>
  <div class="running" id="running" role="status" aria-live="polite"><span class="spin"></span><span>診断しています。10秒ほどお待ちください（<span id="running-sec">0</span>秒）</span></div>
  <?php if ($error !== ''): ?><div class="err"><?= ksc_h($error) ?></div><?php endif; ?>
  <p class="note">同じURLの結果は<?= (int)KSC_CACHE_HOURS ?>時間使い回します。結果のページは、診断した人だけが分かる番号付きのURLになり、検索エンジンには出ません。</p>
  <h2>何を調べるか</h2>
  <div class="what">
    <div><b>通信の暗号化</b>https で開けるか、http から切り替わるか、証明書の期限、「必ず https で開く」指示</div>
    <div><b>ブラウザへの守りの指示</b>読み込んでよいスクリプトの指定、埋め込みの禁止、Cookie の守りの属性など</div>
    <div><b>版の見えすぎ・古い部品</b>サポートの切れた PHP、古い WordPress、既知の脆弱性がある jQuery・Bootstrap など</div>
    <div><b>ページと入力欄</b>入力欄の送り先、暗号化されない部品の読み込み、エラー表示、連絡先（security.txt）</div>
  </div>
  <div class="box"><b>攻撃に近い検査はしません。</b>ふつうの訪問者がページを開くのと同じ範囲だけを見ます。管理画面を探す、パスワードを試す、隠しファイルを探すといったことはしないので、他社のサイトに使っても相手のサーバーに負担や害を与えません。そのぶん、サーバーの中の設定やプラグインごとの脆弱性は分かりません。判定に生成AIは使わないので、同じ状態なら何度測っても同じ結果になります。</div>
<?php else: $s = $result['score']; $cls = fn($v) => $v >= 80 ? 'c-good' : ($v >= 60 ? 'c-mid' : ($v >= 40 ? 'c-gold' : 'c-bad')); ?>
  <p class="note">対象：<a href="<?= ksc_h($result['facts']['final_url'] ?? $result['url']) ?>" rel="nofollow noopener" target="_blank"><?= ksc_h($result['facts']['final_url'] ?? $result['url']) ?></a></p>
  <div class="top">
    <div class="ov"><div class="k">総合</div><div class="v <?= $cls((int)$s['overall']) ?>"><?= (int)$s['overall'] ?><small> / 100</small></div><div class="b <?= $cls((int)$s['overall']) ?>"><?= ksc_h(ksc_band((int)$s['overall'])) ?></div>
      <div class="n">重大 <b><?= (int)$s['count']['critical'] ?></b>件・警告 <b><?= (int)$s['count']['warning'] ?></b>件・改善余地 <b><?= (int)$s['count']['info'] ?></b>件</div></div>
    <div class="cats">
      <?php foreach (ksc_categories() as $k => $label): $v = (int)$s['categories'][$k]; ?><div class="cat"><span><?= ksc_h($label) ?></span><b class="<?= $cls($v) ?>"><?= $v ?></b></div><?php endforeach; ?>
    </div>
  </div>

  <?php if (function_exists('ksc_demo_after_score')) { echo ksc_demo_after_score($result, !isset($_GET['new'])); } ?>

  <h2>直すこと（重い順）</h2>
  <div class="list">
    <?php foreach ($result['findings'] as $x): ?>
      <div class="item"><div class="t"><span class="tag <?= ksc_h($x['sev']) ?>"><?= ksc_h($sev_label[$x['sev']]) ?></span><span class="tag cat2"><?= ksc_h(ksc_short_categories()[$x['cat']]) ?></span><?= ksc_h($x['title']) ?></div>
        <div class="e">実測：<?= ksc_h($x['evidence']) ?></div>
        <div class="a">直し方：<?= ksc_h($x['fix']) ?></div></div>
    <?php endforeach; if (!$result['findings']): ?><div class="item">外から見える範囲では、大きな問題は見つかりませんでした。</div><?php endif; ?>
  </div>

  <?php $fa = $result['facts']; ?>
  <h2>見えた情報</h2>
  <div class="box facts">
    <div><b>http で開いたとき：</b><?= ksc_h(implode(' → ', $fa['http_hops'] ?? [])) ?></div>
    <?php if (!empty($fa['cert'])): ?><div><b>証明書：</b><?= ksc_h($fa['cert']['issuer']) ?>・期限 <?= ksc_h($fa['cert']['valid_to']) ?>（あと<?= (int)$fa['cert']['days'] ?>日）・<?= ksc_h($fa['cert']['protocol']) ?></div><?php endif; ?>
    <div><b>作り：</b><?= ksc_h(($fa['wordpress'] ?? false) ? 'WordPress' : '') ?><?= ksc_h(implode('・', $fa['generator'] ?? [])) ?: '（判別できる表示なし）' ?></div>
    <div><b>読み込んでいるスクリプト：</b><?= (int)($fa['scripts'] ?? 0) ?>件<?= !empty($fa['external_script_hosts']) ? '（外部：' . ksc_h(implode('・', array_slice($fa['external_script_hosts'], 0, 6))) . '）' : '' ?></div>
  </div>
  <p class="note">この診断は、ふつうの訪問者がページを開くのと同じ範囲だけを見ています。サーバーの中の設定、プラグインごとの脆弱性、パスワードの強さ、社内のネットワークは見ていません。点数が高くても、安全が保証されたという意味ではありません。</p>

  <?php $rurl = ksc_base_url() . '?r=' . $result['token']; $stext = ksc_share_text($result); ?>
  <div class="share" id="share">
    <h2>この結果を共有する</h2>
    <img src="<?= ksc_h(ksc_base_url() . '?og=' . $result['token']) ?>" alt="<?= ksc_h(ksc_host($result)) ?>のセキュリティ診断結果のカード" width="1200" height="630" loading="lazy">
    <pre><?= ksc_h($stext . "\n" . $rurl) ?></pre>
    <div class="bt">
      <a class="btn xb" target="_blank" rel="noopener" href="https://x.com/intent/post?<?= ksc_h(http_build_query(['text' => $stext, 'url' => $rurl . '#ref=x-share-ksc'])) ?>">𝕏 Xに投稿</a>
      <button class="btn cp" type="button" data-copy="<?= ksc_h($stext . "\n" . $rurl . '#ref=copy-ksc') ?>">投稿文をコピー</button>
      <span class="ok" hidden>コピーしました</span>
    </div>
    <p class="note">ご自身のサイトの結果を共有するためのものです。他社のサイトの結果を、相手をおとしめる目的で公開しないでください。</p>
  </div>

  <div class="actions">
    <a class="btn main" href="<?= ksc_h($self) ?>?url=<?= rawurlencode($result['url']) ?>&amp;format=md">診断書（Markdown）をダウンロード</a>
    <button class="btn" type="button" onclick="window.print()">印刷・PDFで保存</button>
    <form class="js-run" method="post" action="<?= ksc_h($self) ?>?url=<?= rawurlencode($result['url']) ?>" style="display:inline"><input type="hidden" name="again" value="1"><button class="btn" type="submit">いま測り直す</button></form>
  </div>

  <div class="cta-diag" id="diag">
    <h2>ほかのサイトも診断する</h2>
    <form class="q js-run" method="get" action="<?= ksc_h($self) ?>">
      <input type="text" name="url" inputmode="url" placeholder="例: https://example.co.jp/" value="" required aria-label="診断するURL">
      <button type="submit">診断する</button>
    </form>
    <div class="running" id="running" role="status" aria-live="polite"><span class="spin"></span><span>診断しています。10秒ほどお待ちください（<span id="running-sec">0</span>秒）</span></div>
    <p class="note">判定はすべて実測値にもとづく決まったチェックで、生成AIは使っていません。</p>
  </div>
<?php endif; ?>
<?php endif; ?>
<?= KSC_DEMO_FOOTER ?>
</main>
<footer><div class="wrap"><?= ksc_h(KSC_TITLE) ?>（MIT License）・提供：株式会社エクスブリッジ</div></footer>
<script>
document.querySelectorAll('.cp').forEach(function(b){b.addEventListener('click',function(){
  var t=b.getAttribute('data-copy'),ok=b.parentNode.querySelector('.ok');
  function done(){if(ok){ok.hidden=false;setTimeout(function(){ok.hidden=true},2000)}}
  function fb(){var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(e){}document.body.removeChild(a)}
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,fb)}else{fb()}
})});
document.querySelectorAll('form.js-run').forEach(function (f) {
  f.addEventListener('submit', function () {
    document.querySelectorAll('form.js-run button').forEach(function (b) { b.disabled = true; });
    f.querySelectorAll('button').forEach(function (b) { b.textContent = '診断中…'; });
    var box = f.parentNode.querySelector('.running') || document.getElementById('running');
    if (box) { box.classList.add('on'); var t = 0, sec = box.querySelector('#running-sec'); setInterval(function () { t++; if (sec) sec.textContent = t; }, 1000); }
  });
});
window.addEventListener('pageshow', function (e) { if (e.persisted) { document.querySelectorAll('form.js-run button').forEach(function (b) { b.disabled = false; }); document.querySelectorAll('.running').forEach(function (x) { x.classList.remove('on'); }); } });
</script>
</body>
</html>
