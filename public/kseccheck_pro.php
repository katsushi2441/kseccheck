<?php
declare(strict_types=1);
/**
 * Kurage Security Check — Pro との接続（設定に KSC_PRO_URL と KSC_PRO_KEY があるときだけ働く）。
 *
 * - Pro のサーバーが鍵を受け付けている間（＝顧問の契約中）は、Pro の点検を結果に足す。
 * - 鍵が止まる・期限が切れる・つながらない、のどれでも、何も足さずノーマル版のまま動く（エラーは出さない）。
 * - Pro の点検（https の設定の詳しい読み取り・脆弱性一覧による部品の照合・プラグインの版の照合）は、
 *   所有を確かめたドメインだけにかかる。確かめは Pro のサーバー側で行う。
 * - ノーマル版の判定（kseccheck_engine.php）には手を入れない。
 */

if (!defined('KSC_PRO_URL')) { define('KSC_PRO_URL', ''); }   // 例: https://exbridge.ddns.net:18394
if (!defined('KSC_PRO_KEY')) { define('KSC_PRO_KEY', ''); }   // 契約ごとの鍵（kscp_…）

function ksc_pro_enabled(): bool { return KSC_PRO_URL !== '' && KSC_PRO_KEY !== '' && function_exists('curl_init'); }

/** @return array{0:int,1:?array} [HTTP状態, JSON]。つながらなければ [0, null] */
function ksc_pro_call(string $method, string $path, ?array $body = null, int $timeout = 15): array
{
    if (!ksc_pro_enabled()) { return [0, null]; }
    $ch = curl_init(rtrim(KSC_PRO_URL, '/') . $path);
    $h = ['X-KSC-Key: ' . KSC_PRO_KEY, 'Accept: application/json'];
    $opt = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_FOLLOWLOCATION => false];
    if ($method === 'POST') {
        $h[] = 'Content-Type: application/json';
        $opt[CURLOPT_POST] = true;
        $opt[CURLOPT_POSTFIELDS] = json_encode($body ?? [], JSON_UNESCAPED_UNICODE);
    }
    $opt[CURLOPT_HTTPHEADER] = $h;
    curl_setopt_array($ch, $opt);
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($raw === false) { return [0, null]; }
    $j = json_decode((string)$raw, true);
    return [$code, is_array($j) ? $j : null];
}

/** 契約中なら状態を返す（10分覚えておく）。契約が切れていれば null＝ノーマル版。 */
function ksc_pro_status(bool $fresh = false): ?array
{
    if (!ksc_pro_enabled()) { return null; }
    $f = ksc_dir() . '/pro-status.json';
    if (!$fresh && is_file($f) && time() - filemtime($f) < 600) {
        $s = json_decode((string)file_get_contents($f), true);
        return is_array($s) && !empty($s['ok']) ? $s : null;
    }
    [$code, $j] = ksc_pro_call('GET', '/v1/status', null, 8);
    $s = ($code === 200 && $j && !empty($j['ok'])) ? $j : ['ok' => false, 'code' => $code];
    @file_put_contents($f, json_encode($s, JSON_UNESCAPED_UNICODE));
    return !empty($s['ok']) ? $s : null;
}

function ksc_pro_domain_verified(array $status, string $host): bool
{
    $host = strtolower($host);
    foreach ((array)($status['domains'] ?? []) as $d) { if ($host === $d || str_ends_with($host, '.' . $d)) { return true; } }
    return false;
}

/** ノーマル版の診断の結果に、Pro の点検を足す（契約中で、所有を確かめたドメインのときだけ）。 */
function ksc_pro_attach(array $result): array
{
    if (!empty($result['error'])) { return $result; }
    $st = ksc_pro_status();
    if (!$st) { return $result; }
    $host = (string)parse_url((string)$result['url'], PHP_URL_HOST);
    if (!ksc_pro_domain_verified($st, $host)) { return $result; }
    @set_time_limit(300);
    [$code, $j] = ksc_pro_call('POST', '/v1/check', ['url' => $result['url']], 240);
    if ($code === 200 && $j) { $result['pro'] = $j; }
    elseif (in_array($code, [401, 403], true)) { @unlink(ksc_dir() . '/pro-status.json'); }
    return $result;
}

/** 所有の確かめ（結果ページのボタンから）。 */
function ksc_pro_verify(string $domain, string $action): ?array
{
    [$code, $j] = ksc_pro_call('POST', '/v1/verify', ['domain' => $domain, 'action' => $action], 30);
    if ($code === 200 && $j) {
        if (!empty($j['verified'])) { @unlink(ksc_dir() . '/pro-status.json'); }
        return $j;
    }
    return null;
}

function ksc_pro_md(array $p): string
{
    $sev = ['critical' => '重大', 'warning' => '警告', 'info' => '改善余地'];
    $o = ['', '## Pro の点検（所有を確かめたドメインだけ）', '', '- Pro の点: ' . (int)$p['score'] . ' / 100'];
    foreach ((array)$p['findings'] as $i => $x) {
        $o[] = '';
        $o[] = '### ' . ($i + 1) . '. [' . ($sev[$x['sev']] ?? $x['sev']) . '] ' . $x['title'];
        $o[] = '- 実測: ' . $x['evidence'];
        $o[] = '- 直し方: ' . $x['fix'];
    }
    if (empty($p['findings'])) { $o[] = ''; $o[] = 'Pro の点検では問題は見つかりませんでした。'; }
    return implode("\n", $o);
}

/** 結果ページに出す Pro の欄。契約が切れていれば空文字（何も出ない）。 */
function ksc_pro_section(array $result, ?array $vmsg): string
{
    $st = ksc_pro_status();
    if (!$st) { return ''; }
    $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $host = strtolower((string)parse_url((string)$result['url'], PHP_URL_HOST));
    $sev = ['critical' => '重大', 'warning' => '警告', 'info' => '改善余地'];
    $cat = ['pro_tls' => 'https の設定', 'pro_js' => '部品の脆弱性', 'pro_wp' => 'プラグイン'];
    $o = '<section class="pro" aria-label="Pro の点検"><h2>Pro の点検 <span class="probadge">Pro</span></h2>';
    if (!empty($result['pro'])) {
        $p = $result['pro'];
        $o .= '<p class="note">所有を確かめた ' . $e($host) . ' に、https の設定の詳しい読み取り・脆弱性一覧による部品の照合・プラグインの版の照合をかけました。</p>';
        $o .= '<div class="top"><div class="ov"><div class="k">Pro の点</div><div class="v">' . (int)$p['score'] . '<small> / 100</small></div>';
        if (!empty($p['diff']) && $p['diff']['prev_score'] !== null) {
            $d = $p['diff'];
            $o .= '<div class="n">前回（' . $e(date('n/j', (int)$d['prev_at'])) . '）' . (int)$d['prev_score'] . '点';
            if ($d['fixed']) { $o .= '・直った ' . count($d['fixed']) . '件'; }
            if ($d['new']) { $o .= '・新しい指摘 ' . count($d['new']) . '件'; }
            $o .= '</div>';
        }
        $o .= '</div><div class="cats">';
        $tls = $p['tls'] ?? [];
        if (!empty($tls['protocols'])) {
            $on = array_keys(array_filter($tls['protocols']));
            $o .= '<div class="cat"><span>受け付ける暗号の方式</span><b style="font-size:14px">' . $e(implode(' / ', $on)) . '</b></div>';
        }
        if (!empty($tls['cert']['not_after'])) {
            $o .= '<div class="cat"><span>証明書の検証</span><b style="font-size:14px">' . ($tls['cert']['valid'] ? '通る' : '通らない') . '・期限 ' . $e($tls['cert']['not_after']) . '</b></div>';
        }
        $o .= '<div class="cat"><span>照合した部品</span><b>' . count((array)($p['js'] ?? [])) . '</b></div>';
        $o .= '<div class="cat"><span>照合したプラグイン</span><b>' . count((array)($p['wordpress'] ?? [])) . '</b></div>';
        $o .= '</div></div>';
        $o .= '<div class="list">';
        foreach ((array)$p['findings'] as $x) {
            $o .= '<div class="item"><div class="t"><span class="tag ' . $e($x['sev']) . '">' . $e($sev[$x['sev']] ?? $x['sev']) . '</span><span class="tag cat2">' . $e($cat[$x['cat']] ?? $x['cat']) . '</span>' . $e($x['title']) . '</div>'
                . '<div class="e">実測：' . $e($x['evidence']) . '</div><div class="a">直し方：' . $e($x['fix']) . '</div></div>';
        }
        if (empty($p['findings'])) { $o .= '<div class="item">Pro の点検では問題は見つかりませんでした。</div>'; }
        $o .= '</div>';
    } elseif (ksc_pro_domain_verified($st, $host)) {
        $o .= '<p class="note">このドメインは所有を確かめてあります。「いま測り直す」を押すと、Pro の点検が付きます。</p>';
    } else {
        $o .= '<p>Pro の点検は、所有を確かめたドメインだけにかけます。' . $e($host) . ' が御社のサイトなら、次のどちらかで所有を確かめてください。</p>';
        if ($vmsg && !empty($vmsg['token'])) {
            $o .= '<ol><li>ファイルで確かめる：<code>' . $e($vmsg['file']['url'] ?? '') . '</code> に、次の1行を書いたテキストファイルを置く<br><code>' . $e($vmsg['token']) . '</code></li>'
                . '<li>DNS で確かめる：<code>' . $e($vmsg['dns']['name'] ?? '') . '</code> に TXT レコード <code>' . $e($vmsg['token']) . '</code> を足す</li></ol>';
            if (!empty($vmsg['checked']) && empty($vmsg['verified'])) { $o .= '<p class="err">まだ確かめられませんでした。置いたあと、数分おいてもう一度押してください。</p>'; }
            $o .= '<form method="post" style="display:inline"><input type="hidden" name="pro_verify" value="check"><input type="hidden" name="domain" value="' . $e($host) . '"><button class="btn main" type="submit">置いたので確かめる</button></form>';
        } else {
            $o .= '<form method="post" style="display:inline"><input type="hidden" name="pro_verify" value="start"><input type="hidden" name="domain" value="' . $e($host) . '"><button class="btn main" type="submit">所有の確かめを始める</button></form>';
        }
    }
    return $o . '</section>';
}

const KSC_PRO_CSS = '.pro{background:#fff;border:2px solid #7a3fa8;border-radius:16px;padding:16px;margin:22px 0}.pro h2{margin:0 0 8px}.probadge{display:inline-block;background:#7a3fa8;color:#fff;font-size:12px;border-radius:999px;padding:1px 10px;vertical-align:middle}.pro .ov .v{color:#7a3fa8}.pro code{background:#f4f0fa;padding:1px 6px;border-radius:6px;word-break:break-all}';
