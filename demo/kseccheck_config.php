<?php
// デモ（https://proto.exbridge.jp/kseccheck/）の設定。配布物の kseccheck_config.php.example は触らない。
if (is_file(__DIR__ . '/kseccheck_pro_local.php')) { require_once __DIR__ . '/kseccheck_pro_local.php'; }   // Pro の接続先と鍵（git 外）
define('KSC_TITLE', 'Kurage Security Check Pro');   // デモは Pro 版（当社の契約の鍵で動く・所有確認は当社ドメインだけ）
define('KSC_PRO_DEMO', true);
define('KSC_PASSWORD_HASH', '');          // デモは鍵なし
define('KSC_CACHE_HOURS', 6);
define('KSC_RATE_PER_HOUR', 10);          // デモは1つのIPから1時間に10回まで
define('KSC_CANONICAL', 'https://proto.exbridge.jp/kseccheck/kseccheck.php');
define('KSC_OG_IMAGE', 'https://proto.exbridge.jp/kseccheck/kseccheck-pro-ogp.png');
define('KSC_DEMO_FOOTER', (($_SERVER['HTTP_HOST'] ?? '') === 'proto.exbridge.jp')
  ? '<div class="demo box" style="margin-top:28px"><b>これはデモです。</b>'
  . 'このシステムは、御社のレンタルサーバーにPHPを置くだけで動きます（データベース不要）。社内のサイトや取引先の点検に、自社の中で使えます。'
  . '<div class="actions"><a class="btn main" href="https://kappstore.exbridge.jp/app.php?id=a96e95e176b48800&amp;ref=kseccheck-demo">導入版（Kurage App Store）</a>'
  . '<a class="btn" href="https://exbridge.jp/ai-it-komon.html#ref=kseccheck-demo">AI-IT顧問（点検と直しを引き受けます）</a>'
  . '<a class="btn" href="https://exbridge.jp/ai-sns-komon.html#ref=kseccheck-demo">AI-SNS顧問（ホームページとX）</a></div></div>'
  . '<script src=https://kurage.exbridge.jp/partner-bar.js defer></script>'
  // 計測は proto の他のデモと同じく kurage.exbridge.jp/simpletrack.php に集約（2026-10-25。入れ忘れていて流入が測れなかった）
  . "<script>(function(){var s=document.createElement('script');s.src='https://kurage.exbridge.jp/simpletrack.php?url='+encodeURIComponent(location.href)+'&ref='+encodeURIComponent(document.referrer);s.async=true;document.head.appendChild(s)})();</script>"
  : '');

/** 点数のすぐ下に出す案内（デモだけ）。$visitor は結果ページを開いた人が診断した本人でない可能性があるとき true。 */
function ksc_demo_after_score(array $r, bool $visitor): string
{
  if (($_SERVER['HTTP_HOST'] ?? '') !== 'proto.exbridge.jp') { return ''; }
  $e = static fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
  $c = $r['score']['count'];
  $n = $c['critical'] + $c['warning'];
  $ref = $visitor ? 'ksc-share-komon' : 'ksc-result-komon';
  if ($n > 0) {
    $h = 'この' . $n . '件の直し、AI-IT顧問の時間の中で引き受けます';
    $lead = '重大 ' . (int)$c['critical'] . '件・警告 ' . (int)$c['warning'] . '件が見つかりました。下の「直すこと」を、AIを使って短い時間で直し、この診断で測り直して点数で確かめます。'
      . 'この診断では見えないサーバーの中の設定や、WordPressのプラグイン、PHPの更新まで点検します。';
  } else {
    $h = '外から見える守りは整っています。次は中の点検です';
    $lead = 'この診断で見えるのは外側だけです。サーバーの中の設定、WordPressのプラグイン、PHPの版、バックアップまで、AI-IT顧問で点検します。';
  }
  $contact = 'https://exbridge.jp/contact.php?' . http_build_query(['ref' => $ref, 'subject' => 'AI-IT顧問（セキュリティの点検）について／診断：' . (string)parse_url((string)$r['url'], PHP_URL_HOST)]);
  return '<section class="cta-diag" aria-label="AI-IT顧問のご案内" style="background:#fff">'
    . '<h2>' . $e($h) . '</h2><p>' . $lead . '</p>'
    . '<div class="actions"><a class="btn main" href="https://exbridge.jp/ai-it-komon.html#ref=' . $e($ref) . '">AI-IT顧問を見る</a>'
    . '<a class="btn" href="' . $e($contact) . '">この結果について相談する</a></div></section>';
}
