<?php
// 手元で判定だけを試す: php scripts/check.php https://example.co.jp/ [--json]
require __DIR__ . '/../public/kseccheck_engine.php';
date_default_timezone_set('Asia/Tokyo');
[$ok, $u] = ksc_validate_url($argv[1] ?? '');
if (!$ok) { fwrite(STDERR, $u . "\n"); exit(1); }
$r = ksc_run($u);
echo in_array('--json', $argv, true) ? json_encode($r, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) : ksc_markdown($r), "\n";
