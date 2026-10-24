<?php
// 管理画面のパスワードのハッシュを作る。
//   php scripts/make_password_hash.php 'あなたのパスワード'
// 出た文字列を ktrackgeo_config.php の KTG_PASSWORD_HASH に貼ってください。
if ($argc < 2) { fwrite(STDERR, "使い方: php scripts/make_password_hash.php '<パスワード>'\n"); exit(1); }
echo password_hash($argv[1], PASSWORD_DEFAULT), "\n";
