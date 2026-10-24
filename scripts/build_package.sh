#!/usr/bin/env bash
# 配布用の zip を作る（設定の見本・説明書つき。デモの設定・診断結果は入れない）
set -euo pipefail
cd "$(dirname "$0")/.."
out=outputs/kurage-security-check.zip; tmp=$(mktemp -d); d="$tmp/kurage-security-check"
mkdir -p "$d/ksc_data" "$d/ksc_assets" "$d/scripts"
cp public/kseccheck.php public/kseccheck_engine.php public/kseccheck_config.php.example "$d/"
cp public/ksc_data/.htaccess "$d/ksc_data/"
cp public/ksc_assets/{ksc-card-bold.otf,ksc-card-black.otf,mascot.png,logo.png,OFL.txt} "$d/ksc_assets/"
cp scripts/check.php scripts/make_password_hash.php "$d/scripts/"
cp README.md INSTALL.md CLAUDE.md AGENTS.md LICENSE "$d/"
grep -rq "FTP_PASS\|aixec/.env\|proto_exbridge_jp" "$d" && { echo "社内の設定の痕跡がある。止める" >&2; exit 1; } || true
rm -f "$out"; (cd "$tmp" && zip -qr - kurage-security-check) > "$out"; rm -rf "$tmp"
unzip -l "$out"
