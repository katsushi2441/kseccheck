#!/usr/bin/env bash
# デモの公開。https://proto.exbridge.jp/kseccheck/
# 設定は demo/ のものを使い、配布物の *.example は触らない。FTPは1接続にまとめる。
set -euo pipefail
cd "$(dirname "$0")/.."
/usr/bin/python3 - <<'PY'
import ftplib, os
for ln in open('/home/kojima/work/aixec/.env', encoding='utf-8'):
    if '=' in ln and not ln.startswith('#'):
        k, v = ln.split('=', 1); os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
f = ftplib.FTP(os.environ['FTP_HOST'], timeout=120); f.login(os.environ['FTP_USER'], os.environ['FTP_PASS'])
root = '/web/proto_exbridge_jp/kseccheck'
for d in (root, root + '/ksc_data', root + '/ksc_assets'):
    try: f.mkd(d)
    except ftplib.error_perm: pass
files = {'public/kseccheck.php': 'kseccheck.php', 'public/kseccheck_engine.php': 'kseccheck_engine.php', 'public/kseccheck_pro.php': 'kseccheck_pro.php',
         'demo/kseccheck_config.php': 'kseccheck_config.php', 'demo/kseccheck_pro_local.php': 'kseccheck_pro_local.php', 'demo/index.php': 'index.php', 'demo/.htaccess': '.htaccess',
         'demo/kseccheck-ogp.png': 'kseccheck-ogp.png', 'demo/kseccheck-pro-ogp.png': 'kseccheck-pro-ogp.png', 'public/ksc_data/.htaccess': 'ksc_data/.htaccess'}
for n in ('ksc-card-bold.otf', 'ksc-card-black.otf', 'mascot.png', 'logo.png', 'OFL.txt'):
    files[f'public/ksc_assets/{n}'] = f'ksc_assets/{n}'
for src, dst in files.items():
    f.storbinary(f'STOR {root}/{dst}', open(src, 'rb')); print('deployed:', dst)
f.quit()
PY
echo "published: https://proto.exbridge.jp/kseccheck/"
