# 設置手順

**AIエージェント（Claude Code / Codex など）に、このファイルを渡してください。**手順を読んで設置まで進めます。

## 1. ファイルを上げる

サーバーに、FTPで次のファイルを置きます（配布の zip ならその中身、リポジトリなら `public/` の中身）。

```
kseccheck.php             入口（URLを入れて診断する画面）
kseccheck_engine.php      判定の中身
ksc_assets/               カード画像の文字・マスコット・ロゴ
ksc_data/.htaccess        ← 忘れると診断結果が外から読めます
```

**確認**：`https://あなたのサイト/…/ksc_data/.htaccess` を開いて 403 になること。

## 2. 設定ファイルを作る

`kseccheck_config.php.example` をコピーして `kseccheck_config.php` にします。

- **社外から見える場所に置くなら、パスワードを設定してください**（`php scripts/make_password_hash.php` でハッシュを作り、`KSC_PASSWORD_HASH` に入れる）
- `KSC_ALLOW_PRIVATE` は、社内サイトを診断するときだけ true にします。公開する場所では絶対に true にしません

## 3. PHP の版と、書き込めるかを確かめる

- PHP 8.0 以上で動かします。レンタルサーバーで PHP の版を指定する場合、**指定の書き方によっては PHP がファイルの持ち主ではないユーザーで動き、`ksc_data/` に書き込めないことがあります**
- **確認**：自社のサイトを1回診断し、`ksc_data/` に `r-….json` ができ、結果ページ（`?r=…`）とカード画像（`?og=…`）が開くこと

## 4. 人に伝える

`kseccheck.php` のURLを伝えます。**確認していないものを「できました」と言わないでください。**

## 5. Pro を使う場合（顧問契約のお客様）

1. 当社から受け取った鍵を `kseccheck_config.php` の `KSC_PRO_URL` / `KSC_PRO_KEY` に書く
2. 自社のサイトを1回診断し、結果ページの「Pro の点検」で「所有の確かめを始める」→ 案内どおりにファイルか TXT を置く →「置いたので確かめる」
3. **確認**：「いま測り直す」で Pro の欄に点が出ること
