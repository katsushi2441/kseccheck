# Kurage Security Check（kseccheck）

**URLを入れるだけで、ホームページの外から見える守りを診断する。**

https と証明書、ブラウザへの守りの指示、サポートの切れた PHP・古い WordPress・既知の脆弱性がある jQuery などの古い部品、入力欄の送り先を調べ、直し方を重い順に出します。

デモ: <https://proto.exbridge.jp/kseccheck/>

## 何を調べるか

- **通信の暗号化**：https で開けるか、http から https に切り替わるか、証明書の期限と正しさ、HSTS、古い通信方式
- **ブラウザへの守りの指示**：CSP、埋め込みの禁止（X-Frame-Options / frame-ancestors）、nosniff、Referrer-Policy、Permissions-Policy、Cookie の Secure・HttpOnly・SameSite
- **版の見えすぎ・古い部品**：
  - PHP の版：サポート切れと、PHP2Shell（CVE-2026-109618/109619）の修正が無い版
  - WordPress の版
  - サーバーの版の表示
  - jQuery・jQuery UI・Bootstrap・AngularJS・lodash の古い版
- **ページと入力欄**：入力欄の送り先が http か、http の部品の読み込み、PHP のエラー表示、トップページのエラー、CDN のスクリプトの改ざん検知（SRI）、security.txt

## 攻撃に近い検査はしない

ふつうの訪問者がページを開くのと同じ範囲だけを見ます。

**読むもの**
- トップページ（http と https）
- `/.well-known/security.txt`
- ページが読み込んでいるスクリプトの先頭

**しないこと**
- 管理画面や隠しファイルを探す
- パスワードを試す
- 弱い暗号で接続し直す

そのため、サーバーの中の設定やプラグインごとの脆弱性は分かりません。点数が高くても、安全が保証されたという意味ではありません。

## 作りの決まりごと

- **判定に生成AIを使いません。**同じ状態なら何度測っても同じ結果です
- **外部APIを呼びません。**診断する相手のサイトを読みに行くだけです
- **内部のアドレスに向けさせません。**名前解決したIPを1回ごとに確かめ、リダイレクトの先も確かめ直し、接続先をそのIPに固定します（DNSの付け替えによる踏み台を防ぐ）
- **結果ページのURLは推測できない番号です。**他社のサイトの弱点を、URLを知らない人に見られないようにしています。検索エンジンにも出しません（noindex）
- 結果は Markdown の診断書でダウンロード・印刷できます。Xに貼れるカード画像（1200×630）も作ります

## 動作要件

- PHP 8.0 以上（curl・openssl・gd〔FreeType〕拡張）
- データベース・Composer・npm・cron 不要。レンタルサーバーに FTP で置くだけ

## 設置

[INSTALL.md](INSTALL.md) を読んでください。AIエージェント（Claude Code / Codex）に渡せば設置まで進めます。

## ライセンス

MIT License。カード画像の文字は Noto Sans CJK JP の切り出し（SIL OFL 1.1・`public/ksc_assets/OFL.txt`）。

提供: 株式会社エクスブリッジ <https://exbridge.jp/>

## Pro（AI-IT顧問・AI-SNS顧問の契約中だけ）

設定に `KSC_PRO_URL` と `KSC_PRO_KEY` を書くと、**所有を確かめたドメインだけ**に、https の設定の詳しい読み取り（SSLyze）、脆弱性一覧（retire.js）による部品の照合、WordPress のプラグインの版の照合が足されます。所有は、決まった場所のファイルか DNS の TXT で確かめます。契約が終わると鍵が止まり、画面は自動でノーマル版に戻ります。
