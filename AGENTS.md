# AIエージェントへの指示

**このファイルを最初に読んでください。**（Claude Code は `CLAUDE.md`、Codex は `AGENTS.md` を読みます。2枚は同じ内容です。）

これは **Kurage Security Check（kseccheck）** です。URLを入れるだけで、ホームページの外から見える守りを診断します。

## あなたがやること

1. この文書と `INSTALL.md` を最後まで読む
2. `INSTALL.md` の手順を上から実行し、各手順の「確認」を必ず通す
3. 全部通ったら、入口（kseccheck.php）のURLを人に伝える

## 骨格

```
入口  kseccheck.php          受け付け・保存・結果ページ・カード画像・診断書
判定  kseccheck_engine.php   外から見える守りの判定（生成AIを使わない）
試す  scripts/check.php      手元で判定だけを試す: php scripts/check.php https://example.co.jp/
```

## 勝手に変えてはいけないこと

- **攻撃に近い検査を足さない。**管理画面・隠しファイル（/.git /.env /wp-login.php など）を探す、パスワードを試す、弱い暗号で接続し直す、は入れない。他社のサイトに使えなくなり、相手には攻撃に見えます
- **内部のアドレスに向けさせない。**`ksc_public_ip()` の確かめと、リダイレクトの1回ごとの確かめ、`CURLOPT_RESOLVE` での接続先の固定を外さない
- **結果ページのURLを、URLから計算できる値に戻さない。**他社のサイトの弱点を誰でも引けるようになります
- **診断に生成AIを使わない。外部APIを呼ばない**
- **`ksc_data/.htaccess` を消さない**
- 判定を足したら、`scripts/check.php` で複数のサイトにかけ、誤判定が無いかを実物で確かめる
