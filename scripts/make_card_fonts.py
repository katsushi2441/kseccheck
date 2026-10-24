#!/usr/bin/env python3
"""結果カード（OGP画像）用のフォントを、使う文字だけに切り出す。
  /usr/bin/python3 scripts/make_card_fonts.py  → public/ksc_assets/ksc-card-{bold,black}.otf と OFL.txt

カードに描く日本語は決まった言葉だけ（ドメイン名と数字は半角）。カードの文言を変えたら CARD_TEXT に足して作り直す。
Noto Sans CJK JP（SIL Open Font License 1.1）。
"""
import pathlib
import shutil

from fontTools import subset
from fontTools.ttLib import TTCollection

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "public" / "ksc_assets"
SRC = {"bold": "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
       "black": "/usr/share/fonts/opentype/noto/NotoSansCJK-Black.ttc"}
# kseccheck.php の ksc_card_png と ksc_short_categories / ksc_band に揃える
CARD_TEXT = ("セキュリティ診断結果（外から見える守り） 総合 良好 まずまず 弱い 要対応 "
             "暗号化 守りの指示 版・古い部品 ページ・入力欄 重大 警告 改善余地 件 "
             "で診断 年月日 ／・…　")
ASCII = "".join(chr(c) for c in range(0x20, 0x7F))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, path in SRC.items():
        font = TTCollection(path).fonts[0]
        opts = subset.Options()
        opts.layout_features = ["*"]
        opts.name_IDs = ["*"]
        opts.notdef_outline = True
        sub = subset.Subsetter(opts)
        sub.populate(text=CARD_TEXT + ASCII)
        sub.subset(font)
        dst = OUT / f"ksc-card-{name}.otf"
        font.save(str(dst))
        print(dst, dst.stat().st_size, "bytes")
    shutil.copy(ROOT.parent / "ktrackgeoseo" / "public" / "ktgs_assets" / "OFL.txt", OUT / "OFL.txt")


if __name__ == "__main__":
    main()
