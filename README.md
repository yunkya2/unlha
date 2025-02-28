unlha.py -- Python 版 LZH アーカイブ展開ツール\
(LZH archive extractor written in Python)
===================================================

Python version copyright (c) 2024 Yuichi Nakamura (@yunkya2)

# 概要

ファイル圧縮形式として現在ではほとんど使われなくなった LZH ですが、かつて Windows にあった LZH 展開機能が削除されるなど OS 側の対応もなくなってきているため、既存のアーカイブを展開したい際に困ることがあります。

[LHa for UNIX with Autoconf](https://github.com/jca02266/lha) として UNIX 版の LHa コマンドが公開されていますが、ビルド済みパッケージが提供されている一部の OS 以外では自分で環境を用意してビルドする必要があり、なかなか手軽には使えません。

このプログラムは、上記 UNIX 版 LHa コマンドのアーカイブ展開処理を Python 言語で書き直し、単体の Python スクリプトとして使用できるようにしたものです。
Python 3 の実行環境さえあれば LZH アーカイブを展開することができます。


# 特徴

* Python 言語のみで書かれている LZH アーカイブの展開専用ツールです
* スクリプトファイル 1 つのみで、Python 標準ライブラリ以外の外部ライブラリにはまったく依存していません
* 対応する圧縮形式は lh0(非圧縮)/lh1/lh2/lh3/lh4/lh5/lh6/lh7 です
* 対応するヘッダはレベル 0, 1, 2 です
* アーカイブ内の日本語ファイル名はシフト JIS (CP932) と UTF-8 のみ対応しています
* アーカイブ内のタイムスタンプは認識しますが、UNIX ファイル属性等は無視します

# 使用方法

Python 3 の実行環境のあるコマンドライン上から実行します。

* `unlha.py l <LZH file>`
  * アーカイブファイル `<LZH file>` 内にあるファイル一覧を表示します

* `unlha.py x <LZH file> [<files>...]`
  * アーカイブファイル `<LZH file>` 内にあるファイルをカレントディレクトリ以下に展開します
  * `<files>` を省略した場合はアーカイブ内のすべてのファイルを、指定した場合は該当ファイルのみを展開します

Windows のコマンドプロンプトなど Shebang に対応していない環境では以下のように実行してください。
* `python3 unlha.py l <LZH file>`
* `python3 unlha.py x <LZH file> [<files>...]`

# ライセンス

unlha.py は、C 言語で書かれた LHa for UNIX のアーカイブ展開処理のみを抜き出して Python 言語で書き直し、単体利用できるようにするための処理を新規に書き下ろしたものです。

このような派生物に対して、元となった LHA for UNIX の再配布条件がどのように適用されるかが不明瞭ですが、原作者の意図を尊重して、LHA for UNIX の再配布条件の文面の LHa を unlha.py に変更したものが適用されるものとします。適用される再配布条件を [LICENSE](LICENSE) ファイルに記載します。

# 謝辞

unlha.py は、直接的には [https://github.com/jca02266/lha](https://github.com/jca02266/lha) で公開されている LHa for UNIX のソースコードを元に、一部機能の抜き出しと Python 化を行ったものです。
GitHub でのソースコード公開とメンテナンスに関わられている新井康司さんに感謝します。

また、オリジナルの LHa の開発者である吉崎栄泰さんをはじめとして、これまで LHa for UNIX の開発に関わってこられた皆様に感謝します。
```
LHarc    for UNIX  V 1.02  Copyright(C) 1989  Y.Tagawa
LHx      for MSDOS V C2.01 Copyright(C) 1990  H.Yoshizaki
LHx(arc) for OSK   V 2.01  Modified     1990  Momozou
LHa      for UNIX  V 1.00  Copyright(C) 1992  Masaru Oki
LHa      for UNIX  V 1.14  Modified     1995  Nobutaka Watazaki
LHa      for UNIX  V 1.14i Modified     2000  Tsugio Okamoto
LHA-PMA  for UNIX  V 2     PMA added    2000  Maarten ter Huurne
                   Autoconfiscated 2001-2008  Koji Arai
```

Pierre Zurek さんに lh1/lh2/lh3 対応コードを取りこんでいただきました。感謝します。
