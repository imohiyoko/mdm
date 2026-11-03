# 0003. 機種ごとにメーカーの管理の入り口を使う

- 状態: 承認
- 日付: 2026-11-03

## 背景

アプリの許可・禁止、設定の固定、ロック・初期化は、OS が用意した管理の入り口からしかできない。

## 決定

- Android：Google の Android Management API。自前の管理アプリ（DPC）は作らない
- iPhone・iPad・Mac：Apple の MDM（APNs の MDM 用の証明書を使う）
- Windows：Windows 標準の MDM（OMA-DM、MS-MDE2 の登録）
- 「登録」「ポリシーの配布」「状態の受け取り」「ロック・初期化」を共通のポートにし、機種ごとのアダプタにする
- 作る順は Android → Windows → Apple（事前の準備が少ない順）

## 結果

- 各メーカーの仕組みの範囲でしか管理できない（端末の利用時間の制限など、入り口に無いものはできない）
- Android は Google のサービスに、Apple は Apple のプッシュに頼る
- iPhone の強い制限には監視モード（初期化して入れる）が要る

## 検討した代替案

- Android の自前の管理アプリ（DPC）を作る（Google のサービスに頼らないが、作る量が大きい）
- 既存の OSS（NanoMDM、Fleet など）を組み込む（候補として段階 5 で改めて比べる）
