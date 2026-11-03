# 設計判断の記録（ADR）

| 番号 | 題 |
| --- | --- |
| [0001](0001-separate-repository.md) | iam とは別のリポジトリにする |
| [0002](0002-dns-filter-per-device.md) | 通信フィルターは端末ごとの暗号化した DNS で行う |
| [0003](0003-platform-channels.md) | 機種ごとにメーカーの管理の入り口を使う |
| [0004](0004-orgs-and-admin-roles.md) | 組織で分け、管理者は iam でログインする |
| [0005](0005-android-management-api.md) | Android は端末ごとに AMAPI のポリシーを作り、DNS のホスト名は登録のときだけ配る |
| [0006](0006-windows-mdm.md) | Windows は合言葉で登録し、端末の証明書で確かめる |
