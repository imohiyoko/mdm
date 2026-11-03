# 設計判断の記録（ADR）

| 番号 | 題 |
| --- | --- |
| [0001](0001-separate-repository.md) | iam とは別のリポジトリにする |
| [0002](0002-dns-filter-per-device.md) | 通信フィルターは端末ごとの暗号化した DNS で行う |
| [0003](0003-platform-channels.md) | 機種ごとにメーカーの管理の入り口を使う |
| [0004](0004-orgs-and-admin-roles.md) | 組織で分け、管理者は iam でログインする |
| [0005](0005-android-management-api.md) | Android は端末ごとに AMAPI のポリシーを作り、DNS のホスト名は登録のときだけ配る |
| [0006](0006-windows-mdm.md) | Windows は合言葉で登録し、端末の証明書で確かめる |
| [0007](0007-apple-mdm.md) | iPhone・Mac はプロファイルで登録し、端末の証明書で確かめ、APNs で起こす |
| [0008](0008-compliance-and-ssf.md) | 端末の準拠はポリシーの条件で判定し、変化を SSF で iam に知らせる |
| [0009](0009-wifi-eap-tls.md) | 証明書で Wi-Fi に入る仕組み（EAP-TLS）の RADIUS を MDM に持つ |
| [0010](0010-org-self-service.md) | 組織の管理者がルーターと IAM の受け手を API で登録する |
| [0011](0011-signup-and-invitations.md) | IAM でログインした人が自分で組織を作り、招待のコードで管理者を足す |
| [0012](0012-apple-push-per-org.md) | iPhone・Mac の通知用の証明書を組織ごとに持つ |
| [0013](0013-org-limits.md) | 組織ごとに端末・人・グループ・ポリシーの数の上限を置く |
| [0014](0014-admin-ui.md) | 管理画面はビルドの要らない画面を埋め込み、トークンはサーバーのセッションに置く |
| [0015](0015-radsec.md) | ルーターとのあいだは RadSec（RADIUS over TLS）でも受け、ルーターは証明書で見分ける |
