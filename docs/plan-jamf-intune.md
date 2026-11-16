# Jamf・Intune の置き換えのプラン（段階 10）

- 日付: 2026-11-16
- 状態: 案
- 関連: [roadmap.md](roadmap.md)、[design.md](design.md) 5.2・5.3、ADR [0006](adr/0006-windows-mdm.md)・[0007](adr/0007-apple-mdm.md)

この MDM を、iPhone・iPad・Mac では Jamf の、Windows では Intune の代わりに使えるようにするまでの道のりをまとめる。
実機・Apple Business Manager・Entra のテナントで確かめられないことが多いので、**メーカーの公式の仕様だけをもとに作る（机上の設計）**。仕様からずれていないことはテストで確かめ、実機での確認は各段階の最後に「実機で確かめること」として残す。

## 1. 拠りどころにする仕様

| 対象 | 仕様 | 使い方 |
| --- | --- | --- |
| Apple の MDM・構成プロファイル | Apple の [device-management](https://github.com/apple/device-management)（`mdm/profiles`・`mdm/commands`・`mdm/checkin`。YAML で、キーごとに対応 OS・監視モードの要否が書いてある） | プロファイルと命令のキーは、ここに載っているものだけを使う。OS の版と監視モードの要否もここに合わせる |
| Apple の宣言型の管理（DDM） | 同じリポジトリの `declarative`（宣言の種類・状態の項目・プロトコル） | 段階 10c 以降 |
| Apple の自動登録（ADE） | Apple Business Manager の Device Assignment（DEP）API、`other/machineinfo.yaml` | 段階 10h |
| Windows の MDM | MS-MDE2（登録）、OMA-DM（SyncML）、Microsoft Learn の CSP の説明（Policy CSP・BitLocker・Firewall・Defender・EnterpriseDesktopAppManagement など） | CSP の場所・型・値は Learn の CSP の説明に合わせる |
| Windows の Entra 連携 | Microsoft Learn の「Azure AD（Entra）と MDM の統合」 | 段階 10i |

キーや CSP の場所を足すときは、コードの近くに仕様のどこを見たか（ファイル名・CSP 名）を書く。

## 2. いまあるものと足りないもの

**iPhone・iPad・Mac（Jamf と比べて）**

- ある：プロファイルでの手動の登録、APNs、端末の情報、準拠、ロック・再起動・初期化、決まった種類のプロファイル（制限・パスコード・DNS フィルター・Wi-Fi と証明書）
- 足りない：Apple Business Manager からの自動登録、アプリの配布、任意のプロファイル、FileVault と鍵の預かり、OS アップデートの管理、宣言型の管理（DDM）、Mac のスクリプト・拡張属性・Self Service、端末の情報で決まるグループ（スマートグループ）

**Windows（Intune と比べて）**

- ある：合言葉での手動の登録（OMA-DM）、カメラ・管理の解除・パスワードの長さ、Store のアプリの禁止（AppLocker）、再起動・初期化、端末の情報、準拠、Wi-Fi と証明書
- 足りない：Entra 参加と自動登録・Autopilot、アプリの配布（MSI・MSIX・Win32）、BitLocker・Windows Update・Defender・ファイアウォール、Windows の通信フィルターの強制、任意の CSP、PowerShell のスクリプト

**Safari**

- ある：DNS フィルターは Safari にも効く（止めたドメインは開けない）
- 足りない：Safari そのものの制限（使用の禁止・ポップアップ・詐欺サイトの警告・プライベートブラウズ）、URL 単位の Web のフィルター

## 3. 段階

準備（Apple Business Manager・Entra・署名の証明書）が要らず、仕様だけで作れて効き目の大きいものから順にする。1 段階を 1 つの PR にする。

| 段階 | 内容 | 外の準備 | 実機なしで確かめられること |
| --- | --- | --- | --- |
| 10a | Safari と Web の制限 | なし | プロファイルのキー・値・型 |
| 10b | 任意の構成プロファイル（Apple）と任意の CSP（Windows） | なし | 危ない中身を断ること、配り方 |
| 10c | 宣言型の管理（DDM）の土台 | なし | 宣言・同期の受け答え |
| 10d | OS アップデートの管理 | なし | 宣言・CSP の中身 |
| 10e | 暗号化（FileVault と鍵の預かり、BitLocker） | なし | プロファイル・CSP、鍵の復号と保存 |
| 10f | Windows のセキュリティ（Defender・ファイアウォール・通信フィルターの強制） | なし | CSP の中身 |
| 10g | アプリの配布 | Apple のアプリは Apps and Books の sToken（Apple Business Manager）が要るものがある | 命令・CSP の中身、ライセンスの API は偽のサーバーで |
| 10h | Apple の自動登録（ADE） | Apple Business Manager | DEP API は偽のサーバーで、登録の受け答えは仕様の例で |
| 10i | Windows の Entra 参加と自動登録 | Entra ID（P1 以上） | トークンの検証、登録の受け答え |
| 10j | 端末のエージェント（Mac・Windows のスクリプト・拡張属性・Self Service・Win32 アプリ） | Apple の Developer ID、Windows のコード署名 | 別のリポジトリで |

あわせて、サーバーの中だけでできる **スマートグループ**（端末の情報の条件で決まるグループ）を 10c と 10d のあいだに入れてもよい（ADR 0017 の自動のルールと同じ「判定のたびに決める」作りにする）。

### 10a Safari と Web の制限

- 制限のプロファイル（`com.apple.applicationaccess`）に足す：`allowSafari`（iOS・監視モード）、`safariAllowPopups`、`safariForceFraudWarning`、`safariAllowAutoFill`（iOS は監視モード、macOS 10.13 以降）、`safariAcceptCookies`（iOS）、`allowSafariPrivateBrowsing`（iOS・macOS 26 以降、iOS は監視モード）
- Web のフィルター（`com.apple.webcontent-filter`、`FilterType: BuiltIn`）を iPhone・iPad の監視モードの端末に配る。`AutoFilterEnabled`（大人向けのサイトを自動で止める）、`DenyListURLs`（止める URL。500 件まで）、`AllowListBookmarks`（許可した URL だけを開ける。使うなら止める URL より優先）
- Mac の Safari：組み込みの Web のフィルターは Mac に無い（Mac はプラグインの型だけ）。Mac は DNS フィルターと、制限のうち Mac に効くもの（自動入力・プライベートブラウズ）で止める。DDM の `com.apple.configuration.safari.settings`（macOS 26 以降、利用者の単位）は 10c の後で使う
- ポリシーの JSON・ルールの API・管理画面に `safari` と `web_filter` を足す

### 10b 任意の構成プロファイル・任意の CSP

Jamf の「構成プロファイルのアップロード」、Intune の「カスタム（OMA-URI）」に当たる。ほかの段階で対応しきれない設定を管理者が自分で配れるようにする。

- ポリシーに、Apple の .mobileconfig（署名されていないもの）と、Windows の CSP の設定（場所・型・値）の一覧を持たせる
- 断るもの：登録のプロファイルを入れ替えられる中身（`com.apple.mdm` のペイロード、MDM が自分で作る名前 `com.imohiyoko.mdm.*`）、大きすぎるもの
- Windows は書ける場所を許可の一覧（`./Device/Vendor/MSFT/Policy/Config/`・`./User/Vendor/MSFT/Policy/Config/` など）で決め、登録や MDM そのものの設定（`DMClient` など）は書けないようにする
- 端末ごとに入れたものを覚えておき、ポリシーから外れたら消す（`RemoveProfile`、CSP の `Delete`）

### 10c 宣言型の管理（DDM）の土台

Apple は新しい機能を DDM だけで出すようになっている（`app.managed`・`package`・`safari.settings`・`softwareupdate.enforcement.specific` など）。

- `DeclarativeManagement` の命令と、チェックインの `DeclarativeManagement`（`tokens`・`declaration-items`・`declaration/...`・`status`）を受ける
- 宣言はポリシーから作り、中身の要約を ServerToken にする。状態の報告（`status`）を端末の情報と準拠に使う

### 10d OS アップデートの管理

- Apple：DDM の `softwareupdate.enforcement.specific`（版と期限を決めて入れさせる）、`softwareupdate.settings`（遅らせる日数・自動で入れるか）。DDM に対応しない古い OS は `ScheduleOSUpdate` の命令で
- Windows：Policy CSP の `Update/*`（品質・機能の更新を遅らせる日数、期限、猶予、アクティブ時間）
- 準拠の `MinOSVersion` と合わせて、「期限までに上げていなければ準拠しない」にできるようにする

### 10e 暗号化

- Mac：`com.apple.MCX.FileVault2`（ログインのときに有効にする）と `com.apple.security.FDERecoveryKeyEscrow`（個人用の復旧キーを MDM の証明書で暗号化して預ける）。キーは `SecurityInfo` の答えで受け取り、組織ごとに暗号化して保存する。見る操作は記録に残し、見る役割を絞る
- Windows：BitLocker CSP（`RequireDeviceEncryption`、ほかの暗号化ソフトの警告を出さない、標準ユーザーでも有効にできる、暗号化の方式）。回復キーを MDM が受け取る CSP は無い（Entra か Active Directory に預けるだけ）ので、10i の後で Entra から読むかを考える

### 10f Windows のセキュリティ

- Defender（Policy CSP の `Defender/*`：リアルタイムの保護・クラウドの保護・PUA の保護など）、ファイアウォール（Firewall CSP）
- 通信フィルターの強制（ロードマップの段階 5 の「後で」）：Windows の DNS over HTTPS の設定を CSP で配れるかを Learn で確かめてから決める。だめなら Edge の DoH のポリシー（ADMX の取り込み）か、10j のエージェントで

### 10g アプリの配布

- iPhone・iPad：`InstallApplication`（App Store のアプリ。ライセンスは Apps and Books の API で割り当てる。sToken が無いときは利用者の Apple アカウントで入れる）、`RemoveApplication`、`ManagedApplicationList`。DDM の `app.managed`（iOS 17.2 以降）
- Mac：署名された .pkg を `InstallEnterpriseApplication`（マニフェストの URL）で。DDM の `package`（macOS 26 以降）
- Windows：MSI は EnterpriseDesktopAppManagement CSP（ダウンロードの URL と SHA-256）、MSIX は EnterpriseModernAppManagement CSP。.exe のインストーラー（Intune の Win32 アプリ）は標準の CSP では入れられないので 10j のエージェントで

### 10h Apple の自動登録（ADE）

- 組織ごとに Apple Business Manager のサーバートークン（.p7m）を預かり、DEP API（`/session`・`/account`・`/server/devices`・`/devices/sync`・`/profile`）で端末と登録のプロファイルを同期する
- 登録の URL は、端末が送る MachineInfo（署名付き）で端末を確かめてから登録のプロファイルを返す。`is_mdm_removable: false` で外せない管理にし、監視モードにする。`await_device_configured` で初期設定の途中に設定を入れてから `DeviceConfigured` で進める

### 10i Windows の Entra 参加と自動登録

- Entra の「MDM のアプリ」として登録し、初期設定（OOBE）や設定アプリで Entra にサインインしたら、この MDM に自動で登録されるようにする（MS-MDE2 の登録で、Entra が発行したトークンを受けて検証する）
- Autopilot の展開プロファイルは Intune（Microsoft Graph）か Partner Center でしか管理できないので、この MDM だけでは完結しない。Entra 参加と自動登録で「箱から出してサインインすれば管理に入る」までを作り、Autopilot そのものは対象外にする

### 10j 端末のエージェント（別のリポジトリ）

標準の MDM の仕組みではできないことを、端末に入れる小さなプログラムで行う。Mac のスクリプト・拡張属性（Jamf の Extension Attributes）・Self Service、Windows の Win32 アプリ・PowerShell のスクリプト。

## 4. リポジトリを分けるか

**10a〜10i はこのリポジトリで作る。10j のエージェントだけ別のリポジトリにする。**

- 10a〜10i は、どれも今の Apple・Windows の入り口（登録・端末の証明書・命令の待ち行列・ポリシー）の上に足すもの。分けると、登録と認証の仕組みを 2 か所で持つことになり、ポリシーとの結びつき（自動のルール・準拠）も API 越しになる
- エージェントは、端末の上で動く別のプログラムで、OS ごとのビルド・署名・公証（Apple の notarization）・配布の流れが MDM のサーバーと違う。サーバーとは決まった API（エージェント用の口）だけでつながる。iam と mdm を分けたとき（ADR 0001）と同じ理由で分ける

## 5. 安全のための決まり

これまでの脆弱性の診断で直したことに合わせる。

- 管理者が渡すもの（任意のプロファイル・CSP・URL・アプリの URL）は、大きさと件数の上限を置き、MDM の登録や認証を書き換えられる中身を断る
- 秘密（FileVault の復旧キー・Apple Business Manager のトークン・Apps and Books の sToken）は組織ごとに暗号化して保存し、API の答えに出さない。見る操作は記録に残す
- 組織の管理者は、自分の組織の端末にしか配れない（今のポリシーの決め方と同じ）

## 6. 実機で確かめるときの順

1. 監視モードの iPhone（Apple Configurator で初期化）で 10a の制限と Web のフィルター
2. Mac で 10b・10c・10e
3. Windows 11 Pro で 10b・10d・10e・10f
4. Apple Business Manager・Entra が使えるようになったら 10h・10i
