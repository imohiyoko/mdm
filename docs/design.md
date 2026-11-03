# 設計

## 1. 目的と範囲

端末（iPhone・iPad・Android・Windows・Mac）を 1 か所から管理する。家庭での子どもの端末の見守り（通信・アプリ・時間）と、会社のエンドポイント管理（部署ごとのルール、準拠していない端末を仕事に使わせない、私物の端末の仕事用の領域だけの管理）の両方に使う。

- ログイン・権限は [iam](https://github.com/imohiyoko/iam) に任せる（段階 6）。iam の範囲（`docs/scope.md`）で MDM は iam の外と決めているため、別のリポジトリにする（ADR [0001](adr/0001-separate-repository.md)）
- 規模は 1 家庭〜数千台。まず 1 つのプロセスと SQLite で動くことを優先し、保存先はポートで差し替えられるようにする

## 2. 構成

```
            管理者（親）                         端末（子ども）
                │ 管理の API（JSON、鍵）              │ DoH / DoT（端末ごとの秘密）
                ▼                                    ▼
          adminapi ──────────┐            resolver（DoH・DoT・設定のプロファイル）
                             ▼                       │
                        filter.Engine ◀──────────────┘
                             │ まとめて読み込み・判定
                             ▼
                        core.Store（SQLite）     blocklist（外部の一覧の取り込み）
```

- `core`：データとポート（Store・Clock）。アダプタを import しない（iam の ADR 0003 にならう）
- `filter`：通信フィルターの判定。保存先の内容をまとめて読み込み、変更のたびに読み直す
- `resolver`：DNS の受け口（DoH・DoT）と上流への転送
- `adminapi`：管理の API
- `storage/sqlite`：保存先
- `blocklist`：外部のブロックの一覧の取り込み

時刻はすべて UTC で扱い、止める時間帯だけをポリシーのタイムゾーンで判定する。

## 3. 通信フィルター

ADR [0002](adr/0002-dns-filter-per-device.md)。

### 3.1 端末の見分け方

端末ごとに 20 バイトの秘密（base32 の小文字 32 文字）を作り、SHA-256 だけを保存する。

- DoH（iPhone・Mac・Windows・ブラウザ）：URL のパス `/dns-query/{秘密}`
- DoT（Android のプライベート DNS）：TLS のホスト名 `{ラベル}.{dot.domain}`。SNI は暗号化されずに流れるので、ラベルは DoH の秘密とは別の値（同じ形、別にハッシュを保存）。DNS のラベルは大文字・小文字を区別しないので、小文字にそろえてから照合する

知らない秘密には、DoH は 404、DoT は接続を閉じる（端末があるかどうかを教えない）。

### 3.2 判定の順

1. 運用者が決めた「いつも許す通信」（端末の管理のプッシュ・時刻合わせ・この MDM 自身）→ 通す
2. ポリシーの許可の一覧 → 通す
3. 「今すぐ止める」の間 → 止める
4. 止める時間帯 → 止める
5. 「許可の一覧だけを通す」モード → 止める
6. ポリシーのブロックの一覧 → 止める
7. 取り込んだ外部の一覧 → 止める
8. それ以外 → 通す

読めない名前（使えない文字・長すぎる）は 1 の前に止める（今すぐ止める・許可の一覧だけ を抜けさせない）。ルート（`.`）は上流に任せる。

### 3.2.1 読み込み

判定は保存先の内容のスナップショットで行う。問い合わせは読み込みを待たない。古くなったら（既定 1 分）後ろで読み直し、読み直しに失敗したら前のスナップショットを使い続け、5 秒おいて読み直す。管理の API の変更は、応答を返す前に読み直す。取り込んだ一覧は、取り込んだ時刻が変わったときだけ作り直す。

一覧はドメインとそのサブドメインに当たる。ポリシーは 端末 → 持ち主 → 既定（`default`）の順に決まる。

### 3.3 止め方

NXDOMAIN を返し、端末が EDNS を使っていれば拡張エラー「Blocked」（RFC 8914、15）を付ける。上流に問い合わせられなければ SERVFAIL。

### 3.4 記録

止めた通信はいつも記録する。通した通信はポリシーの `log_queries` が true のときだけ。記録はまとめて書き（DNS を遅くしない）、書けなかったら次に回し、1 万件を超えたら古いものから捨てる。`filter.query_log_retention_days` を過ぎたら消す。

## 3.5 組織・グループ・管理者

ADR [0004](adr/0004-orgs-and-admin-roles.md)。

- 組織（`family`・`company`）が管理の単位。人・グループ・端末・ポリシーはどれか 1 つの組織に属し、組織をまたいで指せない
- ポリシーは組織のものと、サーバー全体のもの（`org_id` なし。既定のポリシー `default` など）がある。サーバー全体のものはどの組織からも使えるが、変えられるのはサーバー全体の管理者だけ
- 取り込む一覧（ブロックの一覧）はサーバー全体で共有する
- ポリシーの決まり方：端末 → 人 → 人のグループ（`priority` の大きい順、同じなら ID の順）→ 組織の既定（`default_policy_id`）→ サーバー全体の既定

| 役割 | できること |
| --- | --- |
| `server_admin` | すべて。組織・取り込む一覧・サーバー全体のポリシー・サーバー全体の管理者の管理 |
| `org_admin` | その組織の中のすべて。その組織の管理者の追加と削除 |
| `org_viewer` | その組織の中を見るだけ（記録の確認など） |

見られない組織のものは 404（あることも教えない）、見られるが変えられないものは 403。操作の記録は組織ごとに残し、組織の管理者は自分の組織の分だけ見る。

### 3.6 管理者のログイン

- 人の管理者は iam でログインし、iam のアクセストークンを `Authorization: Bearer` に付ける。iam のアクセストークンは不透明トークン（iam の ADR 0021）なので、MDM は iam の連携先（機密クライアント）としてイントロスペクション（RFC 7662）で確かめる。答えは 30 秒まで覚える（失効の反映はその分遅れる）
- 確かめるもの：`active`、`iss`（設定の issuer と同じ）、`exp`、`aud`（設定の `oidc.audience` があれば）
- 役割は MDM が持つ（`/v1/admins`。iam の `iss` と `sub` に役割を結び付ける）。iam でログインできても、役割が無ければ使えない
- 設定の鍵（`admin.tokens`）は、最初の管理者の登録と自動化に使う。役割と組織を付けられる

## 4. 管理の API

`/v1/` 以下。`Authorization: Bearer` に設定の鍵か iam のアクセストークン（3.6）を付ける。設定には鍵の SHA-256 だけを書く。

`admin.listen` を 127.0.0.1・::1 以外にするときは `admin.tls` が要る（鍵が平文で流れないように。起動の前の確認で止める）。

| 対象 | 操作 |
| --- | --- |
| `/v1/me` | 呼んだ管理者と役割（`can_signup`：自分で組織を作れるか） |
| `/v1/signup` | 自分で組織を作り、その組織の管理者になる（IAM でログインした人。8） |
| `/v1/orgs/{id}/invitations` | 管理者への招待の一覧・作成（コードを返す）・削除（8） |
| `/v1/invitations/accept` | 招待のコードを受けて、その組織の管理者になる（8） |
| `/v1/orgs` | 一覧・作成（サーバー全体の管理者）・取得・更新（PATCH）・削除（空の組織だけ） |
| `/v1/groups` | 一覧・作成・取得・更新（PATCH）・削除（人が入っていれば 409） |
| `/v1/admins` | 一覧・作成・削除（iam のユーザーへの役割） |
| `/v1/people` | 一覧・作成・取得・更新（PATCH）・削除 |
| `/v1/devices` | 一覧・作成・取得・更新（PATCH）・削除。作成で通信フィルターの設定の情報（秘密を含む）を返す |
| `/v1/devices/{id}/filter-token` | 秘密の作り直し |
| `/v1/devices/{id}/pause` | 今すぐ止める（POST、`minutes`）・戻す（DELETE） |
| `/v1/devices/{id}/queries` | 通信の記録 |
| `/v1/devices/{id}/check` | このサイトは止まるか（記録しない） |
| `/v1/devices/{id}/enroll` | 登録の情報を作る（Android は QR コード・リンク、Windows は合言葉。5.1・5.2） |
| `/v1/devices/{id}/commands` | 命令を送る（POST。Android は `lock`・`reboot`、Windows は `reboot`・`wipe`）・送った命令の記録（GET、Windows） |
| `/v1/devices/{id}/unenroll` | 管理を外す（Android の完全管理の端末は初期化されるので `confirm_wipe`。Windows は次の通信で外れる、`force` で待たずに外す） |
| `/v1/orgs/{id}/usage` | 組織の使っている数と上限（8.3） |
| `/v1/orgs/{id}/limits` | 組織の上限を決める（PUT）・既定に戻す（DELETE）。サーバー全体の管理者だけ（8.3） |
| `/v1/orgs/{id}/apple/push` | 組織の iPhone・Mac の通知用の証明書の状態・入れる（PUT）・消す、証明書の要求を作る（`/csr`。8.2） |
| `/v1/orgs/{id}/android` | Android の管理の状態・始める（`/signup`、Google の画面の URL を返す） |
| `/v1/policies` | 一覧・作成・取得・置き換え（PUT）・削除。既定のポリシーは消せない |
| `/v1/blocklists` | 一覧・作成（取り込みは後ろで行う）・削除・取り込み直し |
| `/v1/audit` | 管理の操作の記録 |

使われているもの（端末のある人、使われているポリシー・一覧・グループ）は消せない（409）。一覧は `?org_id=` で組織を絞れる。作るときの `org_id` は、組織を 1 つだけ管理する管理者なら省ける。

## 5. 機種ごとの管理（段階 3〜6）

ADR [0003](adr/0003-platform-channels.md)。

| 機種 | 入り口 | 事前に要るもの | 強い制限 |
| --- | --- | --- | --- |
| Android | Android Management API | Google Cloud のプロジェクト | 初期化してから登録（完全管理） |
| iPhone・iPad | Apple の MDM | APNs の MDM 用の証明書 | 監視モード（Apple Configurator で初期化して入れる） |
| Mac | Apple の MDM | 同じ | 一部は監視モード |
| Windows | Windows 標準の MDM（OMA-DM） | 公開の HTTPS の入り口 | Pro 以上 |

それぞれ「登録」「ポリシーの配布」「状態の受け取り」「ロック・初期化」を同じ形のポートにそろえ、機種ごとにアダプタを作る。

ポリシーには通信フィルターのほかに、端末の制限（`device`：カメラ・画面の撮影・初期化・VPN の設定の禁止、画面ロックの桁数）と、機種ごとのアプリのルール（`android_apps`・`apple_apps`：`open` か `allowlist`、`required`・`allowed`・`blocked`。`windows_apps` は `blocked` だけ）を持つ。できない機種では無視する。

管理の状態（`core.Managed`）は機種によらず同じ形で持つ：状態（登録待ち・管理中・止められた・外れた）、完全管理か仕事用プロファイルか、機種・OS の版・セキュリティパッチ、ポリシーを守れているかとその理由、暗号化・画面ロック、最後の報告の時刻。段階 7 の準拠の判定はこれを使う。

### 5.1 Android（段階 4）

ADR [0005](adr/0005-android-management-api.md)。

1. 組織の管理者が `POST /v1/orgs/{id}/android/signup` で Google の画面の URL をもらい、開いて進める（Google のアカウントで managed Google Play の enterprise を作る）。終わると公開の入り口の `/android/signup/callback` に戻り、enterprise が組織に結びつく
2. `POST /v1/devices/{id}/enroll` で登録の QR コード（とリンク）を作る。端末ごとに AMAPI のポリシーを作り、DoT のラベルを新しくしてホスト名を書く
   - `fully_managed`（既定）：初期化した端末の最初の画面を 6 回たたき、QR コードを読む。端末を丸ごと管理し、通信フィルターも固定する
   - `work_profile`：私物の端末でリンクを開き、仕事用プロファイルを作る。管理できるのはその中だけ
3. 端末の状態は `android.sync_interval` ごとに取り込み、ポリシーの変更は管理の API で変えたときに配り直す（変わった端末にだけ）
4. `commands` でロック・再起動、`unenroll` で管理を外す

AMAPI でできないこと：時間帯での制限（通信フィルターの止める時間帯で代わりにする）、私物の端末の仕事用プロファイルの外の制限。

### 5.2 Windows（段階 5）

ADR [0006](adr/0006-windows-mdm.md)。Windows の入り口（`windows.listen`）に、登録（`/EnrollmentServer/Discovery.svc`・`Policy.svc`・`Enrollment.svc`）と管理（`/ManagementServer/MDM.svc`）を置く。

1. 管理者が `POST /v1/devices/{id}/enroll` で合言葉を作る（`link` を Windows で開くと、メールアドレスとサーバーが入った登録の画面が開く）
2. 利用者が「設定」→「アカウント」→「職場または学校にアクセスする」→「デバイス管理のみに登録する」で、サーバー（`server_url`）と合言葉（パスワード）を入れる
3. 端末は `windows.poll_minutes` ごとに通信してくる。そのたびにポリシーが変わっていれば設定を配り、1 時間に 1 回、端末の情報（OS の版・機種・暗号化）を問い合わせる

| ポリシー | Windows の設定（CSP） |
| --- | --- |
| `device.camera_disabled` | Policy/Config/Camera/AllowCamera |
| `device.factory_reset_disabled` | Policy/Config/Experience/AllowManualMDMUnenrollment（利用者が設定から管理を外せないようにする） |
| `device.passcode_min_length` | Policy/Config/DeviceLock/DevicePasswordEnabled・MinDevicePasswordLength |
| `windows_apps.blocked` | AppLocker の Microsoft Store のアプリの規則（パッケージ名で止める） |

できないもの：画面の撮影の禁止・VPN の設定の禁止、通信フィルターの固定（後で）、ロック（Windows のパソコンには遠隔のロックが無い）。端末が受け付けなかった設定は `managed.problems` に出る。

### 5.3 iPhone・iPad・Mac（段階 6）

ADR [0007](adr/0007-apple-mdm.md)。Apple の入り口（`apple.listen`）に、登録のプロファイル（`/apple/enroll/{合言葉}.mobileconfig`）、チェックイン（`/apple/checkin`）、命令のやり取り（`/apple/mdm`）を置く。

1. 管理者が `POST /v1/devices/{id}/enroll` で登録のプロファイルの URL を作る（1 回だけ取り出せる。既定 24 時間）
2. 利用者が URL を端末の Safari（Mac はブラウザー）で開き、「設定」でプロファイルを入れる。プロファイルには MDM の認証局が発行した端末の証明書が入る
3. 端末がチェックインする（Authenticate → TokenUpdate）。通知の宛先（push token）を覚え、管理中にして、ポリシーと端末の情報の問い合わせを送る。監視モードと分かったら、DoH の秘密を新しくして通信フィルターのプロファイルを送る
4. 以後、命令があるときは APNs で端末を起こし、端末が `/apple/mdm` に取りに来る。`apple.sync_interval`（既定 1 時間）ごとと管理の API で変えたときに、ポリシーが変わった端末に配り直す。端末の情報は 6 時間ごとに問い合わせる

| ポリシー | Apple の設定 |
| --- | --- |
| `device.camera_disabled` | 制限（com.apple.applicationaccess）の allowCamera |
| `device.screen_capture_disabled` | allowScreenShot |
| `device.factory_reset_disabled` | allowEraseContentAndSettings（監視モードだけ） |
| `device.vpn_config_disabled` | allowVPNCreation（監視モードだけ） |
| `device.passcode_min_length` | パスコード（com.apple.mobiledevice.passwordpolicy） |
| `apple_apps.blocked` | blockedAppBundleIDs（監視モードだけ） |
| `apple_apps` の `allowlist` | allowListedAppBundleIDs（監視モードだけ） |
| 通信フィルター | DNS の設定（com.apple.dnsSettings.managed、DoH、外せない）。監視モードの端末だけ。MDM で入れた DNS の設定は、監視モードでない端末では管理している Wi-Fi にしか効かないため、そちらは手で入れたプロファイルを使う |

命令：ロック（DeviceLock）・再起動（RestartDevice、監視モードだけ）・初期化（EraseDevice）。管理を外すと登録のプロファイルを消す命令（RemoveProfile）を送り、端末が受け取ると外れる。利用者がプロファイルを消したときはチェックアウトが届き、外れた状態になる。

できないもの：アプリを入れさせる（`apple_apps.required`。App Store のアプリの配布は段階 8 で Apple Business Manager と合わせて考える）、私物の端末のユーザー登録（Managed Apple ID が要る）、Mac の利用者ごとの管理。

## 6. iam との連携

- 管理者のログイン：iam のアクセストークン（3.6、段階 3）
- 端末の準拠の状態（段階 7）：6.1 のとおり、変わったら SSF で iam に知らせる。iam は受けた状態を記録する（iam の ADR 0118。ログインの判定に使うのは iam の側で後から決める）

### 6.1 端末の準拠と IAM への知らせ（段階 7）

ADR [0008](adr/0008-compliance-and-ssf.md)。

- ポリシーの `compliance` に条件を書く：`require_encryption`・`require_screen_lock`・`max_report_age_hours`（報告が途切れた時間の上限）・`min_os_version`（機種ごとの OS の最低の版）
- MDM で管理していて（`managed.state` が `active`）、ポリシーを受け入れていることはいつも求める。管理していない端末は準拠していない（`not_managed`）
- `compliance.interval`（既定 1 分）ごとにすべての端末を判定し、結果（準拠か・理由・変わった時刻）を置く。`GET /v1/devices/{id}` の `compliance` で見られる
- 準拠しているかが変わったら、端末の持ち主のメールアドレス（`people.email`。iam で確認済みのもの）を対象にして、CAEP の `device-compliance-change` の SET を ES256 で署名し、設定の `ssf.receivers` に push（RFC 8935）で送る
  - 対象は `complex`：`user` は `email`、`device` は `opaque`（MDM の端末の ID）。iss は `public.base_url`、公開鍵は `{public.base_url}/.well-known/jwks.json`
  - 送れなければ 10 秒から倍々（上限 1 時間）で送り直し、1 日で捨てる（iam は 24 時間より古い SET を受けない）。受け手が 400 で断ったものは送り直さない
  - 持ち主やメールアドレスが変わったら、今の状態をもう一度送る
  - 受け手に `org_ids` を書くと、その組織の端末の知らせだけを送る（組織ごとに別の IAM を使うとき）

| 理由 | 意味 |
| --- | --- |
| `not_managed` | MDM で管理していない（登録していない・外れた・止められた） |
| `policy_not_applied` | ポリシーがまだ届いていない、または端末が断った |
| `not_encrypted`・`no_screen_lock` | 暗号化・画面ロックが無い（条件にしたとき） |
| `os_outdated` | OS が最低の版より古い |
| `not_reporting` | 決めた時間より長く端末から報告が無い |

## 7. 証明書で Wi-Fi に入る（段階 7b）

ADR [0009](adr/0009-wifi-eap-tls.md)。

家や会社の Wi-Fi を WPA2・WPA3 Enterprise にし、ルーター（アクセスポイント）が MDM の RADIUS のサーバーに問い合わせる。端末は MDM が発行した証明書で入る（EAP-TLS）。合言葉（Wi-Fi のパスワード）は無いので、漏れて他の端末が入ることが無く、端末ごとに止められる。

- ネットワークの認証局（`radius.ca_cert`・`radius.ca_key`）を別に持つ。端末の証明書と RADIUS のサーバーの証明書を発行する
  - 端末はこの認証局でサーバーを確かめるので、信頼する証明書に入る。鍵が漏れてもほかのサイトのなりすましに使えないよう、発行できるサーバーの名前を `radius.server_name` だけに絞る（名前の制約。IP アドレスの名前も禁じる）
  - `radius.server_name` を変えたら認証局を作り直す（起動のときに誤りにする）
- 端末の証明書は `POST /v1/devices/{id}/network-cert` で発行する。名前（CN）は端末の ID。鍵と証明書を PKCS#12（合言葉付き）で 1 度だけ返す。MDM は指紋（SHA-256）だけを覚える
  - 発行すると前の証明書は使えなくなる（`keep_previous` で残せる）。`DELETE` ですべて止める。端末を消しても止まる
- RADIUS のサーバー（`radius.listen`、UDP）
  - 問い合わせてよいルーターは `radius.clients`（IP か CIDR と、共有の秘密）。`org_ids` を書いたルーターは、その組織の端末だけを入れる（会社と家など、組織ごとの Wi-Fi）。手順は始めたルーターでしか続けられない。知らないところからの問い合わせと、Message-Authenticator の無い Access-Request は捨てる（BlastRADIUS の対策）
  - TLS 1.2 と 1.3。TLS 1.2 は Extended Master Secret を求める（鍵の取り出しに要る）
  - 端末の証明書が認証局のもので、期限の中で、覚えている指紋で、端末の ID が合うときだけ入れる。`radius.require_compliant` なら、準拠している端末（6.1）だけを入れる
  - 入れるときは Wi-Fi の暗号の鍵（MS-MPPE-Send-Key・Recv-Key）をルーターに渡す
- 端末への配布（段階 7b-2）：ポリシーの `wifi`（SSID と、名前を知らせないネットワークか）に書いたネットワークの設定・端末の証明書・ネットワークの認証局を、MDM で端末に入れる
  - iPhone・iPad・Mac：1 つのプロファイル（`com.apple.security.root`・`com.apple.security.pkcs12`・ネットワークごとの `com.apple.wifi.managed`）。サーバーは `TLSTrustedServerNames` の名前と認証局で確かめる。命令の中身に鍵があるので、端末の答えを受けたら消す
  - 新しい証明書は、端末が受け取ったと答えてから前のものを取り消す（先に取り消すと、その Wi-Fi でしかつながらない端末が受け取れない）
  - `wifi` を変えたとき、証明書の期限が 30 日を切ったときに配り直す。`wifi` を無くすとプロファイルを消し、証明書を取り消す。管理が外れたときも取り消す
  - 管理の API で証明書を取り消した端末には、`wifi` が変わるまで配り直さない
  - Windows：`RootCATrustedCertificates`（認証局）・`ClientCertificateInstall` の PFX（端末の証明書。TPM があれば TPM に入れ、取り出せない）・ネットワークごとの `WiFi` の `WlanXml`（WPA2 Enterprise、コンピューターの証明書で入る。サーバーは名前と認証局の拇印で確かめ、証明書はこの認証局のものだけを選ぶ）。PFX の名前は指紋から決め、新しいものが入ったら前のものを消す。無くなったネットワークの設定は消す。もうある設定（418）は置き換える
  - Android は Android Management API で証明書を入れられないので、手で入れる

## 8. 組織の管理者が自分で使う（SaaS）

ADR [0010](adr/0010-org-self-service.md)。1 台のサーバーを多くの組織で分けて使うとき、サーバーの設定ファイルを触らずに、組織の管理者が API で自分の組織のものを登録する。

- ルーター（`/v1/orgs/{id}/radius-clients`）：インターネットのアドレス（IPv4 は /24、IPv6 は /48 より狭い範囲）だけ。ほかの組織のルーター・設定の `radius.clients` と重なるアドレスは登録できない（ほかの組織の Wi-Fi を乗っ取らないため）。共有の秘密は MDM が作り、登録のときだけ返す。そのルーターには、その組織の端末だけを入れる。1 組織 20 台まで
- 準拠の知らせの受け手（`/v1/orgs/{id}/ssf-receivers`）：インターネットの https の URL だけ。送るときも、つなぐ先のアドレスがループバック・社内のアドレス・クラウドのメタデータなどなら送らない（SSRF の対策）。転送（リダイレクト）は追わず、プロキシも使わない。push の Bearer の値は返さない。その組織の端末の知らせだけを送る。1 組織 5 つまで
- RadSec のルーター（`"transport": "radsec"`）：アドレスは要らない。MDM がルーターの鍵と証明書を作り、登録のときだけ返す（8.5）
- 家の中のアドレスのルーター・社内の IAM は、これまでどおりサーバーの設定に書く（サーバーの管理者が信じて置くもの）

### 8.1 サインアップと招待

ADR [0011](adr/0011-signup-and-invitations.md)。設定の `signup.enabled` で、IAM でログインした人が自分の組織を作れる（`POST /v1/signup`）。作った人はその組織の `org_admin` になる。1 人が作れる組織の数は `signup.max_orgs_per_user`（既定 3）。数は作った記録（`org_signups`）で数え、招待で入った組織は数えない。

- IAM でログインできて役割の無い人が使えるのは `GET /v1/me`・`POST /v1/signup`・`POST /v1/invitations/accept` だけ。ほかは 401（これまでどおり）
- 招待（`/v1/orgs/{id}/invitations`）：組織の管理者が `org_admin` か `org_viewer` の招待を作る。コード（`mdminv_` で始まる 32 バイトの乱数）は作ったときだけ返し、保存は SHA-256 だけ。7 日で切れ、1 回使うと消える。受けていない招待は 1 組織 50 まで
- 受けるとき（`POST /v1/invitations/accept`）は、招待を消すのと役割を入れるのを 1 つのトランザクションで行う。同じコードを同時に出しても 1 人しか受からない。すでにその組織の管理者なら 409 で、招待は残る
- 設定の鍵（誰なのかが IAM に無い）では、サインアップも招待を受けることもできない

### 8.2 組織ごとの iPhone・Mac の通知用の証明書

ADR [0012](adr/0012-apple-push-per-org.md)。Apple の MDM の通知用の証明書は、端末を使う組織の Apple ID で取る。組織の管理者は `/v1/orgs/{id}/apple/push` で自分の組織の証明書を入れる。入れていない組織は設定の `apple.push_cert` を使い、それも無ければ iPhone・Mac を登録できない（409）。

- 証明書の要求（`POST .../csr`）：MDM が鍵（RSA 2048）と CSR を作り、鍵は証明書が届くまで保存する（返さない）。設定に `apple.vendor_cert` があれば、CSR にベンダーの鍵で署名した Apple 向けのファイル（`PushCertRequestCSR`・`PushCertCertificateChain`・`PushCertSignature` の plist を base64 にしたもの）も返す。今の証明書はそのまま使い続ける
- 入れる（`PUT`）：鍵と組か、UID が `com.apple.mgmt.` で始まるか、期限内かを確かめる。topic が今のもの（組織の、または設定の）と違い、登録した端末があれば 409（端末はプロファイルの topic でしか通知を受けない）
- 端末を登録するとき、プロファイルには組織の topic を入れる。チェックインの `Authenticate` の topic が組織のものと違えば断る。通知はその組織の証明書で送る（証明書ごとに APNs のクライアントを作り、使い回す）
- 消す（`DELETE`）：登録した端末があれば 409
- 鍵は保存先にそのまま持つ。漏れると、その組織の端末に「命令を取りに来て」という合図を送れる（命令そのものは MDM の端末の証明書で守られる）

### 8.3 組織ごとの上限と使っている数

ADR [0013](adr/0013-org-limits.md)。端末・人・グループ・ポリシーの数に上限を置ける。既定は設定の `limits`（0 か書かなければ上限なし）で、サーバー全体の管理者が組織ごとに `PUT /v1/orgs/{id}/limits` で変える（`DELETE` で既定に戻す）。上限に達すると作成は 409 `limit_exceeded`。数えてから作るまでは 1 つのロックの中で行い、同時に作っても上限を超えない。

`GET /v1/orgs/{id}/usage` は、組織の管理者・見るだけの人も見られる。使っている数（端末・人・グループ・ポリシー・管理者・ルーター・知らせの受け手）、上限、組織ごとの値か、決まった上限（ルーター 20・受け手 5・受けていない招待 50）を返す。

### 8.4 管理画面

ADR [0014](adr/0014-admin-ui.md)。`admin.base_url` と `oidc` があれば、管理の入り口の `/ui/` で管理画面を出す。画面は HTML・JS・CSS だけで、ビルドの手順は無い（Go のバイナリーに埋め込む）。

- ログインは認可コードフローと PKCE。MDM が機密クライアント（`oidc.client_id`）としてコードをトークンに換える。アクセストークンはブラウザーに渡さず、サーバーのメモリーのセッションに置く。ブラウザーにはセッションの id（32 バイトの乱数）だけを `HttpOnly`・`SameSite=Strict`（https なら `Secure`）のクッキーで渡す。再起動するとログインし直す
- 管理の API は、`Authorization` が無いとき、`X-MDM-UI: 1` の付いた要求でだけクッキーのセッションを受ける。ほかのサイトはこのヘッダーを付けて送れない（CORS を開いていない）ので、CSRF を防ぐ。セッションのトークンは IAM のトークンとしてだけ扱う（設定の鍵としては照合しない）
- 画面は値をすべて `textContent` で入れる。`Content-Security-Policy` で自分のサイトのスクリプトとスタイルだけを許し、枠への埋め込みも断る
- ログインの state と verifier は `/ui/callback` だけに送られる 10 分のクッキーに置き、1 回で消す

### 8.5 RadSec（ルーターとのあいだの TLS）

ADR [0015](adr/0015-radsec.md)。`radius.radsec_listen`（例 `:2083`、TCP）を書くと、RADIUS over TLS（RFC 6614）でもルーターの問い合わせを受ける。

- ルーターは「RadSec のルーターの認証局」（`radius.radsec_ca_cert`・`radsec_ca_key`。端末の認証局とは別。無ければ最初の起動で作る）が発行したクライアント証明書で TLS をつなぐ。証明書の無い・ほかの認証局の接続は握手で断る
- 要求ごとに、証明書の CN（ルーターの ID）と指紋が組織の管理者の登録にあるかを確かめる。無ければ接続を切る。そのルーターには、その組織の端末だけを入れる
- 共有の秘密は `radsec`。区切りは RADIUS の長さ（20〜4096 バイト）。壊れた区切り・10 分のあいだ要求の無い接続は切る。同時の接続は 1000 まで
- 登録の答えは、ルーターの証明書・秘密鍵・MDM を確かめる認証局（ネットワークの認証局）・`server_name`・つなぎ先（`radius.radsec_address`。無ければ `server_name` と待ち受けのポート）
- RadSec を使うなら、設定の `radius.clients` は無くてもよい
