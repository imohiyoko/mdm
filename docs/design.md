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
| `/v1/me` | 呼んだ管理者と役割 |
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
| `/v1/orgs/{id}/android` | Android の管理の状態・始める（`/signup`、Google の画面の URL を返す） |
| `/v1/policies` | 一覧・作成・取得・置き換え（PUT）・削除。既定のポリシーは消せない |
| `/v1/blocklists` | 一覧・作成（取り込みは後ろで行う）・削除・取り込み直し |
| `/v1/audit` | 管理の操作の記録 |

使われているもの（端末のある人、使われているポリシー・一覧・グループ）は消せない（409）。一覧は `?org_id=` で組織を絞れる。作るときの `org_id` は、組織を 1 つだけ管理する管理者なら省ける。

## 5. 機種ごとの管理（段階 3〜5）

ADR [0003](adr/0003-platform-channels.md)。

| 機種 | 入り口 | 事前に要るもの | 強い制限 |
| --- | --- | --- | --- |
| Android | Android Management API | Google Cloud のプロジェクト | 初期化してから登録（完全管理） |
| iPhone・iPad | Apple の MDM | APNs の MDM 用の証明書 | 監視モード（Apple Configurator で初期化して入れる） |
| Mac | Apple の MDM | 同じ | 一部は監視モード |
| Windows | Windows 標準の MDM（OMA-DM） | 公開の HTTPS の入り口 | Pro 以上 |

それぞれ「登録」「ポリシーの配布」「状態の受け取り」「ロック・初期化」を同じ形のポートにそろえ、機種ごとにアダプタを作る。

ポリシーには通信フィルターのほかに、端末の制限（`device`：カメラ・画面の撮影・初期化・VPN の設定の禁止、画面ロックの桁数）と、機種ごとのアプリのルール（`android_apps`：`open` か `allowlist`、`required`・`allowed`・`blocked`）を持つ。できない機種では無視する。

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

## 6. iam との連携

- 管理者のログイン：iam のアクセストークン（3.6、段階 3）
- 端末の準拠の状態（段階 7）（ルールを守れているか、最後に通信した時刻など）を iam に送り、iam はログインの判定に使う。iam 側の受け口に合わせる
