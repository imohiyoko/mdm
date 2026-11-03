# mdm

セルフホストできる端末管理（MDM）。iPhone・iPad・Android・Windows・Mac を 1 か所から管理する。家庭での子どもの端末の見守りと、会社のエンドポイント管理の両方に使う（実験段階）。

ログインと「この端末はルールを守れているか」の連携は、同じ作者の [iam](https://github.com/imohiyoko/iam) と組み合わせる。

- 設計: [docs/design.md](docs/design.md)
- ロードマップ: [docs/roadmap.md](docs/roadmap.md)
- 設計判断の記録（ADR）: [docs/adr/](docs/adr/README.md)
- ライセンス: [Apache-2.0](LICENSE)

## いまできること

段階 1〜7b（土台・通信フィルター・組織と管理者・Android・Windows・iPhone と Mac・準拠と IAM への知らせ・証明書で Wi-Fi に入る仕組みと配布）。

- 組織（家族・会社）を分け、組織ごとに人・グループ（部署など）・端末・ポリシー（ルール）を管理の API で登録する
- 管理者の役割：サーバー全体の管理者・組織の管理者・組織を見るだけ。管理者は IAM でログインする（設定の鍵でも使える）。設定で開けば、IAM でログインした人が自分で組織を作り、招待のコードで管理者を足せる
- ポリシーは 端末 → 人 → 人のグループ（優先度の高い順）→ 組織の既定 → サーバー全体の既定 の順に決まる
- 端末ごとの **通信フィルター**（暗号化した DNS）
  - ブロックの一覧・許可の一覧・外部のブロックの一覧（hosts 形式など）の取り込み
  - 「許可の一覧だけを通す」モード（小さな子ども向け）
  - 止める時間帯（夜など。タイムゾーン付き）、「今すぐ止める」
  - 止めた通信の記録（通した通信の記録はポリシーで選ぶ）
  - 「この端末でこのサイトは止まるか」の確認
- **Android の端末の管理**（Google の Android Management API）
  - QR コードで登録（会社・家の端末は丸ごと管理、私物は仕事用プロファイル）
  - アプリの自動インストール・許可・禁止、「許可したアプリだけ」
  - 端末の制限（カメラ・画面の撮影・初期化・VPN の設定の禁止、画面ロックの桁数）
  - 通信フィルターを端末に固定する（丸ごと管理の端末。子どもが外せない）
  - 状態の取り込み（機種・OS の版・ポリシーを守れているか・暗号化・画面ロック）、ロック・再起動、管理を外す
- **Windows の端末の管理**（Windows 標準の MDM。Home でも使える）
  - 合言葉で登録（「デバイス管理のみに登録する」）
  - Microsoft Store のアプリの禁止、カメラの禁止、パスワードの桁数、利用者が管理を外せないようにする
  - 状態の取り込み（OS の版・機種・暗号化・設定を受け入れたか）、再起動・初期化、管理を外す
- **iPhone・iPad・Mac の端末の管理**（Apple 標準の MDM）
  - 登録のプロファイルの URL を開いて登録
  - 監視モードの端末には通信フィルターを MDM が配る（すべての回線に効き、子どもが外せない）。監視モードでない端末は、手で入れたプロファイルのまま使う（MDM で配ると、Apple の決まりで管理している Wi-Fi にしか効かないため）
  - カメラ・画面の撮影の禁止、パスコードの桁数。監視モードの端末では初期化・VPN の設定の禁止、アプリの禁止・「許可したアプリだけ」
  - 状態の取り込み（機種・OS の版・監視モードか・パスコード・暗号化）、ロック・再起動・初期化、管理を外す
- **端末の準拠（会社のルールに沿っているか）の判定**と、変わったときの **IAM への知らせ**（OpenID Shared Signals Framework）
  - 条件：管理している・ポリシーを受け入れている（いつも）、暗号化・画面ロック・OS の最低の版・報告が途切れていない（選べる）
- **証明書で家・会社の Wi-Fi に入る**（WPA2・WPA3 Enterprise の EAP-TLS。MDM が RADIUS のサーバーになる）
  - Wi-Fi の合言葉が無く、MDM が証明書を発行した端末だけが入れる。端末ごとに止められ、準拠している端末だけに絞れる
  - iPhone・iPad・Mac・Windows には、Wi-Fi の設定と証明書を MDM が配る（期限の前に新しくし、管理を外すと取り消す）
- **ルールの API**：AI のエージェント・自動化・IaC（ルールのファイルを GitHub で管理）からポリシーのルールを読み書きする（OpenAPI つき。試しに送る・版の確かめ）
- 管理の操作の記録

Windows では、通信フィルターを端末に手で設定して使う。

## 動かす（開発用）

Go 1.27 以上が必要です。

```sh
go run ./cmd/mdm admin-token          # 管理の API の鍵を作る
cp mdm.example.yaml mdm.yaml          # sha256 と base_url を書き換える
go run ./cmd/mdm serve -config mdm.yaml
```

端末から届く入り口（`public.listen`）は、インターネットから HTTPS で届く場所に置きます（前に Caddy などのリバースプロキシを置くか、`public.tls` に証明書を書く）。管理の API（`admin.listen`）は家の中・VPN の中からだけ届く場所にします。

## 使い方の例

```sh
A="Authorization: Bearer mdm_..."   # admin-token で作った鍵

# 家族（組織）を作る
curl -H "$A" localhost:8091/v1/orgs -d '{"name": "山田家", "kind": "family"}'

# 小学生向けのルール：ゲームのサイトを止め、21 時〜7 時は止める
curl -H "$A" localhost:8091/v1/policies -d '{
  "org_id": "org_...", "name": "小学生", "block": ["game.example"], "allow": ["school.example"],
  "quiet_hours": [{"start": "21:00", "end": "07:00"}], "time_zone": "Asia/Tokyo"}'

# 子どもと端末を登録する（端末の設定に使う情報が返る。秘密を含むので、ここでしか表示しない）
curl -H "$A" localhost:8091/v1/people -d '{"org_id": "org_...", "name": "たろう", "policy_id": "pol_..."}'
curl -H "$A" localhost:8091/v1/devices -d '{"org_id": "org_...", "name": "たろうの iPhone", "platform": "ios", "person_id": "per_..."}'

# 30 分だけ止める
curl -H "$A" localhost:8091/v1/devices/dev_.../pause -d '{"minutes": 30}'
```

### 管理画面

設定の `admin.base_url`（ブラウザーから届く https://host:port）と `oidc` を書くと、`{base_url}/ui/` で管理画面を使えます。スマホからも使えます。IAM の連携先の戻り先（redirect URI）に `{base_url}/ui/callback` を登録してください。

ログインすると、組織の作成・招待のコードの作成と受け取り、端末（足す・登録・今すぐ止める・消す）・人・グループ・管理者・Wi-Fi のルーター・操作の記録・使っている数を扱えます。ポリシーの細かい編集は、今は API で行います。

### ルールの API（AI・自動化・IaC）

設定に `rules_api.listen`（例 `127.0.0.1:8093`。ほかの機械から使うなら `rules_api.tls` も）を書くと、ポリシーのルールを読み書きする API を使えます。契約は [api/rules/openapi/public.json](api/rules/openapi/public.json) で、AI のエージェントにそのままツールとして渡せます。鍵は管理の API と同じで、組織の管理者の IAM のトークンか、組織に絞った設定の鍵（`admin.tokens` の `role: org_admin`・`org_id`）を使います。

```sh
R=localhost:8093; A="Authorization: Bearer $TOKEN"
curl -H "$A" $R/v1/orgs/org_.../policies                       # 一覧（version つき）
# 試しに送る（plan）：保存せず、変わる項目を返す
curl -H "$A" -X PUT $R/v1/policies/pol_... -d '{"dry_run": true, "policy": {"name": "小学生", "block": ["game.example"], "quiet_hours": [{"start": "21:00", "end": "07:00"}], "time_zone": "Asia/Tokyo"}}'
# → {"changes": [{"field": "block", "added": ["game.example"], "removed": []}, ...], "applied": false, ...}
# 反映する（apply）：expected_version を付けると、画面などで先に変えられていたら 412 で止まる
curl -H "$A" -X PUT $R/v1/policies/pol_... -d '{"expected_version": "…", "policy": {...}}'
# AI 向けの小さな操作：ドメインを足す・消す、今すぐ止める
curl -H "$A" $R/v1/policies/pol_.../edit -d '{"add_block": ["sns.example"]}'
curl -H "$A" $R/v1/devices/dev_.../pause -d '{"minutes": 60}'
```

`policy` に書かない項目は空になります（ファイルの中身を正とします）。同じ中身なら何も変わりません。知らない項目は 400 で断ります。

#### ルールをファイルで管理する（GitHub など）

`mdm rules` は、ルールのファイル（`rules/*.yaml`。1 つのファイルが 1 つのポリシー）をこの API で反映します。

```sh
export MDM_RULES_URL=https://mdm.example.com:8093 MDM_RULES_TOKEN=... MDM_ORG_ID=org_...
mdm rules export -dir rules   # 今のポリシーをファイルに書き出す（始めるとき）
mdm rules plan -dir rules     # ファイルと今の違いを見せる（保存しない）
mdm rules apply -dir rules    # ファイルの中身にする
```

```yaml
# rules/kids.yaml
id: pol_...            # export で入る。無ければ同じ名前のポリシー、それも無ければ作る
name: 小学生
block: [game.example, sns.example]
allow: [school.example]
quiet_hours:
  - {start: "21:00", end: "07:00", days: [mon, tue, wed, thu, sun]}
time_zone: Asia/Tokyo
```

- plan の結果は `+`（作る）・`~`（変わる。項目ごとに足すもの・消すもの）・`=`（変わらない）・`?`（ファイルに無い。変えない・消さない）
- apply は、plan のあとに管理画面などで変えられたポリシーを上書きせずに止まります
- `-detailed-exitcode` を付けると、plan で変わるものがあれば終了コード 2
- GitHub Actions の例：[docs/examples/rules-github-actions.yml](docs/examples/rules-github-actions.yml)（プルリクエストで plan、main に入ったら apply）

### 管理者が IAM でログインする

1. IAM に、この MDM を連携先（機密クライアント）として登録し、client_id と client_secret を設定の `oidc` に書く。MDM はその連携先としてアクセストークンをイントロスペクションで確かめる
2. 管理の API で、IAM のユーザー（`sub`）に役割を与える

```sh
curl -H "$A" localhost:8091/v1/admins -d '{"subject": "<IAM の sub>", "label": "boss@example.com", "role": "org_admin", "org_id": "org_..."}'
```

3. その人は IAM で取ったアクセストークンを `Authorization: Bearer` に付けて管理の API を使う。IAM でログインできても、役割を与えていなければ使えない

#### 自分で組織を作る・管理者を招待する（SaaS として動かすとき）

設定に `signup: {enabled: true}` を書くと、IAM でログインした人が自分の組織を作り、その組織の管理者になれる（1 人 3 組織まで。`max_orgs_per_user` で変えられる）。

```sh
T="Authorization: Bearer <IAM のアクセストークン>"
curl -H "$T" localhost:8091/v1/signup -d '{"name": "すずき家", "kind": "family"}'
```

ほかの人を管理者にするときは、招待のコードを作って本人に渡す。受けた人が IAM でログインしてコードを出すと、その組織の管理者（`org_admin`）か見るだけの人（`org_viewer`）になる。コードは作ったときだけ表示され、7 日で切れ、1 回しか使えない。

```sh
curl -H "$T" localhost:8091/v1/orgs/org_.../invitations -d '{"role": "org_admin", "label": "hanako@example.com"}'
# → {"code": "mdminv_...", ...} を本人に渡す
curl -H "Authorization: Bearer <受ける人のアクセストークン>" localhost:8091/v1/invitations/accept -d '{"code": "mdminv_..."}'
```

### 端末に通信フィルターを設定する

端末を登録したときに返る `filter` の値を使います。

| 端末 | 設定のしかた |
| --- | --- |
| iPhone・iPad・Mac | `apple_profile_url` を Safari で開き、「設定」→「プロファイルがダウンロード済み」からインストール |
| Android | 「設定」→「ネットワーク」→「プライベート DNS」に `dot_hostname` を入れる（下の「Android の準備」が要る） |
| Windows 11 | 「設定」→「ネットワークとインターネット」→ 使っている接続 →「DNS サーバーの割り当て」を「手動」にし、IPv4 の優先 DNS に **この MDM のサーバーの IP アドレス** を入れ、「DNS over HTTPS」を「オン（手動テンプレート）」にして `doh_url` を入れる |
| Chrome・Edge・Firefox | 「セキュア DNS」の「カスタム」に `doh_url` を入れる |

`doh_url` は端末ごとの秘密を含みます。漏れたときは `POST /v1/devices/{id}/filter-token` で作り直します（`dot_hostname` も作り直されます）。

`dot_hostname` の先頭は端末を見分けるための値で、TLS の仕組み上、通信の途中で見えます。そのため DoH の秘密とは別の値にしてあり、これが知られても DoH の設定やプロファイルは取られません。

### Android の準備

Android のプライベート DNS は DNS over TLS（TCP の 853 番）を使います。

1. 設定に `dot` を書く（`domain` と、`*.{domain}` のワイルドカード証明書。Let's Encrypt なら DNS-01 で取れる）
2. 公開の DNS に `*.{domain}` の A（と AAAA）レコードを作り、この MDM のサーバーの IP アドレスに向ける。`{ラベル}.{domain}` がどれもサーバーに届くようにするため
3. ファイアウォール・ルーターで TCP の 853 番をサーバーに通す

### Android の端末を管理する

事前に Google Cloud の準備が要ります（無料）。

1. Google Cloud でプロジェクトを作り、「Android Management API」を有効にする
2. サービスアカウントを作り、ロール「Android Management ユーザー」を付け、鍵（JSON）を作ってサーバーに置く
3. 設定の `android` に `project_id` と `credentials_file` を書く。通信フィルターを端末に固定するなら `dot` も書く（上の「Android の準備」）

```sh
# 組織の Android の管理を始める（返った url をブラウザーで開き、Google のアカウントで進める）
curl -H "$A" localhost:8091/v1/orgs/org_.../android/signup -d '{}'

# 子ども向けのルール：ゲームのアプリを禁止し、設定からの初期化と VPN の設定を禁止する
curl -H "$A" localhost:8091/v1/policies -d '{"org_id": "org_...", "name": "小学生の Android",
  "android_apps": {"mode": "open", "blocked": ["com.example.game"]},
  "device": {"factory_reset_disabled": true, "vpn_config_disabled": true, "passcode_min_length": 4}}'

# 端末の登録の QR コードを作る（qr_code の文字列を QR コードにして、初期化した端末の最初の画面を 6 回たたいて読む）
curl -H "$A" localhost:8091/v1/devices/dev_.../enroll -d '{"mode": "fully_managed"}'

# 私物の端末は仕事用プロファイル（返った url を端末で開く）
curl -H "$A" localhost:8091/v1/devices/dev_.../enroll -d '{"mode": "work_profile"}'

# 画面をロックする
curl -H "$A" localhost:8091/v1/devices/dev_.../commands -d '{"type": "lock"}'
```

### Windows の端末を管理する

1. 設定に `windows` を書く（`listen`・`base_url`・`tls`）。Windows の入り口は端末の証明書を受け取るので、リバースプロキシを通さずにこのサーバーへ TCP のまま届くようにする（TLS の証明書は Let's Encrypt などの公的なもの）
2. 端末の証明書を発行する認証局は、最初の起動で `ca_cert`・`ca_key` に作られる。`ca_key` は大切に保管する（無くすと、登録した Windows をすべて登録し直す）

```sh
# 端末の登録の合言葉を作る（返った link を Windows で開くか、server_url と code を手で入れる）
curl -H "$A" localhost:8091/v1/devices/dev_.../enroll -d '{}'

# Microsoft Store のゲームを止め、利用者が管理を外せないようにする
curl -H "$A" localhost:8091/v1/policies -d '{"org_id": "org_...", "name": "子どもの PC",
  "windows_apps": {"blocked": ["Microsoft.MinecraftUWP"]},
  "device": {"factory_reset_disabled": true, "passcode_min_length": 6}}'
```

Windows の側では「設定」→「アカウント」→「職場または学校にアクセスする」→「デバイス管理のみに登録する」から進めます。メールアドレスの欄には返った `username`、サーバーの欄には `server_url`、パスワードには `code` を入れます。命令や設定は、端末が次に通信してきたとき（既定で 15 分ごと）に届きます。

### iPhone・Mac の準備

Apple の MDM では、端末を起こす通知（APNs）に **MDM の通知用の証明書** が要ります。取り方は次のとおりです。

1. 通知用の鍵と CSR（証明書の申請）を作る：`openssl req -new -newkey rsa:2048 -nodes -keyout apple-push-key.pem -out push.csr -subj "/CN=mdm"`
2. その CSR に「MDM ベンダー」の署名をもらう。次のどちらか
   - 無料の署名サービス（mdmcert.download など。メールで署名済みのファイルが届く）
   - 自分で Apple Developer Enterprise Program（有料）に入り、MDM ベンダーの証明書を取って署名する
3. 署名済みのファイルを [Apple Push Certificates Portal](https://identity.apple.com/pushcert/) に Apple ID で上げ、通知用の証明書（.pem）を受け取る
4. 設定の `apple` に `push_cert`（受け取った証明書）と `push_key`（1 で作った鍵）を書く。証明書は 1 年ごとに、**同じ Apple ID で**「更新」する（新しく作ると、登録した端末をすべて登録し直す）

#### 組織ごとの通知用の証明書（SaaS として動かすとき）

Apple の決まりでは、通知用の証明書は端末を使う組織の Apple ID で取ります。組織の管理者は、自分の組織の証明書を管理の API で入れられます（設定の `push_cert` は、組織が入れていないときに使われます。書かなくてもかまいません）。

```sh
# 1. MDM に鍵と CSR を作らせる。設定に vendor_cert があれば、Apple に上げるファイル（push_cert_request）も返る
curl -H "$T" -X POST localhost:8091/v1/orgs/org_.../apple/push/csr
# 2. push_cert_request を base64 のまま保存して Apple Push Certificates Portal に組織の Apple ID で上げ、証明書（.pem）を受け取る
# 3. 受け取った証明書を入れる（鍵は 1 で MDM が作ったものを使う）
curl -H "$T" -X PUT localhost:8091/v1/orgs/org_.../apple/push --data-binary @<(jq -Rs '{cert: .}' MDM_Push.pem)
```

組織ごとの上限（端末・人・グループ・ポリシーの数）は、設定の `limits` が既定で、サーバー全体の管理者が `PUT /v1/orgs/{id}/limits` で組織ごとに変えられます。使っている数は `GET /v1/orgs/{id}/usage` で見られます。

ベンダーの証明書が無いサーバーでは、ほかの方法（mdmcert.download など）で取った証明書と鍵を `{"cert": "...", "key": "..."}` で入れます。iPhone・Mac を登録したあとは、topic（Apple ID ごとに決まる）の違う証明書には入れ替えられません（409）。毎年の更新は同じ Apple ID で行います。

設定の `apple` には、ほかに `listen`（待ち受けるところ）・`base_url`（端末から届く https://host:port）・`tls` の `cert` と `key`（公的な TLS の証明書）が要ります（[mdm.example.yaml](mdm.example.yaml)）。`apple.listen` が無いと、iPhone・Mac の登録は `apple_not_configured` になります。Apple の入り口も Windows と同じく端末の証明書を受け取るので、リバースプロキシを通さずにこのサーバーへ TCP のまま届くようにします。`base_url` のホスト名は、通信フィルターでいつも通します（止める時間帯や「許可の一覧だけ」でも管理の通信が止まらないように）。

### iPhone・Mac の端末を管理する

```sh
# iPhone を登録して、返った profile_url を端末の Safari で開く
curl -H "$A" localhost:8091/v1/devices -d '{"org_id": "org_...", "name": "子どもの iPhone", "platform": "ios"}'
curl -H "$A" localhost:8091/v1/devices/dev_.../enroll -d '{}'

# 監視モードの iPhone で、許可したアプリだけを使えるようにする
curl -H "$A" localhost:8091/v1/policies -d '{"org_id": "org_...", "name": "小学生の iPhone",
  "apple_apps": {"mode": "allowlist", "allowed": ["com.apple.mobilesafari", "com.apple.MobileSMS"]},
  "device": {"factory_reset_disabled": true, "passcode_min_length": 6}}'

# 返ったポリシーの id を端末に結びつける（持ち主の人に結びつけてもよい）
curl -H "$A" -X PATCH localhost:8091/v1/devices/dev_... -d '{"policy_id": "pol_..."}'
```

iPhone では、Safari で開いたあと「設定」→「プロファイルがダウンロードされました」から入れます（Mac は「システム設定」→「一般」→「デバイス管理」。macOS 12 までは「システム環境設定」→「プロファイル」）。初期化・VPN・アプリの制限は **監視モード** の端末だけで効きます。監視モードにするには、Mac の Apple Configurator で端末を初期化して入れます。監視モードの端末では、登録のあとで通信フィルターの秘密を新しくして MDM が入れ直すので、前に手で入れたプロファイルは消してかまいません。監視モードでない端末は、手で入れたプロファイルをそのまま使います。

「許可の一覧だけを通す」通信フィルターを Android で使うときは、Google Play・Google のサービスのドメインも許可の一覧に入れます（入れないとアプリの更新や管理の通信が止まります）。

### 端末の準拠を IAM に知らせる

端末が会社のルールに沿っているか（準拠）を判定し、変わったら iam に知らせます。iam は受けた状態を記録します（ログインの判定に使うのは iam の側でこれから）。

```sh
# 準拠の条件：暗号化・画面ロック、iPhone は iOS 18.2 以上、3 日以上報告が無ければ準拠していない
curl -H "$A" localhost:8091/v1/policies -d '{"org_id": "org_...", "name": "会社の端末",
  "compliance": {"require_encryption": true, "require_screen_lock": true, "max_report_age_hours": 72,
                 "min_os_version": {"ios": "18.2", "windows": "10.0.22631"}}}'

# 持ち主に iam のメールアドレス（確認済みのもの）を付ける
curl -H "$A" -X PATCH localhost:8091/v1/people/per_... -d '{"email": "taro@example.com"}'

# 判定の結果
curl -H "$A" localhost:8091/v1/devices/dev_...   # "compliance": {"compliant": false, "reasons": ["os_outdated"], ...}
```

iam の側では、`ssf_receiver` を有効にして、管理の API `/v1/admin/ssf/transmitters` で MDM を送信側として登録します。

- `issuer` は MDM の `public.base_url`
- `jwks_uri` は `{public.base_url}/.well-known/jwks.json`
- `audience` は MDM の設定の `ssf.receivers[].audience` と同じ値
- `allowed_actions` は `record_device_posture`

登録で 1 度だけ返る `push_token` をファイルに入れ、MDM の設定の `ssf.receivers` に受け口の URL（`/ssf/receiver/{送信側の ID}`）と一緒に書きます。組織ごとに別の IAM を使うときは、受け手ごとに `org_ids` を書くと、その組織の端末の知らせだけを送ります。

組織の管理者は、自分の組織の IAM を API で登録することもできます（インターネットの https の URL だけ）。`GET` で返る `issuer` と `jwks_uri` を IAM の側の登録に使います。

```sh
curl -H "$A" localhost:8091/v1/orgs/org_.../ssf-receivers -d '{"name": "社の IAM", "url": "https://iam.corp.example/ssf/receiver/stx_...",
  "push_token": "ssfpt_...", "audience": "https://dns.example.com"}'
```

### 証明書で Wi-Fi に入る

Wi-Fi の合言葉の代わりに、MDM が発行した端末の証明書で入るようにします。ルーターが「この端末を入れてよいか」を MDM に問い合わせます（RADIUS）。

1. MDM の設定に `radius` を書きます（`mdm.example.yaml`）。`server_name` はサーバーの証明書の名前で、DNS で引ける名前でなくてかまいません。ルーターとの共有の秘密（16 文字以上のでたらめな文字列）をファイルに入れます
2. ルーターの Wi-Fi の設定で、セキュリティを「WPA2/WPA3 エンタープライズ」（「WPA2-Enterprise」「802.1X」など）にし、RADIUS のサーバーに MDM の IP アドレス、ポート 1812、同じ共有の秘密を入れます。家庭用のルーターには無いことがあるので、そのときは Enterprise に対応したアクセスポイントを使います
3. 端末の証明書を発行して端末に入れます

```sh
# 端末の証明書を発行する（pkcs12 は鍵付きの証明書。password と一緒に、ここでしか表示しない）
curl -H "$A" -X POST localhost:8091/v1/devices/dev_.../network-cert -d '{}'
# → {"pkcs12": "...", "password": "...", "ca_cert": "-----BEGIN CERTIFICATE-----...", "server_name": "radius.home.example", "identity": "dev_..."}

# この端末を Wi-Fi に入れないようにする
curl -H "$A" -X DELETE localhost:8091/v1/devices/dev_.../network-cert
```

iPhone・iPad・Mac・Windows は、ポリシーに `wifi` を書くと、MDM が Wi-Fi の設定と証明書を配ります（手で入れなくてよい）。証明書の期限が近づくと新しくし、管理を外すと取り消します。

```sh
# 家の Wi-Fi（SSID が home-wifi）に証明書で入るルール。ほかのルールと一緒に書く（PUT はポリシーを丸ごと置き換える）
curl -H "$A" localhost:8091/v1/policies -d '{"org_id": "org_...", "name": "家", "wifi": [{"ssid": "home-wifi"}]}'
```

Android は MDM で証明書を入れられないので、端末の Wi-Fi の設定で、EAP の方式を「TLS」、ID を `identity`、サーバーの名前（ドメイン）を `server_name`、CA 証明書を `ca_cert` にして手で入れます。MDM で配っている端末を止めるには、ポリシーの `wifi` から外すか、管理を外します（API で証明書を取り消しても止まりますが、`wifi` を変えると新しく配ります）。

組織の管理者は、サーバーの設定を触らずに、自分の組織のルーターを API で登録できます（インターネットのアドレスのルーターだけ。共有の秘密は MDM が作って 1 度だけ返します）。

```sh
curl -H "$A" localhost:8091/v1/orgs/org_.../radius-clients -d '{"name": "本社", "address": "203.0.113.10"}'
# → {"id": "rdc_...", "secret": "...", "server_name": "radius.example.com", ...}  ルーターに MDM の IP・ポート 1812・secret を入れる
```

組織（家族・会社）ごとに Wi-Fi を分けるときは、`radius.clients` のルーターに `org_ids` を書きます。そのルーターには、その組織の端末だけが入れます（書かなければどの組織の端末も入れます）。

`radius.require_compliant: true` にすると、準拠している端末だけが入れます。RADIUS（UDP）のルーターと MDM のあいだの通信は一部しか暗号化されないので、インターネット越しなら次の RadSec を使います。

#### RadSec（ルーターとのあいだを TLS で守る）

RadSec（RADIUS over TLS）に対応したルーター・アクセスポイントなら、MDM とのあいだの通信をすべて暗号化できます。ルーターはアドレスではなく証明書で見分けるので、家庭の回線のようにアドレスが変わっても使えます。

1. MDM の設定の `radius` に `radsec_listen: ":2083"` を書き、ファイアウォールで TCP の 2083 番を通します
2. 管理画面の「Wi-Fi のルーター」で「RadSec（証明書・TLS）」を選んで足すか、API で登録します

```sh
curl -H "$A" localhost:8091/v1/orgs/org_.../radius-clients -d '{"name": "家", "transport": "radsec"}'
# → {"client_cert": "...", "client_key": "...", "server_ca": "...", "server_name": "radius.example.com", "radsec_address": "radius.example.com:2083", ...}
```

3. ルーターの RadSec の設定に、つなぎ先（`radsec_address`）、クライアント証明書と秘密鍵（`client_cert`・`client_key`）、サーバーを確かめる認証局（`server_ca`）とその名前（`server_name`）、共有の秘密 `radsec` を入れます。秘密鍵はこのときしか表示されません

証明書の期限は 3 年です。作り直すときや、ルーターをなくしたときは、ルーターを消して登録し直します（消すとすぐにつながらなくなります）。

## テスト

```sh
go test -race ./...
```
