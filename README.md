# mdm

セルフホストできる端末管理（MDM）。iPhone・iPad・Android・Windows・Mac を 1 か所から管理する。家庭での子どもの端末の見守りと、会社のエンドポイント管理の両方に使う（実験段階）。

ログインと「この端末はルールを守れているか」の連携は、同じ作者の [iam](https://github.com/imohiyoko/iam) と組み合わせる。

- 設計: [docs/design.md](docs/design.md)
- ロードマップ: [docs/roadmap.md](docs/roadmap.md)
- 設計判断の記録（ADR）: [docs/adr/](docs/adr/README.md)
- ライセンス: [Apache-2.0](LICENSE)

## いまできること

段階 1〜3（土台・通信フィルター・組織と管理者）。

- 組織（家族・会社）を分け、組織ごとに人・グループ（部署など）・端末・ポリシー（ルール）を管理の API で登録する
- 管理者の役割：サーバー全体の管理者・組織の管理者・組織を見るだけ。管理者は IAM でログインする（設定の鍵でも使える）
- ポリシーは 端末 → 人 → 人のグループ（優先度の高い順）→ 組織の既定 → サーバー全体の既定 の順に決まる
- 端末ごとの **通信フィルター**（暗号化した DNS）
  - ブロックの一覧・許可の一覧・外部のブロックの一覧（hosts 形式など）の取り込み
  - 「許可の一覧だけを通す」モード（小さな子ども向け）
  - 止める時間帯（夜など。タイムゾーン付き）、「今すぐ止める」
  - 止めた通信の記録（通した通信の記録はポリシーで選ぶ）
  - 「この端末でこのサイトは止まるか」の確認
- 管理の操作の記録

端末の登録（MDM の本体）は段階 4 から。それまでは、通信フィルターを端末に手で設定して使う（子どもが設定を外せないようにするのは MDM の段階で行う）。

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

### 管理者が IAM でログインする

1. IAM に、この MDM を連携先（機密クライアント）として登録し、client_id と client_secret を設定の `oidc` に書く。MDM はその連携先としてアクセストークンをイントロスペクションで確かめる
2. 管理の API で、IAM のユーザー（`sub`）に役割を与える

```sh
curl -H "$A" localhost:8091/v1/admins -d '{"subject": "<IAM の sub>", "label": "boss@example.com", "role": "org_admin", "org_id": "org_..."}'
```

3. その人は IAM で取ったアクセストークンを `Authorization: Bearer` に付けて管理の API を使う。IAM でログインできても、役割を与えていなければ使えない

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

## テスト

```sh
go test -race ./...
```
