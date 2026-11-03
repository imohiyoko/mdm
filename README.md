# mdm

家庭・小さな組織向けの、セルフホストできる端末管理（MDM）。iPhone・iPad・Android・Windows・Mac を 1 か所から管理し、子どもの端末の通信・アプリ・時間を見守ることを目指す（実験段階）。

ログインと「この端末はルールを守れているか」の連携は、同じ作者の [iam](https://github.com/imohiyoko/iam) と組み合わせる。

- 設計: [docs/design.md](docs/design.md)
- ロードマップ: [docs/roadmap.md](docs/roadmap.md)
- 設計判断の記録（ADR）: [docs/adr/](docs/adr/README.md)
- ライセンス: [Apache-2.0](LICENSE)

## いまできること

段階 1・2（土台と通信フィルター）。

- 家族（人）・端末・ポリシー（ルール）を管理の API で登録する
- 端末ごとの **通信フィルター**（暗号化した DNS）
  - ブロックの一覧・許可の一覧・外部のブロックの一覧（hosts 形式など）の取り込み
  - 「許可の一覧だけを通す」モード（小さな子ども向け）
  - 止める時間帯（夜など。タイムゾーン付き）、「今すぐ止める」
  - 止めた通信の記録（通した通信の記録はポリシーで選ぶ）
  - 「この端末でこのサイトは止まるか」の確認
- 管理の操作の記録

端末の登録（MDM の本体）は段階 3 から。それまでは、通信フィルターを端末に手で設定して使う（子どもが設定を外せないようにするのは MDM の段階で行う）。

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

# 小学生向けのルール：ゲームのサイトを止め、21 時〜7 時は止める
curl -H "$A" localhost:8091/v1/policies -d '{
  "name": "小学生", "block": ["game.example"], "allow": ["school.example"],
  "quiet_hours": [{"start": "21:00", "end": "07:00"}], "time_zone": "Asia/Tokyo"}'

# 子どもと端末を登録する（端末の設定に使う情報が返る。秘密を含むので、ここでしか表示しない）
curl -H "$A" localhost:8091/v1/people -d '{"name": "たろう", "policy_id": "pol_..."}'
curl -H "$A" localhost:8091/v1/devices -d '{"name": "たろうの iPhone", "platform": "ios", "person_id": "per_..."}'

# 30 分だけ止める
curl -H "$A" localhost:8091/v1/devices/dev_.../pause -d '{"minutes": 30}'
```

### 端末に通信フィルターを設定する

端末を登録したときに返る `filter` の値を使います。

| 端末 | 設定のしかた |
| --- | --- |
| iPhone・iPad・Mac | `apple_profile_url` を Safari で開き、「設定」→「プロファイルがダウンロード済み」からインストール |
| Android | 「設定」→「ネットワーク」→「プライベート DNS」に `dot_hostname` を入れる（`dot` の設定が要る） |
| Windows 11 | 「設定」→「ネットワークとインターネット」→ DNS サーバーの割り当てで、暗号化（DNS over HTTPS）のテンプレートに `doh_url` を入れる |
| Chrome・Edge・Firefox | 「セキュア DNS」の「カスタム」に `doh_url` を入れる |

`doh_url` と `dot_hostname` は端末ごとの秘密を含みます。漏れたときは `POST /v1/devices/{id}/filter-token` で作り直します。

## テスト

```sh
go test -race ./...
```
