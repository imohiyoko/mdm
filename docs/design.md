# 設計

## 1. 目的と範囲

家庭・小さな組織の端末（iPhone・iPad・Android・Windows・Mac）を 1 か所から管理する。特に、子どもの端末の通信・アプリ・時間を見守る。

- ログイン・権限は [iam](https://github.com/imohiyoko/iam) に任せる（段階 6）。iam の範囲（`docs/scope.md`）で MDM は iam の外と決めているため、別のリポジトリにする（ADR [0001](adr/0001-separate-repository.md)）
- 規模は 1 家庭〜数百台。1 つのプロセスと SQLite で動くことを優先する

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
- DoT（Android のプライベート DNS）：TLS のホスト名 `{秘密}.{dot.domain}`。DNS のラベルは大文字・小文字を区別しないので、秘密は小文字にそろえてから照合する

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

一覧はドメインとそのサブドメインに当たる。ポリシーは 端末 → 持ち主 → 既定（`default`）の順に決まる。

### 3.3 止め方

NXDOMAIN を返し、端末が EDNS を使っていれば拡張エラー「Blocked」（RFC 8914、15）を付ける。上流に問い合わせられなければ SERVFAIL。

### 3.4 記録

止めた通信はいつも記録する。通した通信はポリシーの `log_queries` が true のときだけ。記録はまとめて書き（DNS を遅くしない）、溢れたら捨てる。`filter.query_log_retention_days` を過ぎたら消す。

## 4. 管理の API

`/v1/` 以下。`Authorization: Bearer` の鍵で認証する。設定には鍵の SHA-256 だけを書く。段階 6 で iam のログインに置き換える。

| 対象 | 操作 |
| --- | --- |
| `/v1/people` | 一覧・作成・取得・更新（PATCH）・削除 |
| `/v1/devices` | 一覧・作成・取得・更新（PATCH）・削除。作成で通信フィルターの設定の情報（秘密を含む）を返す |
| `/v1/devices/{id}/filter-token` | 秘密の作り直し |
| `/v1/devices/{id}/pause` | 今すぐ止める（POST、`minutes`）・戻す（DELETE） |
| `/v1/devices/{id}/queries` | 通信の記録 |
| `/v1/devices/{id}/check` | このサイトは止まるか（記録しない） |
| `/v1/policies` | 一覧・作成・取得・置き換え（PUT）・削除。既定のポリシーは消せない |
| `/v1/blocklists` | 一覧・作成（取り込みは後ろで行う）・削除・取り込み直し |
| `/v1/audit` | 管理の操作の記録 |

使われているもの（端末のある人、使われているポリシー・一覧）は消せない（409）。

## 5. 機種ごとの管理（段階 3〜5）

ADR [0003](adr/0003-platform-channels.md)。

| 機種 | 入り口 | 事前に要るもの | 強い制限 |
| --- | --- | --- | --- |
| Android | Android Management API | Google Cloud のプロジェクト | 初期化してから登録（完全管理） |
| iPhone・iPad | Apple の MDM | APNs の MDM 用の証明書 | 監視モード（Apple Configurator で初期化して入れる） |
| Mac | Apple の MDM | 同じ | 一部は監視モード |
| Windows | Windows 標準の MDM（OMA-DM） | 公開の HTTPS の入り口 | Pro 以上 |

それぞれ「登録」「ポリシーの配布」「状態の受け取り」「ロック・初期化」を同じ形のポートにそろえ、機種ごとにアダプタを作る。

## 6. iam との連携（段階 6）

- 管理者のログイン：iam の OIDC
- 端末の準拠の状態（ルールを守れているか、最後に通信した時刻など）を iam に送り、iam はログインの判定に使う。iam 側の受け口に合わせる
