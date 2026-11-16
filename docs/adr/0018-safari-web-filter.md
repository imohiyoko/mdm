# 0018. Safari の制限は制限のプロファイルに足し、Web のフィルターは監視モードの iPhone・iPad だけに配る

- 状態: 承認
- 日付: 2026-11-16
- 関連: [plan-jamf-intune.md](../plan-jamf-intune.md) 10a、[design.md](../design.md) 5.3、ADR [0007](0007-apple-mdm.md)

## 背景

DNS フィルター（ADR 0002）は Safari にも効くが、ドメイン単位でしか止められず、Safari そのもの（使用・ポップアップ・プライベートブラウズ）は止められない。Apple の MDM には、制限（`com.apple.applicationaccess`）の Safari のキーと、URL 単位の組み込みの Web のフィルター（`com.apple.webcontent-filter` の `FilterType: BuiltIn`）がある。

キーごとの対応 OS・監視モードの要否は Apple の device-management（`mdm/profiles/com.apple.applicationaccess.yaml`・`com.apple.webcontent-filter.yaml`）に従う。要点：

- `allowSafari` は iOS の監視モードだけ。`safariAllowPopups`・`safariForceFraudWarning`・`safariAcceptCookies` は iOS だけ（macOS は n/a）。`safariAllowAutoFill` は iOS（監視モード）と macOS。`allowSafariPrivateBrowsing` は iOS・macOS 26 以降
- 組み込みの Web のフィルターは iOS だけ（macOS はプラグインの型だけ）。iOS 16 以降、監視モードでない端末にはプラグインの型（`ContentFilterUUID`）しか入れられない
- `DenyListURLs` は 500 件までにするよう求められている。`PermittedURLs` は `AutoFilterEnabled` のときだけ意味がある

## 決定

- ポリシーに `safari`（core.SafariRules）と `web_filter`（core.WebFilterRules）を足す。管理の API・ルールの API（0.3.0）・`mdm rules` で扱う
- Safari の制限は今の制限のプロファイルに足す。**止めるものだけキーを書く**。何も止めないポリシーのプロファイルは今と同じ形のままで、配り直しが起きない。端末が知らないキー（古い OS、Mac での iPhone だけのキー）は端末が無視する
- Web のフィルターは、**監視モードの iPhone・iPad のときだけ** 制限のプロファイルにペイロードを足す。Mac や監視モードでない端末に入れると、プロファイルごと入らずにほかの制限まで外れるため。監視モードと分かった（端末の情報の答え）あとの配り直しで入る
- `allow_only` があれば、そこに書いた URL だけを開けるようにする（AllowListBookmarks）。`limit_adult`・`denied` とはいっしょに使えない（400）
- URL は http・https でホスト名があり、利用者名・パスワード・空白・制御文字を含まない、2048 バイトまでのものだけ（違えば 400）。各 500 件まで
- `allow_only` の題は 100 文字まで（超えれば 400）。題を省けば URL を使い、100 文字を超える URL は題だけ 100 文字で切る
- Web のフィルターには `SafariHistoryRetentionEnabled: false` を必ず書く。iOS 26 以降は書かないと true になり、履歴を残させてプライベートブラウズを止めてしまう。止めるかは `safari.private_browsing_disabled` で決める

## 結果

- 監視モードの iPhone・iPad では、Safari を止める・URL 単位で止める・決めたサイトだけにする、ができる
- 監視モードでない iPhone・iPad と Mac では、DNS フィルターと、その端末に効く Safari の制限だけになる。Mac の Safari の細かい設定は、宣言型の管理（段階 10c）の `safari.settings`（macOS 26 以降）で後で足す
- ポリシーの版（ルールの API の `version`）は、項目が増えたので一度だけ変わる。古い版を持って `expected_version` を送った書き込みは 412 になるので、読み直してから送る

## 検討した代替案

- Web のフィルターを別のプロファイルにする：入れる・消すの管理が増える。制限のプロファイルの中身が監視モードで変わるだけなら、今の「要約が変わったら入れ直す」で足りる
- Mac の Safari を管理された設定（`com.apple.Safari` のマネージドプリファレンス）で止める：Apple が仕様として載せていないので使わない
