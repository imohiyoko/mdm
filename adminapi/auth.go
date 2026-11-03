// Package adminapi は管理の API（JSON）。家族・端末・ポリシー・ブロックの一覧を扱う。
package adminapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// AdminToken は管理の API の鍵。設定には鍵の SHA-256（16 進）だけを書く。
// 段階 6 で IAM のログイン（OIDC）に置き換える。
type AdminToken struct {
	Name   string // 操作の記録に残す名前
	SHA256 string
}

// authenticate は Authorization: Bearer の鍵を照合し、管理者の名前を返す。
func authenticate(tokens []AdminToken, r *http.Request) (string, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(raw))
	name, found := "", 0
	for _, t := range tokens {
		want, err := hex.DecodeString(t.SHA256)
		if err != nil || len(want) != sha256.Size {
			continue
		}
		// どの鍵に当たったかで時間が変わらないよう、すべて比べる。
		if subtle.ConstantTimeCompare(sum[:], want) == 1 {
			name, found = t.Name, found+1
		}
	}
	return name, found > 0
}
