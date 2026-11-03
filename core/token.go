package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

var tokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewFilterToken は通信フィルターで端末を見分ける秘密を作る。
// 英小文字と数字の 32 文字なので、URL のパスにも DNS のラベル（DoT のホスト名）にも使える。
func NewFilterToken() (token string, hash []byte) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand は失敗しない（Go 1.24〜）
	}
	token = strings.ToLower(tokenEncoding.EncodeToString(b))
	return token, HashFilterToken(token)
}

// HashFilterToken は保存・照合に使うハッシュ。大文字・小文字を区別しない（DNS のラベルは区別しないため）。
func HashFilterToken(token string) []byte {
	h := sha256.Sum256([]byte(strings.ToLower(token)))
	return h[:]
}

// LooksLikeFilterToken は形だけを確かめる。
func LooksLikeFilterToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range strings.ToLower(s) {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

// NewID は内部の ID を作る。
func NewID(prefix string) string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + "_" + strings.ToLower(tokenEncoding.EncodeToString(b))
}
