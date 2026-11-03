// Package filter は通信フィルター（DNS）の判定を行う。
package filter

import "strings"

// Normalize はドメインを比べられる形にする（小文字、末尾の点なし）。使えない文字があれば空を返す。
func Normalize(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 {
		return ""
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return name
}

// DomainSet はドメインの集まり。登録したドメインのサブドメインにも当たる。
type DomainSet map[string]struct{}

// NewDomainSet は正規化して集める。使えないものは捨てる。
func NewDomainSet(domains []string) DomainSet {
	s := make(DomainSet, len(domains))
	for _, d := range domains {
		if n := Normalize(d); n != "" {
			s[n] = struct{}{}
		}
	}
	return s
}

// Match は name か、その親のドメインが入っていれば、当たったドメインを返す。name は正規化済みであること。
func (s DomainSet) Match(name string) (string, bool) {
	if len(s) == 0 {
		return "", false
	}
	for {
		if _, ok := s[name]; ok {
			return name, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false
		}
		name = name[i+1:]
	}
}
