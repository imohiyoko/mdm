// Package adminapi は管理の API（JSON）。組織・グループ・人・端末・ポリシー・ブロックの一覧を扱う。
package adminapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/imohiyoko/mdm/core"
)

// AdminToken は管理の API の鍵。設定には鍵の SHA-256（16 進）だけを書く。
// 最初の管理者の登録と、自動化（スクリプト）に使う。人の管理者は IAM でログインする（Introspector）。
type AdminToken struct {
	Name   string         `yaml:"name"` // 操作の記録に残す名前
	SHA256 string         `yaml:"sha256"`
	Role   core.AdminRole `yaml:"role"`   // 空なら server_admin
	OrgID  string         `yaml:"org_id"` // org_admin・org_viewer のときの組織
}

// Introspection は IAM が答えたアクセストークンの中身（RFC 7662 のうち使うもの）。
type Introspection struct {
	Active   bool
	Issuer   string
	Subject  string
	Username string // 表示用（メールアドレスなど）
}

// Introspector は IAM のアクセストークンを確かめるポート。
type Introspector interface {
	Introspect(ctx context.Context, token string) (Introspection, error)
}

// UISessions は管理画面のセッション（webui.UI）。要求のクッキーから IAM のアクセストークンを引く。
type UISessions interface {
	Token(r *http.Request) (string, bool)
}

// Principal は API を呼んだ管理者。
type Principal struct {
	Name  string
	Roles []core.AdminBinding
	// Issuer と Subject は IAM でログインした人のもの（設定の鍵なら空）。役割が無くても入る（サインアップ・招待を受けるため）。
	Issuer, Subject string
}

// IsServerAdmin はサーバー全体の管理者か。
func (p *Principal) IsServerAdmin() bool {
	for _, r := range p.Roles {
		if r.Role == core.AdminServer {
			return true
		}
	}
	return false
}

// CanRead は組織 orgID を見られるか。orgID が空（サーバー全体のもの）は、誰でも見られる。
func (p *Principal) CanRead(orgID string) bool {
	if orgID == "" || p.IsServerAdmin() {
		return true
	}
	for _, r := range p.Roles {
		if r.OrgID == orgID && (r.Role == core.AdminOrg || r.Role == core.AdminOrgViewer) {
			return true
		}
	}
	return false
}

// CanWrite は組織 orgID を変えられるか。orgID が空（サーバー全体のもの）はサーバー全体の管理者だけ。
func (p *Principal) CanWrite(orgID string) bool {
	if p.IsServerAdmin() {
		return true
	}
	if orgID == "" {
		return false
	}
	for _, r := range p.Roles {
		if r.OrgID == orgID && r.Role == core.AdminOrg {
			return true
		}
	}
	return false
}

// soleOrg は、組織を 1 つだけ管理する管理者のその組織（作るときに org_id を省けるように）。
func (p *Principal) soleOrg() string {
	if p.IsServerAdmin() || len(p.Roles) != 1 {
		return ""
	}
	return p.Roles[0].OrgID
}

type principalKey struct{}

func principal(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	if p == nil {
		return &Principal{}
	}
	return p
}

func bearer(r *http.Request) (string, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return raw, ok && raw != ""
}

// staticToken は設定の鍵を照合する。
func staticToken(tokens []AdminToken, raw string) (*Principal, bool) {
	sum := sha256.Sum256([]byte(raw))
	var found *AdminToken
	for i := range tokens {
		want, err := hex.DecodeString(tokens[i].SHA256)
		if err != nil || len(want) != sha256.Size {
			continue
		}
		// どの鍵に当たったかで時間が変わらないよう、すべて比べる。
		if subtle.ConstantTimeCompare(sum[:], want) == 1 {
			found = &tokens[i]
		}
	}
	if found == nil {
		return nil, false
	}
	role := found.Role
	if role == "" {
		role = core.AdminServer
	}
	return &Principal{Name: found.Name, Roles: []core.AdminBinding{{Role: role, OrgID: found.OrgID}}}, true
}

// authenticate は設定の鍵か IAM のアクセストークンで管理者を決める。
func (s *Server) authenticate(r *http.Request) (*Principal, bool) {
	raw, ok := bearer(r)
	fromUI := false
	if !ok && s.UI != nil {
		raw, ok = s.UI.Token(r)
		fromUI = ok
	}
	if !ok {
		return nil, false
	}
	return s.principalForToken(r.Context(), raw, fromUI)
}

// principalForToken はトークン raw（設定の鍵か IAM のアクセストークン）の管理者を決める。
// fromUI（管理画面のセッションのトークン）なら、設定の鍵とは照合しない。
func (s *Server) principalForToken(ctx context.Context, raw string, fromUI bool) (*Principal, bool) {
	if !fromUI {
		if p, ok := staticToken(s.Tokens, raw); ok {
			return p, true
		}
	}
	if s.Introspector == nil || strings.HasPrefix(raw, "mdm_") {
		return nil, false
	}
	in, err := s.Introspector.Introspect(ctx, raw)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Warn("introspection", "err", err)
		}
		return nil, false
	}
	if !in.Active || in.Subject == "" {
		return nil, false
	}
	roles, err := s.Store.AdminBindingsFor(ctx, in.Issuer, in.Subject)
	if err != nil {
		return nil, false
	}
	name := in.Username
	if name == "" {
		name = in.Subject
	}
	// 役割が無くても返す。使えるのは roleless の API だけ（Handler で絞る）。
	return &Principal{Name: name, Roles: roles, Issuer: in.Issuer, Subject: in.Subject}, true
}
