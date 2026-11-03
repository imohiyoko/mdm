// Package blocklist は外部のブロックの一覧（hosts 形式・ドメインの一覧・Adblock の ||domain^）を取り込む。
package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

// 一覧の大きさの上限。大きすぎる一覧でメモリを使い切らないため。
const (
	MaxBytes   = 64 << 20
	MaxDomains = 2_000_000
)

// Parse は一覧を読む。読めない行は飛ばす。
func Parse(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(io.LimitReader(r, MaxBytes))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	seen := map[string]struct{}{}
	var out []string
	for sc.Scan() {
		d := parseLine(sc.Text())
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		if len(out) >= MaxDomains {
			return nil, fmt.Errorf("too many domains (> %d)", MaxDomains)
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out, sc.Err()
}

func parseLine(line string) string {
	if i := strings.IndexAny(line, "#!"); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	// Adblock 形式は、ドメイン全体を止める ||example.com^ だけを読む。
	if rest, ok := strings.CutPrefix(line, "||"); ok {
		d, ok := strings.CutSuffix(rest, "^")
		if !ok {
			return ""
		}
		return filter.Normalize(d)
	}
	fields := strings.Fields(line)
	switch len(fields) {
	case 1:
		return filter.Normalize(fields[0])
	case 2:
		// hosts 形式。止めるためのアドレスの行だけを読む。
		switch fields[0] {
		case "0.0.0.0", "127.0.0.1", "::", "::1":
		default:
			return ""
		}
		d := filter.Normalize(fields[1])
		if d == "localhost" || d == "localhost.localdomain" || d == "local" || d == "broadcasthost" {
			return ""
		}
		return d
	}
	return ""
}

// Refresher は一覧を取り込み直す。
type Refresher struct {
	Store  core.Store
	Clock  core.Clock
	Client *http.Client
	// OnChange は取り込み直したあとに呼ぶ（判定の読み直し）。
	OnChange func()
	Logger   *slog.Logger
}

// ValidateURL は取り込み先の URL を確かめる。改ざんされないよう https だけを許す。
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("blocklist url must be https://host/...")
	}
	return nil
}

// Refresh は id の一覧を取り込み直す。失敗したら、前の中身を残してエラーを記録する。
func (r *Refresher) Refresh(ctx context.Context, id string) error {
	b, err := r.Store.GetBlocklist(ctx, id)
	if err != nil {
		return err
	}
	domains, err := r.fetch(ctx, b.URL)
	if err != nil {
		_ = r.Store.SetBlocklistError(ctx, id, err.Error())
		return err
	}
	if err := r.Store.ReplaceBlocklistDomains(ctx, id, domains, r.Clock.Now()); err != nil {
		return err
	}
	if r.OnChange != nil {
		r.OnChange()
	}
	return nil
}

func (r *Refresher) fetch(ctx context.Context, raw string) ([]string, error) {
	if err := ValidateURL(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	c := r.Client
	if c == nil {
		c = &http.Client{Timeout: time.Minute}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return Parse(resp.Body)
}

// RefreshAll はすべての一覧を取り込み直す。1 つの失敗で止めない。
func (r *Refresher) RefreshAll(ctx context.Context) {
	lists, err := r.Store.ListBlocklists(ctx)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Error("list blocklists", "err", err)
		}
		return
	}
	for _, b := range lists {
		if err := r.Refresh(ctx, b.ID); err != nil && r.Logger != nil {
			r.Logger.Warn("refresh blocklist", "id", b.ID, "err", err)
		}
	}
}
