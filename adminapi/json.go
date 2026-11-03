package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{code, msg})
}

func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, core.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "")
	case errors.Is(err, core.ErrConflict):
		writeErr(w, http.StatusConflict, "conflict", "参照されている・同じものがある")
	default:
		writeErr(w, http.StatusInternalServerError, "internal", "")
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	return true
}

type badRequest string

func (b badRequest) Error() string { return string(b) }

func bad(format string, a ...any) error { return badRequest(fmt.Sprintf(format, a...)) }

// --- people

type personJSON struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Role      core.Role `json:"role"`
	PolicyID  string    `json:"policy_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func toPersonJSON(p core.Person) personJSON {
	return personJSON{p.ID, p.Name, p.Role, p.PolicyID, p.CreatedAt}
}

type personInput struct {
	Name     *string    `json:"name"`
	Role     *core.Role `json:"role"`
	PolicyID *string    `json:"policy_id"`
}

func (in personInput) apply(p *core.Person) error {
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Role != nil {
		p.Role = *in.Role
	}
	if in.PolicyID != nil {
		p.PolicyID = *in.PolicyID
	}
	if p.Name == "" || len(p.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	if p.Role != core.RoleChild && p.Role != core.RoleAdult {
		return bad("role は child か adult")
	}
	return nil
}

// --- devices

type deviceJSON struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Platform    core.Platform `json:"platform"`
	PersonID    string        `json:"person_id,omitempty"`
	PolicyID    string        `json:"policy_id,omitempty"`
	PausedUntil *time.Time    `json:"paused_until,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	LastSeenAt  *time.Time    `json:"last_seen_at,omitempty"`
}

func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func toDeviceJSON(d core.Device, now time.Time) deviceJSON {
	var paused *time.Time
	if now.Before(d.PausedUntil) {
		paused = &d.PausedUntil
	}
	return deviceJSON{d.ID, d.Name, d.Platform, d.PersonID, d.PolicyID, paused, d.CreatedAt, optTime(d.LastSeenAt)}
}

type deviceInput struct {
	Name     *string        `json:"name"`
	Platform *core.Platform `json:"platform"`
	PersonID *string        `json:"person_id"`
	PolicyID *string        `json:"policy_id"`
}

func (in deviceInput) apply(d *core.Device) error {
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
	}
	if in.Platform != nil {
		d.Platform = *in.Platform
	}
	if in.PersonID != nil {
		d.PersonID = *in.PersonID
	}
	if in.PolicyID != nil {
		d.PolicyID = *in.PolicyID
	}
	if d.Name == "" || len(d.Name) > 100 {
		return bad("name は 1〜100 文字")
	}
	if !d.Platform.Valid() {
		return bad("platform は ios・android・windows・macos・other のどれか")
	}
	return nil
}

// --- policies

type windowJSON struct {
	Days  []string `json:"days,omitempty"` // "mon"〜"sun"。空なら毎日
	Start string   `json:"start"`          // "21:00"
	End   string   `json:"end"`            // "07:00"
}

type policyJSON struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Mode       core.FilterMode `json:"mode"`
	Allow      []string        `json:"allow"`
	Block      []string        `json:"block"`
	Blocklists []string        `json:"blocklists"`
	QuietHours []windowJSON    `json:"quiet_hours"`
	TimeZone   string          `json:"time_zone,omitempty"`
	LogQueries bool            `json:"log_queries"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

var dayNames = []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

func formatClock(m core.TimeOfDay) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }

func parseClock(s string) (core.TimeOfDay, error) {
	h, m, ok := strings.Cut(s, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, bad("時刻は HH:MM（%q）", s)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 24 || mm < 0 || mm > 59 || hh == 24 && mm != 0 {
		return 0, bad("時刻は HH:MM（%q）", s)
	}
	return core.TimeOfDay(hh*60 + mm), nil
}

func toPolicyJSON(p core.Policy) policyJSON {
	out := policyJSON{
		ID: p.ID, Name: p.Name, Mode: p.Mode, Allow: nonNil(p.Allow), Block: nonNil(p.Block),
		Blocklists: nonNil(p.ListIDs), QuietHours: []windowJSON{}, TimeZone: p.TimeZone,
		LogQueries: p.LogQueries, UpdatedAt: p.UpdatedAt,
	}
	for _, w := range p.Quiet {
		wj := windowJSON{Start: formatClock(w.Start), End: formatClock(w.End)}
		for _, d := range w.Days {
			wj.Days = append(wj.Days, dayNames[d])
		}
		out.QuietHours = append(out.QuietHours, wj)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type policyInput struct {
	Name       string          `json:"name"`
	Mode       core.FilterMode `json:"mode"`
	Allow      []string        `json:"allow"`
	Block      []string        `json:"block"`
	Blocklists []string        `json:"blocklists"`
	QuietHours []windowJSON    `json:"quiet_hours"`
	TimeZone   string          `json:"time_zone"`
	LogQueries bool            `json:"log_queries"`
}

const maxPolicyDomains = 10000

func normalizeDomains(field string, in []string) ([]string, error) {
	if len(in) > maxPolicyDomains {
		return nil, bad("%s は %d 件まで", field, maxPolicyDomains)
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		n := filter.Normalize(strings.TrimPrefix(strings.TrimSpace(d), "*."))
		if n == "" {
			return nil, bad("%s に使えないドメイン %q", field, d)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func (in policyInput) toPolicy(id string) (core.Policy, error) {
	p := core.Policy{ID: id, Name: strings.TrimSpace(in.Name), Mode: in.Mode, TimeZone: in.TimeZone, LogQueries: in.LogQueries, ListIDs: in.Blocklists}
	if p.Name == "" || len(p.Name) > 100 {
		return p, bad("name は 1〜100 文字")
	}
	if p.Mode == "" {
		p.Mode = core.FilterBlocklist
	}
	if p.Mode != core.FilterBlocklist && p.Mode != core.FilterAllowlistOnly {
		return p, bad("mode は blocklist か allowlist_only")
	}
	if p.TimeZone != "" {
		if _, err := time.LoadLocation(p.TimeZone); err != nil {
			return p, bad("time_zone が分からない（%q）", p.TimeZone)
		}
	}
	var err error
	if p.Allow, err = normalizeDomains("allow", in.Allow); err != nil {
		return p, err
	}
	if p.Block, err = normalizeDomains("block", in.Block); err != nil {
		return p, err
	}
	if len(in.QuietHours) > 50 {
		return p, bad("quiet_hours は 50 件まで")
	}
	for _, wj := range in.QuietHours {
		var w core.Window
		if w.Start, err = parseClock(wj.Start); err != nil {
			return p, err
		}
		if w.End, err = parseClock(wj.End); err != nil {
			return p, err
		}
		if w.End == 24*60 {
			w.End = 0
		}
		if w.Start == 24*60 {
			return p, bad("start に 24:00 は使えない")
		}
		if w.Start == w.End {
			return p, bad("start と end が同じ")
		}
		for _, d := range wj.Days {
			i := indexOf(dayNames, strings.ToLower(d))
			if i < 0 {
				return p, bad("days は sun〜sat（%q）", d)
			}
			w.Days = append(w.Days, time.Weekday(i))
		}
		p.Quiet = append(p.Quiet, w)
	}
	return p, nil
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// --- blocklists

type blocklistJSON struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Domains     int        `json:"domains"`
	RefreshedAt *time.Time `json:"refreshed_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

func toBlocklistJSON(b core.Blocklist) blocklistJSON {
	return blocklistJSON{b.ID, b.Name, b.URL, b.Domains, optTime(b.RefreshedAt), b.LastError}
}
