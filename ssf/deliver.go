package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// Receiver は SET を送る受け手（IAM の受け口など）。
type Receiver struct {
	Name string
	// URL は push の受け口（IAM なら https://iam.example/ssf/receiver/{送信側の ID}）。
	URL string
	// PushToken は受け手が出した Bearer の値。
	PushToken string
	// OrgIDs があれば、その組織の端末の知らせだけを送る（組織ごとの IAM）。空ならすべての組織の知らせを送る。
	OrgIDs []string
	// Audience は SET の aud。
	Audience string
}

// Transmitter は準拠の状態の変化を SET にして送る。
type Transmitter struct {
	Store     core.Store
	Clock     core.Clock
	Signer    *Signer
	Issuer    string
	Receivers []Receiver
	HTTP      *http.Client
	Logger    *slog.Logger
}

func (t *Transmitter) log() *slog.Logger {
	if t.Logger == nil {
		return slog.Default()
	}
	return t.Logger
}

// Enabled は受け手が 1 つでもあるか。
func (t *Transmitter) Enabled() bool { return t != nil && len(t.Receivers) > 0 }

// Enqueue は変化を受け手ごとの SET にして、送る待ちに入れる。
func (t *Transmitter) Enqueue(ctx context.Context, c ComplianceChange) error {
	if !t.Enabled() || c.Email == "" {
		return nil
	}
	now := t.Clock.Now()
	var evs []core.SSFEvent
	for _, r := range t.Receivers {
		if len(r.OrgIDs) > 0 && !slices.Contains(r.OrgIDs, c.OrgID) {
			continue
		}
		set, err := t.Signer.Sign(ComplianceSET(t.Issuer, r.Audience, c, now))
		if err != nil {
			return err
		}
		evs = append(evs, core.SSFEvent{Receiver: r.Name, SET: set, NextAt: now, CreatedAt: now})
	}
	return t.Store.EnqueueSSF(ctx, evs)
}

func backoff(attempts int) time.Duration {
	d := 10 * time.Second
	for i := 0; i < attempts && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

// DeliverDue は送る時刻が来た SET を送る。
func (t *Transmitter) DeliverDue(ctx context.Context) error {
	evs, err := t.Store.DueSSF(ctx, t.Clock.Now(), 100)
	if err != nil {
		return err
	}
	for _, e := range evs {
		var r *Receiver
		for i := range t.Receivers {
			if t.Receivers[i].Name == e.Receiver {
				r = &t.Receivers[i]
			}
		}
		if r == nil { // 設定から消した受け手
			if err := t.Store.DeleteSSF(ctx, e.ID); err != nil {
				return err
			}
			continue
		}
		done, msg := t.send(ctx, *r, e.SET)
		if done {
			if msg != "" {
				t.log().Warn("ssf: 受け手が SET を受けなかった", "receiver", r.Name, "err", msg)
			}
			if err := t.Store.DeleteSSF(ctx, e.ID); err != nil {
				return err
			}
			continue
		}
		t.log().Warn("ssf: 送れなかった。あとで送り直す", "receiver", r.Name, "err", msg)
		if err := t.Store.RetrySSF(ctx, e.ID, t.Clock.Now().Add(backoff(e.Attempts)), msg); err != nil {
			return err
		}
	}
	return nil
}

// send は 1 つの SET を送る。done は待ちから外してよいか（届いた、または受け手が受けないと答えた）。
func (t *Transmitter) send(ctx context.Context, r Receiver, set string) (done bool, msg string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, strings.NewReader(set))
	if err != nil {
		return true, err.Error()
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.PushToken)
	client := t.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, ""
	case resp.StatusCode == http.StatusBadRequest:
		// RFC 8935 2.3：受け手がこの SET を受けない。送り直しても同じ。
		var e struct {
			Err         string `json:"err"`
			Description string `json:"description"`
		}
		_ = json.Unmarshal(body, &e)
		return true, fmt.Sprintf("rejected: %s %s", e.Err, e.Description)
	default:
		return false, fmt.Sprintf("%d %s", resp.StatusCode, bytes.TrimSpace(body))
	}
}

// Run は interval ごとに送る。
func (t *Transmitter) Run(ctx context.Context, interval time.Duration) {
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		if err := t.DeliverDue(ctx); err != nil && ctx.Err() == nil {
			t.log().Error("ssf deliver", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// Handler は /.well-known/jwks.json と /.well-known/ssf-configuration。
func (t *Transmitter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write(t.Signer.JWKS())
	})
	mux.HandleFunc("GET /.well-known/ssf-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(Configuration(t.Issuer))
	})
	return mux
}
