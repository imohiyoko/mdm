// Package resolver は端末からの DNS の問い合わせを受け、通信フィルターの判定をして、通すものは上流に送る。
package resolver

import (
	"context"
	"errors"
	"log/slog"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/filter"
)

// Upstream は上流の DNS のポート。msg は DNS のメッセージ（ワイヤ形式）。
type Upstream interface {
	Exchange(ctx context.Context, msg []byte) ([]byte, error)
}

// Resolver は判定と転送を行う。
type Resolver struct {
	Engine   *filter.Engine
	Upstream Upstream
	Log      *QueryLogger // nil なら記録しない
	Logger   *slog.Logger
}

// ErrUnknownDevice は秘密に当たる端末が無い。
var ErrUnknownDevice = errors.New("unknown device")

// edeBlocked は Extended DNS Errors（RFC 8914）の「Blocked」。
const edeBlocked = 15

// Handle は token の端末からの問い合わせ msg に答える。
func (r *Resolver) Handle(ctx context.Context, token string, msg []byte) ([]byte, error) {
	dev, err := r.Engine.Device(ctx, token)
	if errors.Is(err, core.ErrNotFound) {
		return nil, ErrUnknownDevice
	}
	if err != nil {
		return nil, err
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(msg)
	if err != nil {
		return nil, err // 壊れたメッセージには答えない
	}
	if hdr.Response {
		return nil, errors.New("not a query")
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || hdr.OpCode != 0 {
		return reply(hdr, qs, dnsmessage.RCodeFormatError, false)
	}
	edns := hasEDNS(&p)
	q := qs[0]
	name := q.Name.String()
	dec, pol, err := r.Engine.Decide(ctx, dev, name)
	if err != nil {
		return nil, err
	}
	r.record(dev, pol, name, q.Type, dec)
	if dec.Action == core.ActionBlock {
		return reply(hdr, qs, dnsmessage.RCodeNameError, edns)
	}
	resp, err := r.Upstream.Exchange(ctx, msg)
	if err != nil {
		if r.Logger != nil {
			r.Logger.Warn("upstream", "err", err)
		}
		return reply(hdr, qs, dnsmessage.RCodeServerFailure, false)
	}
	return resp, nil
}

func (r *Resolver) record(dev core.Device, pol core.Policy, name string, t dnsmessage.Type, dec filter.Decision) {
	if r.Log == nil {
		return
	}
	r.Log.Seen(dev.ID)
	// 止めたものはいつも残す。通したものはポリシーで残すと決めたときだけ。
	if dec.Action == core.ActionAllow && !pol.LogQueries {
		return
	}
	r.Log.Add(core.QueryLog{
		DeviceID: dev.ID,
		Name:     filter.Normalize(name),
		Type:     typeName(t),
		Action:   dec.Action,
		Reason:   string(dec.Reason),
	})
}

func typeName(t dnsmessage.Type) string {
	s := t.String()
	if len(s) > 4 && s[:4] == "Type" {
		return s[4:]
	}
	return s
}

func hasEDNS(p *dnsmessage.Parser) bool {
	if err := p.SkipAllAnswers(); err != nil {
		return false
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return false
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return false
		}
		if h.Type == dnsmessage.TypeOPT {
			return true
		}
		if err := p.SkipAdditional(); err != nil {
			return false
		}
	}
}

// reply は答えの無い返事を作る。blocked なら EDNS の拡張エラー「Blocked」を付ける。
func reply(req dnsmessage.Header, qs []dnsmessage.Question, rcode dnsmessage.RCode, blocked bool) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 req.ID,
		Response:           true,
		OpCode:             req.OpCode,
		RecursionDesired:   req.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if len(qs) == 1 {
		if err := b.Question(qs[0]); err != nil {
			return nil, err
		}
	}
	if blocked {
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		var rh dnsmessage.ResourceHeader
		if err := rh.SetEDNS0(1232, dnsmessage.RCodeSuccess, false); err != nil {
			return nil, err
		}
		ede := []byte{0, edeBlocked} // INFO-CODE だけ、EXTRA-TEXT なし
		if err := b.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 15, Data: ede}}}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}
