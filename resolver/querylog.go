package resolver

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/imohiyoko/mdm/core"
)

// QueryLogger は問い合わせの記録と端末の最後の通信の時刻を、まとめて保存先に書く。
// 問い合わせのたびに書くと DNS が遅くなるため。溢れたら捨てる（DNS を止めない）。
type QueryLogger struct {
	Store  core.Store
	Clock  core.Clock
	Logger *slog.Logger

	mu      sync.Mutex
	buf     []core.QueryLog
	seen    map[string]time.Time
	dropped int
}

const maxBuffered = 10000

// Add は記録を足す。At は今の時刻にする。
func (l *QueryLogger) Add(q core.QueryLog) {
	q.At = l.Clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buf) >= maxBuffered {
		l.dropped++
		return
	}
	l.buf = append(l.buf, q)
}

// Seen は端末が通信したことを覚える。
func (l *QueryLogger) Seen(deviceID string) {
	now := l.Clock.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[string]time.Time{}
	}
	l.seen[deviceID] = now
}

// Flush はたまった分を書く。
func (l *QueryLogger) Flush(ctx context.Context) error {
	l.mu.Lock()
	buf, seen, dropped := l.buf, l.seen, l.dropped
	l.buf, l.seen, l.dropped = nil, nil, 0
	l.mu.Unlock()
	if dropped > 0 && l.Logger != nil {
		l.Logger.Warn("query log dropped", "count", dropped)
	}
	for id, at := range seen {
		if err := l.Store.TouchDevice(ctx, id, at); err != nil {
			return err
		}
	}
	return l.Store.AppendQueryLogs(ctx, buf)
}

// Run は ctx が終わるまで interval ごとに書く。終わるときにも書く。
func (l *QueryLogger) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := l.Flush(context.WithoutCancel(ctx)); err != nil && l.Logger != nil {
				l.Logger.Error("query log flush", "err", err)
			}
			return
		case <-t.C:
			if err := l.Flush(ctx); err != nil && l.Logger != nil {
				l.Logger.Error("query log flush", "err", err)
			}
		}
	}
}
