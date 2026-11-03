package resolver

import (
	"context"
	"errors"
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
	var errs []error
	for id, at := range seen {
		if err := l.Store.TouchDevice(ctx, id, at); err != nil {
			errs = append(errs, err)
			break // 保存先が落ちているなら、残りも失敗する
		}
	}
	if err := l.Store.AppendQueryLogs(ctx, buf); err != nil {
		errs = append(errs, err)
		l.requeue(buf)
	}
	return errors.Join(errs...)
}

// requeue は書けなかった記録を先頭に戻す。上限を超える分は、新しい記録を残して古いものを捨てる。
func (l *QueryLogger) requeue(buf []core.QueryLog) {
	l.mu.Lock()
	defer l.mu.Unlock()
	merged := append(buf, l.buf...)
	if over := len(merged) - maxBuffered; over > 0 {
		merged = merged[over:]
		l.dropped += over
	}
	l.buf = merged
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
