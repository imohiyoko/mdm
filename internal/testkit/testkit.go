// Package testkit はテストの道具。
package testkit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/storage/sqlite"
)

// Clock は進めるまで止まっている時計。
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock は t で止まった時計。
func NewClock(t time.Time) *Clock { return &Clock{t: t.UTC()} }

// Now は今の時刻。
func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// Advance は進める。
func (c *Clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// Set は合わせる。
func (c *Clock) Set(t time.Time) { c.mu.Lock(); c.t = t.UTC(); c.mu.Unlock() }

// Store はメモリの SQLite。テストの終わりに閉じる。
func Store(t testing.TB) core.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
