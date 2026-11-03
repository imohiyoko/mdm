package resolver_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/imohiyoko/mdm/core"
	"github.com/imohiyoko/mdm/internal/testkit"
	"github.com/imohiyoko/mdm/resolver"
)

type flakyStore struct {
	core.Store
	fail bool
}

func (s *flakyStore) AppendQueryLogs(ctx context.Context, logs []core.QueryLog) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.Store.AppendQueryLogs(ctx, logs)
}

func TestFlushRequeuesOnFailure(t *testing.T) {
	ctx := context.Background()
	fs := &flakyStore{Store: testkit.Store(t), fail: true}
	l := &resolver.QueryLogger{Store: fs, Clock: testkit.NewClock(time.Unix(1e9, 0))}
	l.Add(core.QueryLog{DeviceID: "d", Name: "a.example", Action: core.ActionBlock})
	if err := l.Flush(ctx); err == nil {
		t.Fatal("失敗を返すべき")
	}
	l.Add(core.QueryLog{DeviceID: "d", Name: "b.example", Action: core.ActionBlock})
	fs.fail = false
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	logs, _ := fs.ListQueryLogs(ctx, "d", time.Time{}, 10)
	if len(logs) != 2 {
		t.Fatalf("書けなかった記録も残す: %+v", logs)
	}
}
