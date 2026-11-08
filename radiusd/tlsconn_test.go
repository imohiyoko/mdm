package radiusd

import (
	"context"
	"errors"
	"testing"
	"time"
)

// 期限切れで片付けられた（conn を閉じた）セッションへの入力は、panic せずに errClosed になる。
func TestStepAfterSessionClosed(t *testing.T) {
	s := &Server{}
	ss := &session{started: true, conn: newPipeConn(), done: make(chan error, 1)}
	ss.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := s.step(ctx, ss, []byte{0x16}); !errors.Is(err, errClosed) {
		t.Fatalf("step = %v, want errClosed", err)
	}
}

// 閉じた pipeConn の Read は待たずに errClosed を返す。
func TestPipeConnReadAfterClose(t *testing.T) {
	c := newPipeConn()
	_ = c.Close()
	_ = c.Close() // 二度目も panic しない
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, errClosed) {
		t.Fatalf("Read = %v, want errClosed", err)
	}
}
