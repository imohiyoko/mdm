package radiusd

import (
	"errors"
	"net"
	"sync"
	"time"
)

// pipeConn は EAP-TLS で運ぶ TLS のデータを crypto/tls に渡す net.Conn。
// TLS の処理は別のゴルーチンで動き、入力を待つ（Read で読むものが無い）たびに waiting に知らせる。
type pipeConn struct {
	mu      sync.Mutex
	in      []byte
	out     []byte
	closed  bool
	feed    chan []byte
	waiting chan struct{}
}

func newPipeConn() *pipeConn {
	return &pipeConn{feed: make(chan []byte), waiting: make(chan struct{}, 1)}
}

var errClosed = errors.New("eap-tls: closed")

func (c *pipeConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.in) == 0 {
		c.mu.Unlock()
		select {
		case c.waiting <- struct{}{}:
		default:
		}
		data, ok := <-c.feed
		if !ok {
			return 0, errClosed
		}
		c.mu.Lock()
		c.in = append(c.in, data...)
	}
	n := copy(b, c.in)
	c.in = c.in[n:]
	c.mu.Unlock()
	return n, nil
}

func (c *pipeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errClosed
	}
	c.out = append(c.out, b...)
	return len(b), nil
}

// takeOut は TLS が書いたものを取り出す。
func (c *pipeConn) takeOut() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.out
	c.out = nil
	return out
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.feed)
	}
	return nil
}

type eapAddr struct{}

func (eapAddr) Network() string { return "eap" }
func (eapAddr) String() string  { return "eap" }

func (c *pipeConn) LocalAddr() net.Addr              { return eapAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr             { return eapAddr{} }
func (c *pipeConn) SetDeadline(time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(time.Time) error { return nil }
