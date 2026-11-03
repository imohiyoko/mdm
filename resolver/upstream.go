package resolver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const dnsMessageType = "application/dns-message"

// DoHUpstream は上流に DNS over HTTPS（RFC 8484）で問い合わせる。
type DoHUpstream struct {
	URL    string
	Client *http.Client
}

// Exchange は POST で送る。
func (u *DoHUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsMessageType)
	req.Header.Set("Accept", dnsMessageType)
	c := u.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

// PlainUpstream は上流に暗号化しない DNS で問い合わせる（家の中のルーターなど）。
// UDP で答えが切れていたら TCP で問い直す。
type PlainUpstream struct {
	Addr    string // "192.168.1.1:53"
	Timeout time.Duration
}

func (u *PlainUpstream) timeout() time.Duration {
	if u.Timeout == 0 {
		return 3 * time.Second
	}
	return u.Timeout
}

// Exchange は問い合わせる。
func (u *PlainUpstream) Exchange(ctx context.Context, msg []byte) ([]byte, error) {
	resp, err := u.exchange(ctx, "udp", msg)
	if err != nil {
		return nil, err
	}
	if len(resp) > 2 && resp[2]&0x02 != 0 { // TC
		return u.exchange(ctx, "tcp", msg)
	}
	return resp, nil
}

func (u *PlainUpstream) exchange(ctx context.Context, network string, msg []byte) ([]byte, error) {
	d := net.Dialer{Timeout: u.timeout()}
	conn, err := d.DialContext(ctx, network, u.Addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(u.timeout()))
	if network == "udp" {
		if _, err := conn.Write(msg); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			if n >= 2 && n >= 12 && buf[0] == msg[0] && buf[1] == msg[1] {
				return buf[:n], nil
			}
		}
	}
	if err := WriteFramed(conn, msg); err != nil {
		return nil, err
	}
	return ReadFramed(conn)
}

// WriteFramed は TCP・DoT の形（2 バイトの長さ + 本体）で書く。
func WriteFramed(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("message too long")
	}
	b := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(b, uint16(len(msg)))
	copy(b[2:], msg)
	_, err := w.Write(b)
	return err
}

// ReadFramed は TCP・DoT の形で読む。
func ReadFramed(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
