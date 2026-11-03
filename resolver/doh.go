package resolver

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
)

// DoHHandler は端末からの DNS over HTTPS（RFC 8484）を受ける。
// 端末は URL のパスの秘密で見分ける：/dns-query/{token}。
// Windows・iPhone・Mac は DoH の URL をそのまま設定できる。
type DoHHandler struct {
	Resolver *Resolver
}

const dohPrefix = "/dns-query/"

func (h *DoHHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, dohPrefix)
	if !ok || token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	var msg []byte
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		b, err := base64.RawURLEncoding.DecodeString(q)
		if err != nil || len(b) == 0 {
			http.Error(w, "bad dns parameter", http.StatusBadRequest)
			return
		}
		msg = b
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != dnsMessageType {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil || len(b) == 0 || len(b) > 65535 {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		msg = b
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := h.Resolver.HandleDoH(r.Context(), token, msg)
	switch {
	case errors.Is(err, ErrUnknownDevice):
		// 秘密が違う。端末があるかどうかは教えない。
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", dnsMessageType)
	w.Header().Set("Cache-Control", "no-store") // 端末ごとに答えが違う
	_, _ = w.Write(resp)
}
