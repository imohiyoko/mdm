package resolver

import (
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/imohiyoko/mdm/core"
)

// AppleProfile は iPhone・iPad・Mac に通信フィルターを設定する構成プロファイル（.mobileconfig）を作る。
// 端末で開くと「設定」からインストールできる。監視モードの端末では、本人が外せない（ProhibitDisablement）。
func AppleProfile(dohURL, token, displayName string) []byte {
	sum := sha256.Sum256([]byte("mdm-dns-profile:" + strings.ToLower(token)))
	outer, inner := uuidFrom(sum[:16]), uuidFrom(sum[16:])
	esc := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>%s</string>
			</dict>
			<key>ProhibitDisablement</key>
			<true/>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadIdentifier</key>
			<string>mdm.dns.%s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>mdm.profile.%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, esc(dohURL), esc(displayName), inner, inner, esc(displayName), outer, outer))
}

func uuidFrom(b []byte) string {
	u := make([]byte, 16)
	copy(u, b)
	u[6] = u[6]&0x0f | 0x80 // 版 8（独自の作り方）
	u[8] = u[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]))
}

// PublicHandler は端末から届く入り口（DoH と、設定のプロファイル）。
type PublicHandler struct {
	Resolver   *Resolver
	DoHBaseURL string // "https://dns.example.com"
}

func (h *PublicHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle(dohPrefix, &DoHHandler{Resolver: h.Resolver})
	mux.HandleFunc("GET /setup/apple/{file}", h.appleProfile)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	return mux
}

func (h *PublicHandler) appleProfile(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutSuffix(r.PathValue("file"), ".mobileconfig")
	if !ok {
		http.NotFound(w, r)
		return
	}
	dev, err := h.Resolver.Engine.Device(r.Context(), token)
	if errors.Is(err, core.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	body := AppleProfile(h.DoHBaseURL+dohPrefix+strings.ToLower(token), token, "通信フィルター（"+dev.Name+"）")
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="filter.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}
