package android

import (
	"errors"
	"html/template"
	"net/http"
)

// CallbackPath は enterprise を作ったあとに Google の画面から戻ってくる道。公開の入り口に置く。
const CallbackPath = "/android/signup/callback"

var page = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Android の管理</title>
<body style="font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.7">
<h1 style="font-size:1.4rem">{{.Title}}</h1><p>{{.Body}}</p></body></html>`))

// CallbackHandler は登録の画面から戻ってきたところ。enterprise を作って組織に結びつける。
func (s *Service) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		q := r.URL.Query()
		e, err := s.FinishSignup(r.Context(), q.Get("state"), q.Get("enterpriseToken"))
		if err != nil {
			status, body := http.StatusBadGateway, "Google の側で enterprise を作れませんでした。しばらくしてから、管理の画面でもう一度始めてください。"
			if errors.Is(err, ErrBadSignup) {
				status, body = http.StatusBadRequest, "申し込みが見つからないか、期限（1 時間）が切れています。管理の画面でもう一度始めてください。"
			}
			s.log().Warn("android signup callback", "err", err)
			w.WriteHeader(status)
			_ = page.Execute(w, map[string]string{"Title": "Android の管理を始められませんでした", "Body": body})
			return
		}
		s.log().Info("android enterprise created", "org", e.OrgID, "enterprise", e.Name)
		_ = page.Execute(w, map[string]string{"Title": "Android の管理を始めました", "Body": "この画面は閉じてかまいません。管理の画面から端末を登録できます。"})
	})
}
