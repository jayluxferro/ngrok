// interactive web user interface
package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/gorilla/websocket"
	"net/http"
	"ngrok/client/assets"
	"ngrok/client/mvc"
	"ngrok/log"
	"ngrok/proto"
	"ngrok/util"
	"path"
	"strings"
	"time"
)

type WebView struct {
	log.Logger

	ctl mvc.Controller

	// messages sent over this broadcast are sent to all websocket connections
	wsMessages *util.Broadcast
	server     *http.Server
	mux        *http.ServeMux
	auth       *WebAuth
}

type WebAuth struct {
	BasicUser  string
	BasicPass  string
	Token      string
	RequireAny bool
}

func NewWebView(ctl mvc.Controller, addr string, auth *WebAuth) *WebView {
	wv := &WebView{
		Logger:     log.NewPrefixLogger("view", "web"),
		wsMessages: util.NewBroadcast(),
		ctl:        ctl,
		mux:        http.NewServeMux(),
		server:     &http.Server{Addr: addr},
		auth:       auth,
	}
	wv.server.Handler = wv.mux

	// for now, always redirect to the http view
	wv.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !wv.authorized(w, r) {
			return
		}
		http.Redirect(w, r, "/http/in", 302)
	})

	// handle web socket connections
	wv.mux.HandleFunc("/_ws", func(w http.ResponseWriter, r *http.Request) {
		if !wv.authorized(w, r) {
			return
		}
		conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)

		if err != nil {
			http.Error(w, "Failed websocket upgrade", 400)
			wv.Warn("Failed websocket upgrade: %v", err)
			return
		}
		defer conn.Close()

		msgs := wv.wsMessages.Reg()
		defer wv.wsMessages.UnReg(msgs)
		for m := range msgs {
			err := conn.WriteMessage(websocket.TextMessage, m.([]byte))
			if err != nil {
				// connection is closed
				break
			}
		}
	})

	// serve static assets
	wv.mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		if !wv.authorized(w, r) {
			return
		}
		buf, err := assets.Asset(path.Join("assets", "client", r.URL.Path[1:]))
		if err != nil {
			wv.Warn("Error serving static file: %s", err.Error())
			http.NotFound(w, r)
			return
		}
		w.Write(buf)
	})

	wv.Info("Serving web interface on %s", addr)
	wv.ctl.Go(func() {
		if err := wv.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			wv.Error("Web interface failed: %v", err)
		}
	})
	return wv
}

func (wv *WebView) NewHttpView(proto *proto.Http) *WebHttpView {
	return newWebHttpView(wv.ctl, wv, proto)
}

func (wv *WebView) Shutdown() {
	if wv.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = wv.server.Shutdown(ctx)
	}
}

func (wv *WebView) authorized(w http.ResponseWriter, r *http.Request) bool {
	if wv.auth == nil || !wv.auth.RequireAny {
		return true
	}

	if wv.auth.Token != "" {
		token := r.Header.Get("X-Ngrok-Inspect-Token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(wv.auth.Token)) == 1 {
			return true
		}
	}

	if wv.auth.BasicUser != "" || wv.auth.BasicPass != "" {
		u, p, ok := r.BasicAuth()
		if ok &&
			subtle.ConstantTimeCompare([]byte(u), []byte(wv.auth.BasicUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(wv.auth.BasicPass)) == 1 {
			return true
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="ngrok-inspect"`)
	}

	if strings.ToUpper(r.Method) == "OPTIONS" {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return false
}
