package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ngrok/server/assets"
	"ngrok/util"
)

var (
	authRejectCount     uint64
	rateDropCount       uint64
	publicConnCount     int64
	publicConnOpenTotal uint64
	publicConnPeak      int64
	controlConnCount    int64
)

const adminSessionCookie = "ngrok_admin_session"

// adminContentSecurityPolicy is the CSP every admin route answers with. The
// dashboard is a static SPA (SPEC-CLUSTER19 §6): every script it loads is an
// external file under /static/, so script-src no longer carries
// 'unsafe-inline' -- the inline dashboard HTML was the only reason the
// allowance existed, and dropping it means an injected inline <script> does
// not run. style-src keeps 'unsafe-inline' because the SPA uses a few inline
// style attributes; a future cluster can tighten that. Pinned verbatim by a
// test: this header is the review gate, and a header that drifts silently is
// a gate that no longer gates.
const adminContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"

// apiRateFor derives the /api/* rate budget from -adminRate (SPEC-CLUSTER19
// §2). The workbench validates on keystroke-idle plus an explicit button, so
// a fast editor pasting sections can outrun the pages budget (default
// 120/min) and lock themselves out of their own dashboard mid-edit; the API
// gets its own limiter at five times the pages budget. 0 -- off -- propagates
// exactly when -adminRate 0 unthrottles the whole admin surface: an operator
// who deliberately sets a tight -adminRate gets a proportionally tight API
// budget, never a surprise floor.
func apiRateFor(adminRate int) int {
	if adminRate <= 0 {
		return 0
	}
	return 5 * adminRate
}

type adminAuth struct {
	User         string
	Pass         string
	Token        string
	Required     bool
	SessionToken string
}

func parseAdminAuth(auth, token string) *adminAuth {
	if auth == "" && token == "" {
		return nil
	}
	a := &adminAuth{Token: token, Required: true}
	if auth != "" {
		parts := strings.SplitN(auth, ":", 2)
		if len(parts) == 2 {
			a.User = parts[0]
			a.Pass = parts[1]
		}
	}
	if a.User != "" || a.Pass != "" {
		s, err := util.SecureRandId(24)
		if err == nil {
			a.SessionToken = s
		}
	}
	return a
}

func incPublicConns() {
	n := atomic.AddInt64(&publicConnCount, 1)
	atomic.AddUint64(&publicConnOpenTotal, 1)
	for {
		peak := atomic.LoadInt64(&publicConnPeak)
		if n <= peak || atomic.CompareAndSwapInt64(&publicConnPeak, peak, n) {
			return
		}
	}
}

func decPublicConns() {
	atomic.AddInt64(&publicConnCount, -1)
}

func startAdminServer(addr string, enablePprof bool, auth *adminAuth, rate int) *http.Server {
	mux := adminHandler(enablePprof, auth, rate)
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		_ = srv.ListenAndServe()
	}()
	return srv
}

// adminHandler builds the admin routes. Split from startAdminServer so tests
// can serve the identical handler stack from httptest.NewServer instead of a
// real listener with a race on its port.
func adminHandler(enablePprof bool, auth *adminAuth, rate int) *http.ServeMux {
	mux := http.NewServeMux()
	adminLimiter := newIPRateLimiter(rate, time.Minute)
	apiLimiter := newIPRateLimiter(apiRateFor(rate), time.Minute)

	// secured is the one wrapper both route families go through: the security
	// headers, the method pin, the limiter and the auth check, in that order.
	// The two families differ only in which limiter answers -- /api/* has its
	// own budget (apiRateFor) so workbench keystrokes cannot exhaust the
	// pages one -- and everything else (headers, auth semantics, the 405 and
	// 429 bodies) is shared, because a difference the wrapper does not carry
	// is a difference half the routes would quietly grow out of.
	secured := func(limiter *ipRateLimiter, allowMethods string, requireAuth bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", adminContentSecurityPolicy)

			if allowMethods != "" && !strings.Contains(allowMethods, r.Method) {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !limiter.allow(remoteIPFromReq(r)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			if requireAuth && !authorizedAdmin(w, r, auth) {
				return
			}
			h(w, r)
		}
	}
	secure := func(allowMethods string, requireAuth bool, h http.HandlerFunc) http.HandlerFunc {
		return secured(adminLimiter, allowMethods, requireAuth, h)
	}
	// secureAPI is the API sibling: same wrapper, the api limiter, and auth
	// always required -- the workbench reads and validates operator
	// documents, which is not something the unauthenticated public gets to
	// ask about.
	secureAPI := func(allowMethods string, h http.HandlerFunc) http.HandlerFunc {
		return secured(apiLimiter, allowMethods, true, h)
	}

	mux.HandleFunc("/", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		// The SPA's entry document, served from the embedded assets
		// (SPEC-CLUSTER19 §6) -- ngrokd's first import of the package the
		// server-assets make target already packages. The wrapper has already
		// set no-store and the CSP; the entry doc loads its scripts and
		// styles from /static/.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(assets.MustAsset(dashboardIndexAsset))
	}))

	// The SPA's scripts and styles (SPEC-CLUSTER19 §6): exactly the three
	// names below, by fixed lookup -- never a path join. A name is taken from
	// the request path, and the only names that resolve are the three the
	// dashboard ships, so there is no traversal to have: anything else 404s
	// before any filesystem-shaped idea enters the picture.
	mux.HandleFunc("/static/", secureAPI(http.MethodGet, serveDashboardStatic))

	mux.HandleFunc("/login", secure(http.MethodGet+http.MethodPost, false, func(w http.ResponseWriter, r *http.Request) {
		if auth == nil || (auth.User == "" && auth.Pass == "") {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(loginHTML))
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		u := r.Form.Get("username")
		p := r.Form.Get("password")
		if subtle.ConstantTimeCompare([]byte(u), []byte(auth.User)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(auth.Pass)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     adminSessionCookie,
			Value:    auth.SessionToken,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   3600,
		})
		http.Redirect(w, r, "/", http.StatusFound)
	}))

	mux.HandleFunc("/logout", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: adminSessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/login", http.StatusFound)
	}))

	mux.HandleFunc("/healthz", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}))

	mux.HandleFunc("/metrics", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		window := parseInt64Query(r, "window", 60)
		series := observe.historyWindow(window)
		rates := rateSummary(series)

		payload := map[string]interface{}{
			"public_connections":      atomic.LoadInt64(&publicConnCount),
			"public_connections_peak": atomic.LoadInt64(&publicConnPeak),
			"control_connections":     atomic.LoadInt64(&controlConnCount),
			"public_conn_open_total":  atomic.LoadUint64(&publicConnOpenTotal),
			"auth_reject_count":       atomic.LoadUint64(&authRejectCount),
			"rate_drop_count":         atomic.LoadUint64(&rateDropCount),
			"uptime_seconds":          observe.uptimeSeconds(),
			"tunnels_active":          len(observe.snapshots()),
			"window_seconds":          window,
			"rates":                   rates,
			// Event-stream health (SPEC-CLUSTER9 §4): how many events the
			// hub has dropped on full subscriber queues (SSE clients and
			// export destinations alike), how many consumers exist right
			// now, and the per-destination loss/backlog rows.
			"event_drop_count":   observe.events.droppedEvents(),
			"event_subscribers":  observe.events.subscriberCount(),
			"event_destinations": exportedDestinationStats(),
		}
		if strings.EqualFold(r.URL.Query().Get("detail"), "full") {
			payload["series"] = series
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))

	mux.HandleFunc("/recommendations", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		window := parseInt64Query(r, "window", 300)
		series := observe.historyWindow(window)
		rates := rateSummary(series)
		peakPublic := int64(0)
		for _, p := range series {
			if p.PublicConnections > peakPublic {
				peakPublic = p.PublicConnections
			}
		}

		recommendedPublicRate := int(rates["public_conn_open_rate_per_sec"]*2 + 1)
		if recommendedPublicRate < 50 {
			recommendedPublicRate = 50
		}
		recommendedConnPerIP := int(float64(peakPublic)*1.5) + 10
		if recommendedConnPerIP < 50 {
			recommendedConnPerIP = 50
		}

		payload := map[string]interface{}{
			"window_seconds": window,
			"observed": map[string]interface{}{
				"peak_public_connections": peakPublic,
				"rates":                   rates,
			},
			"recommended": map[string]interface{}{
				"publicRate":   recommendedPublicRate,
				"maxConnPerIP": recommendedConnPerIP,
				"authRate":     maxInt(opts.authRate, int(rates["auth_reject_rate_per_sec"]*120+30)),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))

	mux.HandleFunc("/metrics/prometheus", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s := observe.snapshots()
		_, _ = fmt.Fprintf(w, "# HELP ngrokd_public_connections current public connections\n")
		_, _ = fmt.Fprintf(w, "# TYPE ngrokd_public_connections gauge\nngrokd_public_connections %d\n", atomic.LoadInt64(&publicConnCount))
		_, _ = fmt.Fprintf(w, "# HELP ngrokd_control_connections current control connections\n")
		_, _ = fmt.Fprintf(w, "# TYPE ngrokd_control_connections gauge\nngrokd_control_connections %d\n", atomic.LoadInt64(&controlConnCount))
		_, _ = fmt.Fprintf(w, "# HELP ngrokd_auth_reject_count total auth rejects\n")
		_, _ = fmt.Fprintf(w, "# TYPE ngrokd_auth_reject_count counter\nngrokd_auth_reject_count %d\n", atomic.LoadUint64(&authRejectCount))
		_, _ = fmt.Fprintf(w, "# HELP ngrokd_rate_drop_count total rate-limit drops\n")
		_, _ = fmt.Fprintf(w, "# TYPE ngrokd_rate_drop_count counter\nngrokd_rate_drop_count %d\n", atomic.LoadUint64(&rateDropCount))
		_, _ = fmt.Fprintf(w, "# HELP ngrokd_event_drop_count events dropped on full subscriber queues\n")
		_, _ = fmt.Fprintf(w, "# TYPE ngrokd_event_drop_count counter\nngrokd_event_drop_count %d\n", observe.events.droppedEvents())
		_, _ = fmt.Fprintf(w, "# HELP ngrokd_tunnel_active_connections active connections by tunnel\n")
		_, _ = fmt.Fprintf(w, "# TYPE ngrokd_tunnel_active_connections gauge\n")
		for _, t := range s {
			_, _ = fmt.Fprintf(w, "ngrokd_tunnel_active_connections{url=%q,protocol=%q} %d\n", t.URL, t.Protocol, t.ActiveConnections)
			_, _ = fmt.Fprintf(w, "ngrokd_tunnel_total_connections{url=%q,protocol=%q} %d\n", t.URL, t.Protocol, t.TotalConnections)
			_, _ = fmt.Fprintf(w, "ngrokd_tunnel_bytes_in{url=%q,protocol=%q} %d\n", t.URL, t.Protocol, t.BytesIn)
			_, _ = fmt.Fprintf(w, "ngrokd_tunnel_bytes_out{url=%q,protocol=%q} %d\n", t.URL, t.Protocol, t.BytesOut)
		}
	}))

	mux.HandleFunc("/tunnels", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"tunnels": observe.snapshots()})
	}))

	mux.HandleFunc("/events", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}

		sub := observe.events.subscribe()
		defer observe.events.unsubscribe(sub)

		for {
			select {
			case <-r.Context().Done():
				return
			case payload, ok := <-sub.ch:
				if !ok {
					return
				}
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(payload)
				_, _ = w.Write([]byte("\n\n"))
				flusher.Flush()
			}
		}
	}))

	// The workbench API (SPEC-CLUSTER19 §1): auth'd, method-pinned, own rate
	// budget, bodies capped at 1 MiB inside the handlers. The handlers live
	// in admin_api.go; every error path answers JSON because the SPA parses
	// JSON.
	mux.HandleFunc("/api/schema", secureAPI(http.MethodGet, handleAPISchema))
	mux.HandleFunc("/api/validate/config", secureAPI(http.MethodPost, handleAPIValidateConfig))
	mux.HandleFunc("/api/validate/policy", secureAPI(http.MethodPost, handleAPIValidatePolicy))
	mux.HandleFunc("/api/render", secureAPI(http.MethodPost, handleAPIRender))

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", secure(http.MethodGet, true, pprof.Index))
		mux.HandleFunc("/debug/pprof/cmdline", secure(http.MethodGet, true, pprof.Cmdline))
		mux.HandleFunc("/debug/pprof/profile", secure(http.MethodGet, true, pprof.Profile))
		mux.HandleFunc("/debug/pprof/symbol", secure(http.MethodGet, true, pprof.Symbol))
		mux.HandleFunc("/debug/pprof/trace", secure(http.MethodGet, true, pprof.Trace))
	}

	return mux
}

func authorizedAdmin(w http.ResponseWriter, r *http.Request, auth *adminAuth) bool {
	if auth == nil || !auth.Required {
		return true
	}
	if c, err := r.Cookie(adminSessionCookie); err == nil && auth.SessionToken != "" {
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(auth.SessionToken)) == 1 {
			return true
		}
	}
	if auth.Token != "" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Ngrok-Admin-Token")), []byte(auth.Token)) == 1 {
			return true
		}
	}
	if auth.User != "" || auth.Pass != "" {
		u, p, ok := r.BasicAuth()
		if ok && subtle.ConstantTimeCompare([]byte(u), []byte(auth.User)) == 1 && subtle.ConstantTimeCompare([]byte(p), []byte(auth.Pass)) == 1 {
			return true
		}

		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "text/html") && r.URL.Path != "/login" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return false
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="ngrok-admin"`)
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func remoteIPFromReq(r *http.Request) string {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

// dashboardIndexAsset is the embedded entry document "/" serves; the names
// below are the go-bindata spellings (assets_debug.go / the release twin).
const dashboardIndexAsset = "assets/server/dashboard/index.html"

// dashboardStaticAssets is the whole /static/ namespace: the three files the
// SPA loads, keyed by the URL name each is requested under. The values are
// the asset-package name and the Content-Type each answers with. The route is
// a lookup in this table and nothing else -- no path join, no directory
// listing, no fallback -- so a request path that is not exactly one of these
// names ("../", a subdirectory, an unknown file) misses and 404s.
var dashboardStaticAssets = map[string]struct {
	asset string
	mime  string
}{
	"index.html": {"assets/server/dashboard/index.html", "text/html"},
	"style.css":  {"assets/server/dashboard/style.css", "text/css"},
	"app.js":     {"assets/server/dashboard/app.js", "text/javascript"},
}

// serveDashboardStatic answers GET /static/<name> from the embedded assets.
// The wrapper has already set the security headers, including no-store: the
// dashboard is three small files and correctness (an operator seeing today's
// SPA, not yesterday's) beats caching them.
func serveDashboardStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	entry, ok := dashboardStaticAssets[name]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", entry.mime)
	_, _ = w.Write(assets.MustAsset(entry.asset))
}

const loginHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title>
<style>body{font:14px/1.4 ui-sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;padding-top:60px}.box{background:#111827;border:1px solid #334155;padding:16px;border-radius:8px}input{display:block;width:260px;margin:8px 0;padding:8px}</style></head>
<body><form class="box" method="post" action="/login"><h3>ngrokd admin login</h3><input name="username" placeholder="username"/><input type="password" name="password" placeholder="password"/><button type="submit">Sign in</button></form></body></html>`

func parseInt64Query(r *http.Request, key string, def int64) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func rateSummary(series []metricsPoint) map[string]float64 {
	out := map[string]float64{
		"public_conn_open_rate_per_sec": 0,
		"rate_drop_rate_per_sec":        0,
		"auth_reject_rate_per_sec":      0,
	}
	if len(series) < 2 {
		return out
	}
	first := series[0]
	last := series[len(series)-1]
	dt := last.At.Sub(first.At).Seconds()
	if dt <= 0 {
		return out
	}
	out["public_conn_open_rate_per_sec"] = float64(last.PublicConnOpened-first.PublicConnOpened) / dt
	out["rate_drop_rate_per_sec"] = float64(last.RateDropCount-first.RateDropCount) / dt
	out["auth_reject_rate_per_sec"] = float64(last.AuthRejectCount-first.AuthRejectCount) / dt
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
