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
	mux := http.NewServeMux()
	adminLimiter := newIPRateLimiter(rate, time.Minute)

	secure := func(allowMethods string, requireAuth bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")

			if allowMethods != "" && !strings.Contains(allowMethods, r.Method) {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !adminLimiter.allow(remoteIPFromReq(r)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			if requireAuth && !authorizedAdmin(w, r, auth) {
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("/", secure(http.MethodGet, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(adminDashboardHTML))
	}))

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

		ch := observe.events.subscribe()
		defer observe.events.unsubscribe(ch)

		for {
			select {
			case <-r.Context().Done():
				return
			case payload, ok := <-ch:
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

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", secure(http.MethodGet, true, pprof.Index))
		mux.HandleFunc("/debug/pprof/cmdline", secure(http.MethodGet, true, pprof.Cmdline))
		mux.HandleFunc("/debug/pprof/profile", secure(http.MethodGet, true, pprof.Profile))
		mux.HandleFunc("/debug/pprof/symbol", secure(http.MethodGet, true, pprof.Symbol))
		mux.HandleFunc("/debug/pprof/trace", secure(http.MethodGet, true, pprof.Trace))
	}

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		_ = srv.ListenAndServe()
	}()
	return srv
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

const loginHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Admin Login</title>
<style>body{font:14px/1.4 ui-sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;padding-top:60px}.box{background:#111827;border:1px solid #334155;padding:16px;border-radius:8px}input{display:block;width:260px;margin:8px 0;padding:8px}</style></head>
<body><form class="box" method="post" action="/login"><h3>ngrokd admin login</h3><input name="username" placeholder="username"/><input type="password" name="password" placeholder="password"/><button type="submit">Sign in</button></form></body></html>`

const adminDashboardHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>ngrokd admin</title>
<style>
body{font:14px/1.4 ui-monospace,Menlo,monospace;background:#0f172a;color:#e2e8f0;margin:0;padding:20px}
h1{margin:0 0 12px}.card{border:1px solid #334155;padding:10px;margin:10px 0;border-radius:8px;background:#111827}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #334155;padding:6px;text-align:left}
#events{max-height:260px;overflow:auto;white-space:pre}
</style></head><body>
<h1>ngrokd observability <a href="/logout" style="color:#93c5fd">logout</a></h1>
<div class="card">
  <label>Window:
    <select id="window"><option value="60">1m</option><option value="300" selected>5m</option><option value="900">15m</option></select>
  </label>
  <label>Refresh:
    <select id="refresh"><option value="2000" selected>2s</option><option value="5000">5s</option><option value="10000">10s</option></select>
  </label>
</div>
<div class="card"><pre id="metrics"></pre></div>
<div class="card"><pre id="reco"></pre></div>
<div class="card"><table id="tunnels"><thead><tr><th>URL</th><th>Proto</th><th>Active</th><th>Total</th><th>Bytes In</th><th>Bytes Out</th></tr></thead><tbody></tbody></table></div>
<div class="card"><div>Events</div><div id="events"></div></div>
<script>
async function refresh(){
  const w=document.getElementById('window').value;
  const m=await fetch('/metrics?window='+w).then(r=>r.json()); document.getElementById('metrics').textContent=JSON.stringify(m,null,2);
  const rec=await fetch('/recommendations?window='+w).then(r=>r.json()); document.getElementById('reco').textContent=JSON.stringify(rec,null,2);
  const t=await fetch('/tunnels').then(r=>r.json()); const tb=document.querySelector('#tunnels tbody'); tb.innerHTML='';
  (t.tunnels||[]).forEach(x=>{const tr=document.createElement('tr'); tr.innerHTML='<td>'+x.url+'</td><td>'+x.protocol+'</td><td>'+x.active_connections+'</td><td>'+x.total_connections+'</td><td>'+x.bytes_in+'</td><td>'+x.bytes_out+'</td>'; tb.appendChild(tr);});
}
let timer=null; function setTimer(){ if(timer) clearInterval(timer); timer=setInterval(refresh, parseInt(document.getElementById('refresh').value)); }
document.getElementById('refresh').addEventListener('change', setTimer);
document.getElementById('window').addEventListener('change', refresh);
refresh(); setTimer();
const ev=document.getElementById('events'); const es=new EventSource('/events'); es.onmessage=(e)=>{ev.textContent=e.data+'\n'+ev.textContent; if(ev.textContent.length>20000){ev.textContent=ev.textContent.slice(0,20000);} };
</script></body></html>`

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
