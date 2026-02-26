package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync/atomic"
	"time"
)

var (
	authRejectCount  uint64
	rateDropCount    uint64
	publicConnCount  int64
	publicConnPeak   int64
	controlConnCount int64
)

type adminAuth struct {
	User     string
	Pass     string
	Token    string
	Required bool
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
	return a
}

func incPublicConns() {
	n := atomic.AddInt64(&publicConnCount, 1)
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

	secure := func(allowMethods string, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Cache-Control", "no-store")

			if allowMethods != "" && !strings.Contains(allowMethods, r.Method) {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !adminLimiter.allow(remoteIPFromReq(r)) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			if !authorizedAdmin(w, r, auth) {
				return
			}
			h(w, r)
		}
	}

	mux.HandleFunc("/", secure(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(adminDashboardHTML))
	}))

	mux.HandleFunc("/healthz", secure(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}))

	mux.HandleFunc("/metrics", secure(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]interface{}{
			"public_connections":      atomic.LoadInt64(&publicConnCount),
			"public_connections_peak": atomic.LoadInt64(&publicConnPeak),
			"control_connections":     atomic.LoadInt64(&controlConnCount),
			"auth_reject_count":       atomic.LoadUint64(&authRejectCount),
			"rate_drop_count":         atomic.LoadUint64(&rateDropCount),
			"uptime_seconds":          observe.uptimeSeconds(),
			"tunnels_active":          len(observe.snapshots()),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))

	mux.HandleFunc("/tunnels", secure(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"tunnels": observe.snapshots()})
	}))

	mux.HandleFunc("/events", secure(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
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
		mux.HandleFunc("/debug/pprof/", secure(http.MethodGet, pprof.Index))
		mux.HandleFunc("/debug/pprof/cmdline", secure(http.MethodGet, pprof.Cmdline))
		mux.HandleFunc("/debug/pprof/profile", secure(http.MethodGet, pprof.Profile))
		mux.HandleFunc("/debug/pprof/symbol", secure(http.MethodGet, pprof.Symbol))
		mux.HandleFunc("/debug/pprof/trace", secure(http.MethodGet, pprof.Trace))
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
		w.Header().Set("WWW-Authenticate", `Basic realm="ngrok-admin"`)
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

func remoteIPFromReq(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > -1 {
		host = host[:i]
	}
	return host
}

const adminDashboardHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>ngrokd admin</title>
<style>
body{font:14px/1.4 ui-monospace,Menlo,monospace;background:#0f172a;color:#e2e8f0;margin:0;padding:20px}
h1{margin:0 0 12px}.card{border:1px solid #334155;padding:10px;margin:10px 0;border-radius:8px;background:#111827}
table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #334155;padding:6px;text-align:left}
#events{max-height:260px;overflow:auto;white-space:pre}
</style></head><body>
<h1>ngrokd observability</h1>
<div class="card"><pre id="metrics"></pre></div>
<div class="card"><table id="tunnels"><thead><tr><th>URL</th><th>Proto</th><th>Active</th><th>Total</th><th>Bytes In</th><th>Bytes Out</th></tr></thead><tbody></tbody></table></div>
<div class="card"><div>Events</div><div id="events"></div></div>
<script>
async function refresh(){
  const m=await fetch('/metrics').then(r=>r.json()); document.getElementById('metrics').textContent=JSON.stringify(m,null,2);
  const t=await fetch('/tunnels').then(r=>r.json()); const tb=document.querySelector('#tunnels tbody'); tb.innerHTML='';
  (t.tunnels||[]).forEach(x=>{const tr=document.createElement('tr'); tr.innerHTML='<td>'+x.url+'</td><td>'+x.protocol+'</td><td>'+x.active_connections+'</td><td>'+x.total_connections+'</td><td>'+x.bytes_in+'</td><td>'+x.bytes_out+'</td>'; tb.appendChild(tr);});
}
refresh(); setInterval(refresh,2000);
const ev=document.getElementById('events'); const es=new EventSource('/events'); es.onmessage=(e)=>{ev.textContent=e.data+'\n'+ev.textContent; if(ev.textContent.length>20000){ev.textContent=ev.textContent.slice(0,20000);} };
</script></body></html>`
