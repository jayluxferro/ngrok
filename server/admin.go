package server

import (
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"sync/atomic"
)

var (
	authRejectCount  uint64
	rateDropCount    uint64
	publicConnCount  int64
	publicConnPeak   int64
	controlConnCount int64
)

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

func startAdminServer(addr string, enablePprof bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		payload := map[string]interface{}{
			"public_connections":      atomic.LoadInt64(&publicConnCount),
			"public_connections_peak": atomic.LoadInt64(&publicConnPeak),
			"control_connections":     atomic.LoadInt64(&controlConnCount),
			"auth_reject_count":       atomic.LoadUint64(&authRejectCount),
			"rate_drop_count":         atomic.LoadUint64(&rateDropCount),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	})

	if enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		_ = srv.ListenAndServe()
	}()
	return srv
}
