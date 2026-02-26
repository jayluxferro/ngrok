package server

import (
	"net"
	"sync"
	"time"
)

type ipRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int
	limit   int
	window  time.Duration
	resetAt time.Time
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{
		counts:  make(map[string]int),
		limit:   limit,
		window:  window,
		resetAt: time.Now().Add(window),
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.After(l.resetAt) {
		l.counts = make(map[string]int)
		l.resetAt = now.Add(l.window)
	}

	l.counts[ip]++
	return l.counts[ip] <= l.limit
}

type ipConnLimiter struct {
	mu      sync.Mutex
	limit   int
	current map[string]int
}

func newIPConnLimiter(limit int) *ipConnLimiter {
	return &ipConnLimiter{
		limit:   limit,
		current: make(map[string]int),
	}
}

func (l *ipConnLimiter) acquire(ip string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current[ip] >= l.limit {
		return false
	}
	l.current[ip]++
	return true
}

func (l *ipConnLimiter) release(ip string) {
	if l == nil || l.limit <= 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current[ip] <= 1 {
		delete(l.current, ip)
		return
	}
	l.current[ip]--
}

func remoteIP(addr net.Addr) string {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return ""
	}
	return tcp.IP.String()
}
