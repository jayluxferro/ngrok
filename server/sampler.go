package server

import (
	"sync"
	"time"
)

type logSampler struct {
	mu      sync.Mutex
	entries map[string]sampleEntry
	window  time.Duration
}

type sampleEntry struct {
	start time.Time
	count int
}

func newLogSampler(window time.Duration) *logSampler {
	return &logSampler{
		entries: make(map[string]sampleEntry),
		window:  window,
	}
}

// allow first 3 messages per window and then every 50th.
//
// A nil sampler allows everything, the same way a nil ipRateLimiter or
// ipConnLimiter does (ratelimit.go): warnSampler is only built in Main(), and
// the rejection paths that consult it must keep working -- and keep saying what
// they refused -- in a test binary that never ran Main().
func (s *logSampler) allow(key string) bool {
	if s == nil {
		return true
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[key]
	if e.start.IsZero() || now.Sub(e.start) > s.window {
		e = sampleEntry{start: now, count: 0}
	}
	e.count++
	s.entries[key] = e
	if e.count <= 3 {
		return true
	}
	return e.count%50 == 0
}
