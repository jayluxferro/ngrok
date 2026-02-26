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
func (s *logSampler) allow(key string) bool {
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
