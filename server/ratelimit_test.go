package server

import (
	"testing"
	"time"
)

func TestIPRateLimiter(t *testing.T) {
	lim := newIPRateLimiter(2, 20*time.Millisecond)
	if !lim.allow("1.2.3.4") {
		t.Fatalf("first request should pass")
	}
	if !lim.allow("1.2.3.4") {
		t.Fatalf("second request should pass")
	}
	if lim.allow("1.2.3.4") {
		t.Fatalf("third request should be rate-limited")
	}

	time.Sleep(25 * time.Millisecond)
	if !lim.allow("1.2.3.4") {
		t.Fatalf("request should pass after window reset")
	}
}

func TestIPConnLimiter(t *testing.T) {
	lim := newIPConnLimiter(1)
	if !lim.acquire("8.8.8.8") {
		t.Fatalf("expected initial acquire to pass")
	}
	if lim.acquire("8.8.8.8") {
		t.Fatalf("expected second acquire to fail")
	}
	lim.release("8.8.8.8")
	if !lim.acquire("8.8.8.8") {
		t.Fatalf("expected acquire to pass after release")
	}
}
