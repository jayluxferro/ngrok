package util

import (
	"testing"
	"time"
)

func TestBroadcastDoesNotBlockOnSlowListener(t *testing.T) {
	b := NewBroadcast()
	slow := b.Reg()
	fast := b.Reg()
	defer b.UnReg(slow)
	defer b.UnReg(fast)

	// Fill slow listener buffer and ensure broadcaster still progresses.
	for i := 0; i < listenerBufferSize+10; i++ {
		b.In() <- i
	}

	select {
	case <-fast:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected fast listener to receive updates without blocking")
	}
}
