package util

import "testing"

func BenchmarkBroadcastFanout(b *testing.B) {
	br := NewBroadcast()
	l1 := br.Reg()
	l2 := br.Reg()
	l3 := br.Reg()
	defer br.UnReg(l1)
	defer br.UnReg(l2)
	defer br.UnReg(l3)

	go func() {
		for range l1 {
		}
	}()
	go func() {
		for range l2 {
		}
	}()
	go func() {
		for range l3 {
		}
	}()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		br.In() <- i
	}
}
