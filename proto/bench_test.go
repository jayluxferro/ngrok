package proto

import (
	"bytes"
	"testing"
)

func BenchmarkExtractBody64KB(b *testing.B) {
	payload := bytes.Repeat([]byte("a"), 64*1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, rc, _, err := extractBody(bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		_ = rc.Close()
	}
}
