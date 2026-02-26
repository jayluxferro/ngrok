package msg

import (
	"net"
	"testing"
)

func BenchmarkPackUnpackAuth(b *testing.B) {
	m := &Auth{
		Version:   "2",
		MmVersion: "1.0",
		User:      "token",
		OS:        "linux",
		Arch:      "amd64",
		ClientId:  "cid",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, err := Pack(m)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Unpack(buf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadWriteMsg(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < b.N; i++ {
			if err := WriteMsg(&testConn{Conn: client}, &Ping{}); err != nil {
				return
			}
		}
	}()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ReadMsg(&testConn{Conn: server}); err != nil {
			b.Fatal(err)
		}
	}
	<-done
}
