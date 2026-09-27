package msg

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type testConn struct {
	net.Conn
}

func (c *testConn) AddLogPrefix(string)          {}
func (c *testConn) ClearLogPrefixes()            {}
func (c *testConn) Debug(string, ...interface{}) {}
func (c *testConn) Info(string, ...interface{})  {}
func (c *testConn) Warn(string, ...interface{}) error {
	return nil
}
func (c *testConn) Error(string, ...interface{}) error {
	return nil
}
func (c *testConn) Id() string       { return "test" }
func (c *testConn) SetType(string)   {}
func (c *testConn) CloseRead() error { return nil }

func TestReadMsgRejectsLargeFrame(t *testing.T) {
	old := maxMessageSize
	SetMaxMessageSize(8)
	defer SetMaxMessageSize(old)

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_ = binary.Write(client, binary.LittleEndian, int64(64))
		_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_ = client.Close()
	}()

	_, err := ReadMsg(&testConn{Conn: server})
	if err == nil {
		t.Fatalf("expected oversized frame to fail")
	}
}
