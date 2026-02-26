package msg

import (
	"encoding/binary"
	"fmt"
	"io"
	"ngrok/conn"
)

var maxMessageSize int64 = 4 * 1024 * 1024 // 4 MiB

func SetMaxMessageSize(size int64) {
	if size > 0 {
		maxMessageSize = size
	}
}

func readMsgShared(c conn.Conn) (buffer []byte, err error) {
	c.Debug("Waiting to read message")

	var sz int64
	err = binary.Read(c, binary.LittleEndian, &sz)
	if err != nil {
		return
	}
	c.Debug("Reading message with length: %d", sz)

	if sz <= 0 {
		return nil, fmt.Errorf("invalid message length: %d", sz)
	}
	if sz > maxMessageSize {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", sz, maxMessageSize)
	}

	buffer = make([]byte, sz)
	n, err := io.ReadFull(c, buffer)
	c.Debug("Read message %s", buffer)

	if err != nil {
		return
	}

	if int64(n) != sz {
		err = fmt.Errorf("expected to read %d bytes, but only read %d", sz, n)
		return
	}

	return
}

func ReadMsg(c conn.Conn) (msg Message, err error) {
	buffer, err := readMsgShared(c)
	if err != nil {
		return
	}

	return Unpack(buffer)
}

func ReadMsgInto(c conn.Conn, msg Message) (err error) {
	buffer, err := readMsgShared(c)
	if err != nil {
		return
	}
	return UnpackInto(buffer, msg)
}

func WriteMsg(c conn.Conn, msg interface{}) (err error) {
	buffer, err := Pack(msg)
	if err != nil {
		return
	}

	c.Debug("Writing message: %s", string(buffer))
	err = binary.Write(c, binary.LittleEndian, int64(len(buffer)))

	if err != nil {
		return
	}

	if _, err = c.Write(buffer); err != nil {
		return
	}

	return nil
}
