package msg

// Fuzzing for the JSON envelope wire protocol.
//
// Everything here reads bytes that came off a socket that anyone can open.
// The control connection is the first thing a peer talks to (server/control.go
// reads an Auth message before it knows who the peer is), and the proxy
// connections carry the same framing after it, so the decoder is reachable
// before authentication and has to be safe on garbage.
//
// The invariants:
//
//  1. No panic, for arbitrary bytes, both as a framed wire stream
//     (ReadMsgInto: 8-byte little-endian length, then the payload) and as bare
//     JSON (UnpackInto, which is where the envelope is actually decoded).
//
//  2. Termination inside fzDecodeTimeout. Both sources are in-memory readers,
//     so a decode that needs longer than the timeout is not slow, it is stuck.
//
//  3. Bounded allocation. readMsgShared checks the declared size against
//     maxMessageSize *before* make([]byte, sz), so an 8-byte frame header can
//     never ask the server for an arbitrary amount of memory. The fuzz check is
//     the observable half of that -- an oversized frame is an error -- and
//     TestMsgFrameSizeIsBounded is the accounting half.
//
//  4. A decode that succeeded can be re-encoded and decoded again to the same
//     value. This is the round-trip property the client/server pair depends on:
//     the client packs a struct, the server unpacks it into the same struct, and
//     both sides read the envelope's Type field to decide which struct that is.
//     Any field the packer drops and the unpacker would have looked for is a
//     silent protocol divergence, and DeepEqual is what catches it.
//
// The decoders are a thin layer over encoding/json, so the interesting question
// is not whether json.Unmarshal can be crashed -- it cannot -- but whether this
// package's framing and type dispatch add a way to crash it. That is what
// FuzzMsgDecode and FuzzEnvelopeRoundTrip are aimed at.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fzDecodeTimeout bounds one decode. See invariant 2 above.
const fzDecodeTimeout = 5 * time.Second

// fzConn is the smallest conn.Conn that can be read from: a byte slice, with
// the net.Conn methods the decoder never reaches left to the embedded nil
// interface (which would panic loudly rather than silently returning zeros, if
// msg's read path ever grew a call to one).
type fzConn struct {
	net.Conn
	r io.Reader
}

func (c *fzConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *fzConn) AddLogPrefix(string)          {}
func (c *fzConn) ClearLogPrefixes()            {}
func (c *fzConn) Debug(string, ...interface{}) {}
func (c *fzConn) Info(string, ...interface{})  {}
func (c *fzConn) Warn(string, ...interface{}) error {
	return nil
}
func (c *fzConn) Error(string, ...interface{}) error { return nil }
func (c *fzConn) Id() string                         { return "fuzz" }
func (c *fzConn) SetType(string)                     {}
func (c *fzConn) CloseRead() error                   { return nil }

// fzFrame builds the wire shape readMsgShared expects: the little-endian int64
// length, then the payload.
func fzFrame(sz int64, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint64(buf, uint64(sz))
	copy(buf[8:], payload)
	return buf
}

// fzDecodeOn runs fn on another goroutine and reports whether it finished. See
// invariant 2: the goroutine is abandoned only when the watchdog fires, which
// must never happen, so nothing here needs to unwind it.
func fzDecodeOn(fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(fzDecodeTimeout):
		return false
	}
}

// fzTargets is the decode target matrix: every message type the protocol
// dispatches on, plus the two shapes that are not a typed target at all (a nil
// target, which asks the decoder to guess the type from the envelope, and an
// interface{} target, which is what a caller that does not know the schema
// would pass).
func fzTargets() []struct {
	name string
	make func() interface{}
} {
	targets := []struct {
		name string
		make func() interface{}
	}{
		{"Auth", func() interface{} { return &Auth{} }},
		{"AuthResp", func() interface{} { return &AuthResp{} }},
		{"ReqTunnel", func() interface{} { return &ReqTunnel{} }},
		{"NewTunnel", func() interface{} { return &NewTunnel{} }},
		{"RegMux", func() interface{} { return &RegMux{} }},
		{"RegProxy", func() interface{} { return &RegProxy{} }},
		{"ReqProxy", func() interface{} { return &ReqProxy{} }},
		{"StartProxy", func() interface{} { return &StartProxy{} }},
		{"Ping", func() interface{} { return &Ping{} }},
		{"Pong", func() interface{} { return &Pong{} }},
		{"Envelope", func() interface{} { return &Envelope{} }},
		{"nil-target", func() interface{} { return nil }},
		{"interface-target", func() interface{} { return &struct{ Any interface{} }{} }},
	}
	return targets
}

// fzMessageSeeds are valid frames for every type the protocol dispatches on,
// built by packing the structs themselves so that the corpus cannot drift from
// the schema.
func fzMessageSeeds() [][]byte {
	payloads := []interface{}{
		&Auth{Version: "2", MmVersion: "1.0", User: "token", Password: "pw", OS: "linux", Arch: "amd64", ClientId: "cid", Caps: []string{"proxy-mux"}},
		&AuthResp{Version: "2", MmVersion: "1.0", ClientId: "cid", Caps: []string{"proxy-mux"}},
		&ReqTunnel{ReqId: "1", Protocol: "http", Hostname: "a.example", Subdomain: "sub", HttpAuth: "u:p", RemotePort: 8080, Binding: "internal", Pooling: true, ForwardTo: "https://svc.internal"},
		&NewTunnel{ReqId: "1", Url: "http://a.example", Protocol: "http", Error: ""},
		&RegMux{ClientId: "cid"},
		&RegProxy{ClientId: "cid"},
		&ReqProxy{},
		&StartProxy{Url: "http://a.example", ClientAddr: "1.2.3.4:5678"},
		&Ping{},
		&Pong{},
	}
	var out [][]byte
	for _, p := range payloads {
		buf, err := Pack(p)
		if err != nil {
			panic(fmt.Sprintf("fuzzing: packing the %T seed failed: %v", p, err))
		}
		out = append(out, fzFrame(int64(len(buf)), buf))
	}
	return out
}

// fzJSONSeeds are envelope documents for the same types, for the round-trip
// fuzzer: a mix of the packed form and hand-written ones with fields the struct
// does not have (which json drops) and with the type deliberately wrong.
func fzJSONSeeds() [][]byte {
	var out [][]byte
	for _, framed := range fzMessageSeeds() {
		out = append(out, framed[8:])
	}
	return append(out, [][]byte{
		[]byte(`{"Type":"Auth","Payload":{"Version":"2"}}`),
		[]byte(`{"Type":"Auth","Payload":{"Version":2}}`), // wrong scalar type
		[]byte(`{"Type":"Auth","Payload":{"Unknown":1,"Deep":{"a":[1,2]}}}`),
		[]byte(`{"Type":"NoSuchMessage","Payload":{}}`),
		[]byte(`{"Type":"","Payload":null}`),
		[]byte(`{"Type":null,"Payload":[]}`),
		[]byte(`{"Type":"ReqTunnel","Payload":{"RemotePort":70000}}`),
		[]byte(`{"Type":"ReqTunnel","Payload":{"RemotePort":-1}}`),
		[]byte(`{"Type":"ReqTunnel","Payload":{"Pooling":"yes"}}`),
		[]byte(`{"Type":"StartProxy","Payload":[]}`),
		[]byte(`{"Type":"Envelope","Payload":{"Type":"Auth","Payload":{}}}`),
		[]byte(`[1,2,3]`),
		[]byte(`null`),
		[]byte(`{`),
		[]byte(``),
	}...)
}

// fzDecode feeds one byte string to every decode entry point and target. what
// names the entry point in failures.
func fzDecode(t *testing.T, what string, in []byte) {
	t.Helper()

	// The framed path: this is what ReadMsgInto does, including the size check
	// that is supposed to make an oversized frame impossible.
	for _, target := range fzTargets() {
		target := target
		if !fzDecodeOn(func() {
			c := &fzConn{r: bytes.NewReader(in)}
			err := ReadMsgInto(c, target.make())
			_ = err
		}) {
			t.Fatalf("%s: ReadMsgInto(%s) did not return within %s\ninput: %q", what, target.name, fzDecodeTimeout, in)
		}
	}

	// The bare-JSON path: the same bytes with the framing stripped, so the
	// envelope decoder sees them whether or not they were a plausible frame.
	for _, target := range fzTargets() {
		target := target
		if !fzDecodeOn(func() {
			_ = UnpackInto(in, target.make())
		}) {
			t.Fatalf("%s: UnpackInto(%s) did not return within %s\ninput: %q", what, target.name, fzDecodeTimeout, in)
		}
		if !fzDecodeOn(func() {
			_, _ = Unpack(in)
		}) {
			t.Fatalf("%s: Unpack did not return within %s\ninput: %q", what, fzDecodeTimeout, in)
		}
	}

	// Invariant 3, observable half: a frame that declares more than
	// maxMessageSize must be refused, whatever its payload says.
	if len(in) >= 8 {
		sz := int64(binary.LittleEndian.Uint64(in[:8]))
		if sz > maxMessageSize {
			err := ReadMsgInto(&fzConn{r: bytes.NewReader(in)}, &Auth{})
			if err == nil {
				t.Fatalf("%s: a frame declaring %d bytes was accepted, but maxMessageSize is %d\ninput: %q",
					what, sz, maxMessageSize, in)
			}
		}
	}
}

// FuzzMsgDecode feeds arbitrary bytes to the envelope decoder as a framed wire
// stream and as bare JSON.
func FuzzMsgDecode(f *testing.F) {
	for _, seed := range fzMessageSeeds() {
		f.Add(seed)
	}
	// Hand-built frames for the boundaries the size check has to catch.
	f.Add(fzFrame(0, nil))
	f.Add(fzFrame(-1, []byte(`{}`)))
	f.Add(fzFrame(1, nil))
	f.Add(fzFrame(4*1024*1024, []byte(`{}`)))
	f.Add(fzFrame(4*1024*1024+1, []byte(`{}`)))
	f.Add(fzFrame(1<<40, nil))
	f.Add([]byte("not a frame at all"))

	f.Fuzz(func(t *testing.T, in []byte) {
		fzDecode(t, "FuzzMsgDecode", in)
	})
}

// fzRoundTrip is invariant 4: whatever survived a decode has to survive a
// re-encode and a second decode unchanged, for the typed target and for the
// type-guessed one.
func fzRoundTrip(t *testing.T, what string, in []byte) {
	t.Helper()

	// Typed target: the decoder fills the caller's struct.
	target := &Auth{}
	if err := UnpackInto(in, target); err != nil {
		return
	}
	buf, err := Pack(target)
	if err != nil {
		t.Fatalf("%s: a payload that decoded as Auth could not be packed again: %v\ninput: %q", what, err, in)
	}
	again := &Auth{}
	if err := UnpackInto(buf, again); err != nil {
		t.Fatalf("%s: re-decoding a freshly packed Auth failed: %v\ninput: %q\npacked: %q", what, err, in, buf)
	}
	if !reflect.DeepEqual(target, again) {
		t.Fatalf("%s: the Auth round trip was not the identity\ninput:  %q\nfirst:  %+v\nsecond: %+v", what, in, target, again)
	}

	// Type-guessed target: Unpack picks the struct from the envelope's Type
	// field and hands back a pointer to it.
	msg, err := Unpack(in)
	if err != nil {
		return
	}
	if msg == nil {
		t.Fatalf("%s: Unpack returned no message and no error\ninput: %q", what, in)
	}
	rt := reflect.TypeOf(msg)
	if rt.Kind() != reflect.Ptr || rt.Elem().Kind() != reflect.Struct {
		// An interface{} target or any other shape Pack cannot name; Pack
		// would panic on a non-pointer, so this is the boundary of the
		// property rather than a failure of it.
		return
	}
	buf, err = Pack(msg)
	if err != nil {
		t.Fatalf("%s: an unpacked %s could not be packed again: %v\ninput: %q", what, rt.Elem().Name(), err, in)
	}
	againMsg, err := Unpack(buf)
	if err != nil {
		t.Fatalf("%s: re-decoding a freshly packed %s failed: %v\ninput: %q\npacked: %q", what, rt.Elem().Name(), err, in, buf)
	}
	if !reflect.DeepEqual(msg, againMsg) {
		t.Fatalf("%s: the %s round trip was not the identity\ninput:  %q\nfirst:  %+v\nsecond: %+v",
			what, rt.Elem().Name(), in, msg, againMsg)
	}
}

// FuzzEnvelopeRoundTrip fuzzes the pack/unpack pair on semi-valid envelope
// JSON: whatever decodes has to re-encode to the same value.
func FuzzEnvelopeRoundTrip(f *testing.F) {
	for _, seed := range fzJSONSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		if !fzDecodeOn(func() { fzRoundTrip(t, "FuzzEnvelopeRoundTrip", in) }) {
			t.Fatalf("FuzzEnvelopeRoundTrip did not return within %s\ninput: %q", fzDecodeTimeout, in)
		}
	})
}

// TestMsgFrameSizeIsBounded is invariant 3's accounting half: the size check
// has to happen before the buffer is allocated, so a frame header claiming a
// gigabyte must cost eight bytes of input and nothing else.
func TestMsgFrameSizeIsBounded(t *testing.T) {
	// A size that is unambiguously over the 4 MiB default but small enough that
	// a regression would be measurable rather than fatal.
	const claimed = 1 << 30
	in := fzFrame(claimed, nil)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	err := ReadMsgInto(&fzConn{r: bytes.NewReader(in)}, &Auth{})

	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatalf("a frame claiming %d bytes was accepted; maxMessageSize is %d", claimed, maxMessageSize)
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("the oversized frame failed for the wrong reason: %v", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
		t.Fatalf("rejecting a frame claiming %d bytes still allocated %d bytes; "+
			"the size check is meant to run before make([]byte, sz)", claimed, grew)
	}

	// The same claim through the public setter, to show the bound is
	// maxMessageSize and not a coincidence of the default.
	old := maxMessageSize
	defer SetMaxMessageSize(old)
	SetMaxMessageSize(1 << 20)
	if err := ReadMsgInto(&fzConn{r: bytes.NewReader(fzFrame(1<<20+1, nil))}, &Auth{}); err == nil {
		t.Fatalf("maxMessageSize = 1 MiB still accepted a 1 MiB + 1 frame")
	}
	SetMaxMessageSize(-1) // documented to ignore non-positive sizes
	if maxMessageSize != 1<<20 {
		t.Fatalf("SetMaxMessageSize(-1) changed the bound to %d; it is documented to ignore non-positive sizes", maxMessageSize)
	}
}

// TestMsgDecodeRejectsTruncatedAndTrailingFrames pins the framing behaviour
// around the size check: a frame whose declared length runs past the end of the
// stream is an error, and a second frame is decoded only after the first is
// consumed exactly.
func TestMsgDecodeRejectsTruncatedAndTrailingFrames(t *testing.T) {
	auth, err := Pack(&Auth{Version: "2", User: "u"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("truncated", func(t *testing.T) {
		in := fzFrame(int64(len(auth)), auth[:len(auth)-1])
		if err := ReadMsgInto(&fzConn{r: bytes.NewReader(in)}, &Auth{}); err == nil {
			t.Fatalf("a frame shorter than its declared length was accepted")
		}
	})

	t.Run("two frames", func(t *testing.T) {
		in := append(fzFrame(int64(len(auth)), auth), fzFrame(int64(len(auth)), auth)...)
		c := &fzConn{r: bytes.NewReader(in)}
		first := &Auth{}
		if err := ReadMsgInto(c, first); err != nil {
			t.Fatalf("the first frame failed: %v", err)
		}
		second := &Auth{}
		if err := ReadMsgInto(c, second); err != nil {
			t.Fatalf("the second frame failed: %v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("the two frames decoded differently: %+v vs %+v", first, second)
		}
	})

	t.Run("declared length zero", func(t *testing.T) {
		if err := ReadMsgInto(&fzConn{r: bytes.NewReader(fzFrame(0, []byte(`{"Type":"Ping","Payload":{}}`)))}, &Ping{}); err == nil {
			t.Fatalf("a frame declaring zero bytes was accepted")
		}
	})

	t.Run("negative declared length", func(t *testing.T) {
		if err := ReadMsgInto(&fzConn{r: bytes.NewReader(fzFrame(-1, nil))}, &Ping{}); err == nil {
			t.Fatalf("a frame declaring a negative length was accepted")
		}
	})
}

// TestMsgUnknownTypeIsAnError documents the dispatch table as the only place a
// type name becomes a struct: an envelope naming a type this build does not
// know is an error, never a zero value silently handed to a caller.
func TestMsgUnknownTypeIsAnError(t *testing.T) {
	for _, in := range [][]byte{
		[]byte(`{"Type":"NotAMessage","Payload":{}}`),
		[]byte(`{"Type":"","Payload":{}}`),
		[]byte(`{"Payload":{}}`),
	} {
		if msg, err := Unpack(in); err == nil {
			t.Fatalf("Unpack(%q) returned %#v and no error", in, msg)
		}
	}
	// ...and a known type with a broken payload is an error too, not a
	// half-filled struct reported as success.
	if _, err := Unpack([]byte(`{"Type":"Auth","Payload":`)); err == nil {
		t.Fatalf("a truncated envelope payload was accepted")
	}

	// json.Unmarshal is happy to accept a payload of the wrong shape for a
	// known type. That is by design here (the envelope Type wins), but it is
	// worth pinning: the decode is silent, so a caller that cares about a
	// mismatch has to check the fields itself.
	auth := &Auth{}
	if err := UnpackInto([]byte(`{"Type":"ReqTunnel","Payload":{"Url":"http://x","Protocol":"http"}}`), auth); err != nil {
		t.Fatalf("a ReqTunnel payload decoded into an *Auth reported an error: %v", err)
	}
	if auth.Version != "" || auth.User != "" {
		t.Fatalf("a ReqTunnel payload filled Auth fields: %+v", auth)
	}
	// An *Envelope target is a trap, not a shortcut, and it is worth pinning
	// because the type is exported. unpack decodes the outer envelope into a
	// local, then decodes env.Payload *into the caller's target* -- so an
	// *Envelope target gets the payload object's fields decoded into its own
	// two fields, and the envelope the caller asked for is gone. Nothing in
	// this repository reads a message that way (the dispatch is by Type, and
	// Envelope is not in TypeMap), but a caller who tried it would get a
	// zero Envelope and no error at all: the failure is silent.
	env := &Envelope{}
	if err := UnpackInto([]byte(`{"Type":"Auth","Payload":{"Version":"2"}}`), env); err != nil {
		t.Fatalf("decoding into an *Envelope failed: %v", err)
	}
	if env.Type != "" || len(env.Payload) != 0 {
		t.Fatalf("an *Envelope target now keeps the envelope; update this test and the note above: %+v", env)
	}
	decoded, err := Unpack([]byte(`{"Type":"Auth","Payload":{"Version":"2"}}`))
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}
	auth, ok := decoded.(*Auth)
	if !ok || auth.Version != "2" {
		t.Fatalf("the typed dispatch did not reach the payload: %#v", decoded)
	}
	_ = json.RawMessage(nil) // the encoding/json import is used by the seeds above
}
