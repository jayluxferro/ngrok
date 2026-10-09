package conn

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	vhost "github.com/inconshreveable/go-vhost"
	"io"
	"net"
	"net/http"
	"net/url"
	"ngrok/log"
	"ngrok/util"
	"sync"
)

type Conn interface {
	net.Conn
	log.Logger
	Id() string
	SetType(string)
	CloseRead() error
}

type loggedConn struct {
	tcp *net.TCPConn
	net.Conn
	log.Logger
	id  int32
	typ string
}

type Listener struct {
	net.Addr
	net.Listener
	Conns chan *loggedConn
}

func wrapConn(conn net.Conn, typ string) *loggedConn {
	switch c := conn.(type) {
	case *vhost.HTTPConn:
		wrapped := c.Conn.(*loggedConn)
		return &loggedConn{wrapped.tcp, conn, wrapped.Logger, wrapped.id, wrapped.typ}
	case *loggedConn:
		return c
	case *net.TCPConn:
		wrapped := &loggedConn{c, conn, log.NewPrefixLogger(), util.GlobalInt31(), typ}
		wrapped.AddLogPrefix(wrapped.Id())
		return wrapped
	default:
		// Anything else is a net.Conn that is not a TCP connection. The caller
		// today is the smux multiplexer (SPEC cluster 3, 3.1), which hands us
		// its streams so that they travel through the whole conn.Conn stack --
		// msg framing, logging, deadlines, Join -- exactly like the TCP proxy
		// connections they replace.
		//
		// There is no *net.TCPConn to record here, so the tcp field stays nil:
		// it is only read by CloseRead, which can only mean anything for a TCP
		// connection and is not called on these conns.
		wrapped := &loggedConn{nil, conn, log.NewPrefixLogger(), util.GlobalInt31(), typ}
		wrapped.AddLogPrefix(wrapped.Id())
		return wrapped
	}
}

func Listen(addr, typ string, tlsCfg *tls.Config) (l *Listener, err error) {
	// listen for incoming connections
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return
	}

	l = &Listener{
		Addr:     listener.Addr(),
		Listener: listener,
		Conns:    make(chan *loggedConn),
	}

	go func() {
		defer close(l.Conns)
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				// Listener has likely been closed for shutdown.
				return
			}

			c := wrapConn(rawConn, typ)
			if tlsCfg != nil {
				c.Conn = tls.Server(c.Conn, tlsCfg)
			}
			c.Info("New connection from %v", c.RemoteAddr())
			l.Conns <- c
		}
	}()
	return
}

func (l *Listener) Close() error {
	return l.Listener.Close()
}

func Wrap(conn net.Conn, typ string) *loggedConn {
	return wrapConn(conn, typ)
}

func Dial(addr, typ string, tlsCfg *tls.Config) (conn *loggedConn, err error) {
	var rawConn net.Conn
	if rawConn, err = net.Dial("tcp", addr); err != nil {
		return
	}

	conn = wrapConn(rawConn, typ)
	conn.Debug("New connection to: %v", rawConn.RemoteAddr())

	if tlsCfg != nil {
		conn.StartTLS(tlsCfg)
	}

	return
}

func DialHttpProxy(proxyUrl, addr, typ string, tlsCfg *tls.Config) (conn *loggedConn, err error) {
	// parse the proxy address
	var parsedUrl *url.URL
	if parsedUrl, err = url.Parse(proxyUrl); err != nil {
		return
	}

	var proxyAuth string
	if parsedUrl.User != nil {
		proxyAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(parsedUrl.User.String()))
	}

	var proxyTlsConfig *tls.Config
	switch parsedUrl.Scheme {
	case "http":
		proxyTlsConfig = nil
	case "https":
		proxyTlsConfig = new(tls.Config)
	default:
		err = fmt.Errorf("Proxy URL scheme must be http or https, got: %s", parsedUrl.Scheme)
		return
	}

	// dial the proxy
	if conn, err = Dial(parsedUrl.Host, typ, proxyTlsConfig); err != nil {
		return
	}

	// send an HTTP proxy CONNECT message
	req, err := http.NewRequest("CONNECT", "https://"+addr, nil)
	if err != nil {
		return
	}

	if proxyAuth != "" {
		req.Header.Set("Proxy-Authorization", proxyAuth)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ngrok)")
	req.Write(conn)

	// read the proxy's response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		err = fmt.Errorf("Non-200 response from proxy server: %s", resp.Status)
		return
	}

	// upgrade to TLS
	conn.StartTLS(tlsCfg)

	return
}

func (c *loggedConn) StartTLS(tlsCfg *tls.Config) {
	c.Conn = tls.Client(c.Conn, tlsCfg)
}

func (c *loggedConn) Close() (err error) {
	if err := c.Conn.Close(); err == nil {
		c.Debug("Closing")
	}
	return
}

func (c *loggedConn) Id() string {
	return fmt.Sprintf("%s:%x", c.typ, c.id)
}

func (c *loggedConn) SetType(typ string) {
	oldId := c.Id()
	c.typ = typ
	// One critical section: a log call concurrent with the rename must see
	// the whole old prefix or the whole new one, never the momentary empty
	// prefix the ClearLogPrefixes+AddLogPrefix pair this replaced exposed
	// between its two locks.
	c.SetLogPrefixes(c.Id())
	c.Info("Renamed connection %s", oldId)
}

func (c *loggedConn) CloseRead() error {
	// XXX: use CloseRead() in Conn.Join() and in Control.shutdown() for cleaner
	// connection termination. Unfortunately, when I've tried that, I've observed
	// failures where the connection was closed *before* flushing its write buffer,
	// set with SetLinger() set properly (which it is by default).
	return c.tcp.CloseRead()
}

// joinBufSize is the size of the staging buffer Join hands to io.CopyBuffer, in
// place of the 32 KiB io.Copy allocates for itself. macOS has no splice(2), so
// a plain-TCP leg on Darwin pays a userspace hop whatever we do, and a 32 KiB
// buffer underutilizes a high-BDP link; 256 KiB keeps more of the pipe in
// flight. On Linux it costs nothing: the legs that can splice (conn/zerocopy.go
// delegates to the net package) never look at the buffer at all.
const joinBufSize = 256 * 1024

// joinBufPool is where those buffers come from.
//
// A pool, and not one package-level slice, because io.CopyBuffer stages EVERY
// read through the buffer it is given for the whole life of the copy: a single
// shared slice is therefore read into by every copy in the process at once.
// That is not a style preference -- two directions of one join run
// concurrently, so with a shared slice they overwrite each other's in-flight
// bytes, which -race reports on the staged leg of
// TestJoinStagingBufferIsNotShared (conn/zerocopy_test.go). Per-copy buffers
// cost nothing extra in steady state: the pool holds one buffer per concurrent
// copy either way and reuses it instead of reallocating.
//
// The buffer only matters for legs that expose neither ReadFrom nor WriterTo,
// because io.CopyBuffer short-circuits to those first. Every *loggedConn now
// exposes both (conn/zerocopy.go); the legs that do not are the ones wrapped
// in an interface-embedding adapter -- rewriter's filteredConn, and the tee's
// read side -- plus anything the net package cannot reach, i.e. TLS legs and
// smux streams, which is exactly where the larger buffer pays off on Darwin.
var joinBufPool = sync.Pool{
	New: func() interface{} { return make([]byte, joinBufSize) },
}

func Join(c Conn, c2 Conn) (int64, int64) {
	var wait sync.WaitGroup

	pipe := func(to Conn, from Conn, bytesCopied *int64) {
		defer to.Close()
		defer from.Close()
		defer wait.Done()

		// One buffer per direction, from the pool: see joinBufPool above for
		// why this may not be a single shared slice.
		buf := joinBufPool.Get().([]byte)
		defer joinBufPool.Put(buf)

		var err error
		*bytesCopied, err = io.CopyBuffer(to, from, buf)
		if err != nil {
			from.Warn("Copied %d bytes to %s before failing with error %v", *bytesCopied, to.Id(), err)
		} else {
			from.Debug("Copied %d bytes to %s", *bytesCopied, to.Id())
		}
	}

	wait.Add(2)
	var fromBytes, toBytes int64
	go pipe(c, c2, &fromBytes)
	go pipe(c2, c, &toBytes)
	c.Info("Joined with connection %s", c2.Id())
	wait.Wait()
	return fromBytes, toBytes
}
