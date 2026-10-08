package rewriter

// Fuzzing and the hostile edge matrix for the rewriter state machine.
//
// The rewriter sits in front of the public internet on both ends of a tunnel:
// the bytes it reads are whatever the peer sends, and the only thing standing
// between a malformed stream and a broken connection is fail-open. This file
// states that as invariants a fuzzer can check, and then drives the edges the
// prose in rewriter.go makes claims about.
//
// The invariants, and where each is enforced:
//
//  1. No panic. Arbitrary bytes, a hostile policy, a hook that panics on every
//     message and a hook that returns CR/LF-carrying verdicts. A panic here is
//     the fuzzer's crash, not a recovered one: the point is that the package is
//     supposed to catch it first (callRequestHook/callResponseHook), and a
//     crash proves it did not.
//
//  2. Termination. Every drain finishes inside fzDrainTimeout and the output is
//     bounded relative to the input. Both sources are in-memory readers, so a
//     drain that needs longer than the timeout is not slow -- it is a state
//     machine that stopped consuming its input, which is the one way this
//     package can hang a live connection.
//
//  3. A policy that transforms nothing is the identity map. Not "preserves the
//     message", not "preserves the bytes net/http cares about": out == in,
//     byte for byte, in both directions, for arbitrary input. This is the
//     package's central promise ("fail-open ... keeps a connection the old
//     code would have carried working") stated as an equation, and it is the
//     strongest oracle in the file: any byte the state machine reorders, drops
//     or duplicates fails it, with no judgement call about what the bytes mean.
//
//  4. A transforming policy keeps a well-formed message well-formed. If the
//     input is exactly one complete HTTP message that net/http itself can read
//     (head, body, and nothing left over), then the output must also be exactly
//     one complete message that net/http can read. net/http is the arbiter of
//     "well-formed" here for the same reason the package's own tests use it:
//     if a real client cannot read what we produced, the framing is wrong
//     however the bytes look.
//
//  5. The gzip transform's body contract. When the output declares
//     Content-Encoding: gzip, decompressing its body reproduces the input body
//     byte for byte (rewriter.go's own words: "the transform's whole contract").
//
// Invariant 4 is deliberately gated on the *input* being net/http-readable.
// The rewriter's own parser is laxer than net/http in places -- it accepts a
// request target or a version net/http rejects -- and a head it rewrites
// without understanding is passed through with only the policy's fields
// changed, so gating on the laxer parser would fail on inputs that were never
// well-formed to begin with. Gating on net/http asks the question that matters:
// the policy may only ever change the bytes it names, so a message a client
// could read must stay a message a client can read.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- driving the pair -------------------------------------------------------

// fzDrainTimeout bounds one drain of one pair. See invariant 2 above.
const fzDrainTimeout = 5 * time.Second

// fzOutCap bounds the output one direction may produce from an input of n
// bytes. The policy's own additions are a constant, and the gzip transform
// costs a few bytes of chunk framing per read rather than per byte, so anything
// past this is a state machine that is not making progress rather than a
// transform with a bad ratio. The allowance is generous on purpose: the check
// is for runaway output, not for compression ratio.
func fzOutCap(n int) int { return 64*n + 1<<20 }

// errFzOutputTooBig is returned by fzCapWriter's Write, and surfacing it is a
// finding (invariant 2), never a limitation of the harness.
var errFzOutputTooBig = errors.New("rewriter output exceeded the cap for its input")

// fzCapWriter is an io.Writer that refuses to grow past limit, so that a
// rewriter which never terminates on a bounded input cannot take the fuzz
// process down with it before the watchdog has a chance to report.
type fzCapWriter struct {
	buf   bytes.Buffer
	limit int
}

func (w *fzCapWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.limit {
		return 0, errFzOutputTooBig
	}
	return w.buf.Write(p)
}

// fzRunResult is one pair's two outputs, or the reason there are none.
type fzRunResult struct {
	reqOut, respOut []byte
	err             error
	timedOut        bool

	// stage is only meaningful when timedOut is set: it names the drain that
	// was in flight when the watchdog fired, so that a recurrence says which
	// side to look at instead of being undiagnosable the way the first one was.
	stage string
}

// fzOptions are the read shapes a run can be tortured with.
type fzOptions struct {
	// byteWise hands the source out one byte per Read. Every line boundary,
	// every chunk-size line and every framing byte then arrives on its own,
	// which is the worst case for a state machine whose steps are sized by what
	// a single read returns.
	byteWise bool

	// outBuf is the caller's buffer size. 0 is io.Copy's 32 KiB.
	outBuf int
}

// fzRun drives one pair over in-memory sources.
func fzRun(reqIn, respIn string, p *Policy) fzRunResult {
	return fzRunOpts(reqIn, respIn, p, fzOptions{})
}

// fzRunOpts is fzRun with the read shapes made explicit.
//
// The request side is drained first, then the response side, which is the
// order a live connection sees: a response can only be framed once the request
// that asked for it was parsed, and the response side needs the request side's
// method and Accept-Encoding to decide anything at all.
//
// Both drains run on another goroutine so that a state machine which stops
// consuming its input fails the test instead of hanging the fuzz process. The
// goroutine is abandoned when the watchdog fires, which is why the timeout is
// seconds rather than milliseconds: it must never fire on a slow machine, only
// on a stuck one.
//
// Two details here are the residue of an unreproduced failure during the timed
// fuzz run (see fzFlakeInput and TestRewriterFlakeInputIsStable): the timer is
// created with NewTimer and stopped rather than taken from time.After, and the
// timeout records which drain was in flight.
//
// The first is not stylistic. time.After's timer cannot be stopped by the
// caller, so every call that takes the done branch -- which is almost all of
// them -- leaks a live 5s timer that has to sit in the runtime's timer heap
// until it fires. fzCheck runs four drains per fuzz execution and the fuzzer
// does ~35k executions per second, so that is on the order of 700k live timers
// and 700k timer expirations per second, all of them sending into a channel
// nobody will ever receive from. That is a lot of timer-heap and GC churn to
// put next to the thing being measured, and a stall caused by it would look
// exactly like a stalled state machine. Stopping the timer removes the churn.
//
// The second is diagnosability. The failure that prompted all of this reported
// an input that passes on its own and has never reproduced, and the one thing
// that would have settled it -- which drain was stuck -- was not recorded
// anywhere. The stage is now read out of the timeout message.
func fzRunOpts(reqIn, respIn string, p *Policy, opt fzOptions) fzRunResult {
	done := make(chan fzRunResult, 1)

	// fzDrainStage: 0 before the pair is built, 1 draining the request side,
	// 2 draining the response side, 3 done. Only the timeout path reads it, so
	// its only job is to say where a stuck drain stopped.
	var stage atomic.Int32

	go func() {
		var reqSrc, respSrc io.Reader = strings.NewReader(reqIn), strings.NewReader(respIn)
		if opt.byteWise {
			reqSrc, respSrc = &fzByteReader{s: reqIn}, &fzByteReader{s: respIn}
		}
		req, resp := NewPair(reqSrc, respSrc, p)

		var res fzRunResult
		copyOne := func(r io.Reader, n int, dst *[]byte, side string) error {
			w := &fzCapWriter{limit: fzOutCap(n)}
			var err error
			if opt.outBuf > 0 {
				_, err = io.CopyBuffer(w, r, make([]byte, opt.outBuf))
			} else {
				_, err = io.Copy(w, r)
			}
			if err != nil {
				return fmt.Errorf("%s side: %w", side, err)
			}
			*dst = append([]byte(nil), w.buf.Bytes()...)
			return nil
		}

		stage.Store(1)
		res.err = copyOne(req, len(reqIn), &res.reqOut, "request")
		stage.Store(2)
		if respErr := copyOne(resp, len(respIn), &res.respOut, "response"); res.err == nil {
			res.err = respErr
		}
		stage.Store(3)
		done <- res
	}()

	timer := time.NewTimer(fzDrainTimeout)
	defer timer.Stop()
	select {
	case res := <-done:
		return res
	case <-timer.C:
		return fzRunResult{timedOut: true, stage: fzDrainStageName(stage.Load())}
	}
}

// fzDrainStageName turns the stage counter into words for the timeout message.
func fzDrainStageName(n int32) string {
	switch n {
	case 0:
		return "before either drain started (building the pair)"
	case 1:
		return "draining the request side"
	case 2:
		return "draining the response side"
	default:
		return "after both drains returned (writing the result)"
	}
}

// fzByteReader hands out exactly one byte per Read. It is the read shape a
// live connection produces when a peer writes a head one byte at a time, and
// the shape that makes every claim about "reads consume exactly up to the line
// terminator, so nothing beyond the line is over-consumed" testable.
type fzByteReader struct {
	s string
	i int
}

func (r *fzByteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.s[r.i]
	r.i++
	return 1, nil
}

// fzFinished fails the test if a drain did not finish, or if the output ran
// away from the input (invariants 1 and 2).
func fzFinished(t *testing.T, what string, r fzRunResult) fzRunResult {
	t.Helper()
	if r.timedOut {
		t.Fatalf("%s: the rewriter did not finish a drain of an in-memory source within %s "+
			"(stuck %s); a state machine that stops consuming its input is the one way this "+
			"package can hang a live connection",
			what, fzDrainTimeout, r.stage)
	}
	if r.err != nil {
		t.Fatalf("%s: draining the rewriter failed: %v", what, r.err)
	}
	return r
}

// --- net/http as the arbiter of "well-formed" -------------------------------

// fzCountingReader counts what was taken off the front of the stream, so that
// "how many bytes did that message use" is answerable even though bufio reads
// ahead.
type fzCountingReader struct {
	r io.Reader
	n int64
}

func (c *fzCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// fzHTTP is what net/http made of one raw stream.
type fzHTTP struct {
	header   http.Header
	status   int
	body     []byte
	consumed int // bytes of the raw stream the message used
}

// fzReadHTTP reads exactly one HTTP message out of raw with net/http, plus its
// decoded body. consumed is len(raw) exactly when the stream held one message
// and nothing else.
func fzReadHTTP(raw []byte, sd side) (fzHTTP, error) {
	var out fzHTTP
	cr := &fzCountingReader{r: bytes.NewReader(raw)}
	br := bufio.NewReader(cr)

	var body io.ReadCloser
	if sd == sideRequest {
		req, err := http.ReadRequest(br)
		if err != nil {
			return out, err
		}
		out.header, out.status, body = req.Header, 0, req.Body
	} else {
		// req is nil: net/http then reads the response as an answer to a GET.
		// Every response this test feeds the response side is an answer to the
		// plain GET in fzFuzzRequest, which is not a HEAD, so the two agree
		// about whether a body is allowed.
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return out, err
		}
		out.header, out.status, body = resp.Header, resp.StatusCode, resp.Body
	}

	b, err := io.ReadAll(body)
	body.Close()
	if err != nil {
		return out, err
	}
	out.body = b
	out.consumed = int(cr.n) - br.Buffered()
	return out, nil
}

// fzComplete reports whether raw is exactly one complete HTTP message.
func fzComplete(raw []byte, sd side) (fzHTTP, bool) {
	m, err := fzReadHTTP(raw, sd)
	if err != nil {
		return m, false
	}
	return m, m.consumed == len(raw)
}

// fzOneMessage is invariant 4. It says nothing about input that is not a
// complete message: for anything else the only promise this package makes is
// that no byte is lost, and fzNoopIdentity is what checks that.
func fzOneMessage(t *testing.T, what string, sd side, in, out []byte, gzipBody bool) {
	t.Helper()
	inMsg, ok := fzComplete(in, sd)
	if !ok {
		return
	}

	outMsg, err := fzReadHTTP(out, sd)
	if err != nil {
		t.Fatalf("%s: the input is one complete HTTP message net/http can read, but the output is not readable at all: %v\ninput:  %q\noutput: %q", what, err, in, out)
	}
	if outMsg.consumed != len(out) {
		t.Fatalf("%s: the output is not exactly one message: net/http used %d of %d bytes\ninput:  %q\noutput: %q",
			what, outMsg.consumed, len(out), in, out)
	}

	// Invariant 5: the transform's body contract.
	if !gzipBody || outMsg.header.Get("Content-Encoding") != "gzip" {
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(outMsg.body))
	if err != nil {
		t.Fatalf("%s: the output declares Content-Encoding: gzip but its body is not a gzip stream: %v\ninput:  %q\noutput: %q", what, err, in, out)
	}
	got, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatalf("%s: decompressing the transformed body failed: %v\noutput: %q", what, err, out)
	}
	if !bytes.Equal(got, inMsg.body) {
		t.Fatalf("%s: the compressed body does not decompress to the input body\ngot:  %q\nwant: %q", what, got, inMsg.body)
	}
}

// fzNoopIdentity is invariant 3, the strongest oracle in the file.
//
// One byte change is carved out of it, and exactly one: the CL+TE
// normalization RFC 7230 3.3.3 calls for. A head that states both framings is
// forwarded without its Content-Length, and this is not a policy decision --
// the corpus contains such a head on purpose (fzReqSeeds[13], which is
// rewriter_test.go's dual-framed case), and the alternative to dropping the
// field is forwarding a head that two HTTP stacks can disagree about, which is
// the request-smuggling shape the pairing is famous for. The carve-out is
// structural rather than "a shorter output is fine": out has to be in with
// nothing removed but Content-Length field lines, and each dropped line has to
// sit in a head that also carries a chunked Transfer-Encoding (see
// rewriteRequestHead). Every other byte change is still a failure.
func fzNoopIdentity(t *testing.T, what, in, out string) {
	t.Helper()
	if in == out {
		return
	}
	if fzNormalizationOnlyCL(in, out) {
		return
	}
	t.Fatalf("%s: a policy that transforms nothing changed the bytes (at offset %d)\ninput:  %q\noutput: %q",
		what, firstDiff(in, out), in, out)
}

// fzNormalizationOnlyCL reports whether out is in with nothing removed but
// droppable Content-Length lines. Comparison is by line, so a change inside a
// line is never accepted; the line terminator itself is not compared, which
// leaves a \n-versus-\r\n change invisible to this one predicate (fzOneMessage
// is what would catch that, and net/http reads both).
func fzNormalizationOnlyCL(in, out string) bool {
	inLines, outLines := strings.Split(in, "\n"), strings.Split(out, "\n")
	j := 0
	for i := 0; i < len(inLines); i++ {
		if j < len(outLines) && inLines[i] == outLines[j] {
			j++
			continue
		}
		if !fzDroppableCL(inLines, i) {
			return false
		}
	}
	return j == len(outLines)
}

// fzDroppableCL reports whether inLines[i] is a Content-Length field of a head
// that names chunked Transfer-Encoding. The head is the blank-line-delimited
// window around the line, which is the window parseHead works in.
func fzDroppableCL(lines []string, i int) bool {
	if name, ok := fzFieldName(lines[i]); !ok || name != "content-length" {
		return false
	}
	for j := i; j >= 0; j-- {
		if fzBlankLine(lines[j]) {
			break
		}
		if name, ok := fzFieldName(lines[j]); ok && name == "transfer-encoding" &&
			strings.Contains(strings.ToLower(lines[j]), "chunked") {
			return true
		}
	}
	for j := i + 1; j < len(lines); j++ {
		if fzBlankLine(lines[j]) {
			break
		}
		if name, ok := fzFieldName(lines[j]); ok && name == "transfer-encoding" &&
			strings.Contains(strings.ToLower(lines[j]), "chunked") {
			return true
		}
	}
	return false
}

// fzFieldName reads the lower-cased field name off a header line. A line that
// is not of the form token ":" ... has no name. The token check is what keeps a
// body line that happens to start with "Content-Length :" from counting as a
// droppable field.
func fzFieldName(line string) (string, bool) {
	line = strings.TrimSuffix(line, "\r")
	i := strings.IndexByte(line, ':')
	if i <= 0 {
		return "", false
	}
	name := line[:i]
	for k := 0; k < len(name); k++ {
		if !fzTokenByte(name[k]) {
			return "", false
		}
	}
	return strings.ToLower(name), true
}

// fzTokenByte is RFC 7230's tchar, which is what a field name may be made of.
func fzTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// fzBlankLine reports whether a line, as split on "\n", is the empty line
// between a head and what follows it.
func fzBlankLine(line string) bool {
	return line == "" || line == "\r"
}

// fzRefusedHead reports whether the difference between a hook-armed run and an
// unarmed one is the refusal refuseHead documents: with a request hook armed, a
// head the request side cannot process is answered with a 431 and never
// forwarded, where the unarmed policy fails open and passes it through.
//
// There are two routes into that refusal -- a head too tall for the read buffer
// or the 64 KiB cap, and a head parseHead rejects -- and they are one rule in
// the rewriter, so they are one predicate here: split, a divergence that fits
// neither half would be waved through by the other.
//
// Each clause is a way for the refusal to not be the explanation:
//
//  1. The armed run forwarded a strict prefix of the unarmed one. Strict,
//     because the refusal always withholds at least the bytes of the head it
//     refused, and the unarmed run is the one that carries them (fail open). A
//     prefix, because a panicking hook leaves no other trace -- every message
//     before the refused one is rewritten identically -- and because the refusal
//     stops the request side for good (it drains), so nothing can be forwarded
//     behind it.
//
//  2. The withheld tail is refused from its first byte when it is offered to
//     the armed request side on a connection of its own: nothing forwarded, and
//     the 431 as the answer. This is where the narrowness lives, and it is asked
//     of the rewriter rather than re-derived here on purpose -- a second copy of
//     the parser's rules would be free to drift from the decision it describes.
//     It works because the tail begins exactly at the first byte of the message
//     the armed run refused: that message is the one the unarmed run carries
//     verbatim (a head parseHead cannot read is precisely the case both the
//     refusal and fail-open exist for), so re-feeding it reproduces the refusal
//     as a first-message one, whatever shape the head has -- a line past the read
//     buffer, a head past the cap, an obs-fold continuation line, a header line
//     with no colon, a space in the field name, a request line that is not one.
//     It also rules out the reading that would make this carve-out useless: a run
//     that stops early for some other reason has an arbitrary tail, and an
//     arbitrary tail is not a stream the armed side refuses from its first byte
//     -- a stream with no complete head in it fails open like anything else, and
//     then this clause sees the bytes.
//
//  3. The response side differs only by the 431 the refusal publishes.
//
// Clause 2 asks the rewriter about itself, so it is worth being exact about what
// it does not prove: a rewriter that refused every armed request outright would
// explain every divergence this way too, and this target would not notice --
// verified, not assumed, by refusing every request in a scratch build and
// watching the seed corpus pass. The envelope of what the refusal may swallow (a
// well-formed request goes through with a hook armed, an unarmed policy fails
// open on an unprocessable head, the answer is the 431 and not something a hook
// chose) is pinned by rewriter_test.go, not here. What this predicate is for is
// the other direction: a divergence with no refusal behind it, or a refusal
// whose shape has drifted from the one the rewriter makes.
//
// What none of this says is that the refusal is correct -- only that it is the
// refusal. The invariants that are not about a hook being invisible run on the
// same input either way; this predicate exists to name the one exception, not to
// excuse the run.
func fzRefusedHead(t *testing.T, static, panics fzRunResult) bool {
	t.Helper()

	if len(panics.reqOut) >= len(static.reqOut) || !bytes.HasPrefix(static.reqOut, panics.reqOut) {
		return false
	}
	tail := fzFinished(t, "the withheld tail, armed, on a connection of its own",
		fzRun(string(static.reqOut[len(panics.reqOut):]), "", fzPanicHookPolicy))
	if len(tail.reqOut) != 0 || !fzIs431(tail.respOut) {
		return false
	}
	return fzRefusalOnTheWire(panics.respOut, static.respOut)
}

// fzIs431 reports whether raw is exactly one complete 431 response, the answer
// refuseHead publishes when it refuses a request.
func fzIs431(raw []byte) bool {
	m, ok := fzComplete(raw, sideResponse)
	return ok && m.status == http.StatusRequestHeaderFieldsTooLarge
}

// fzRefusalOnTheWire reports whether the armed run's response bytes are
// explained by the refusal.
//
// There are two shapes, and which one applies is a fact about generations
// rather than about the bytes: the 431 is delivered on the response side of the
// request that was refused (connState.takeTerminate is keyed by generation), so
// it can be answered on only if that request's answer slot is reached at all.
//
//   - With the 431 on the wire, it ends the stream: the terminated response side
//     drains from there, dropping whatever answer was queued behind a request
//     that never left this process. What came before it has to be a prefix of the
//     unarmed run's answer -- a refusal is announced at a message boundary, so it
//     cannot rewrite what has already been sent.
//
//   - With no 431, the terminate was never delivered: the response side reached
//     the end of its source before the boundary a refused request's answer would
//     have been delivered at (the fuzz harness has an upstream that answers
//     nothing, or answers fewer requests than the client sent). Nothing of the
//     refusal reached the response side then, so its bytes have to be exactly the
//     unarmed run's -- not a prefix: a response side that stopped short without a
//     431 to show for it is a truncation, which is a finding.
func fzRefusalOnTheWire(armed, static []byte) bool {
	for off := 0; ; {
		if off == len(armed) {
			return bytes.Equal(armed, static)
		}
		m, err := fzReadHTTP(armed[off:], sideResponse)
		if err != nil || m.consumed == 0 {
			return false
		}
		if m.status == http.StatusRequestHeaderFieldsTooLarge {
			return off+m.consumed == len(armed) && bytes.HasPrefix(static, armed[:off])
		}
		off += m.consumed
	}
}

// fzPrefaceInput reports whether the request bytes open with a head the
// rewriter's preface guard fires on (h2Preface): a request line whose method
// is PRI or whose version is HTTP/2.0, at the head of a connection that
// parses. With no hook armed the connection passes through; with any hook
// armed it is closed outright. The predicate mirrors parseHead plus
// parsedHead.isHTTP2Preface rather than calling them -- an oracle that imports
// the code under test would prove nothing, the same choice
// fzNormalizationOnlyCL made -- so the two spellings are kept apart on
// purpose, and drift between them is a finding.
//
// The head has to parse, and that part matters: a PRI line followed by a line
// that is not a field is a head parseHead rejects, and that input belongs to
// the refusal exception above (fzRefusedHead), not to this one. The two
// signals alone are true of bytes the rewriter never treats as a preface.
func fzPrefaceInput(reqIn string) bool {
	// Lines as a split on "\n", which is the convention fzBlankLine and
	// fzFieldName already work in: the terminator is not part of a line, and
	// a trailing "\r" is. The last element of the split is the tail behind the
	// final newline -- empty when the input ends with one, and never a line --
	// so a head is complete only if its blank line lands before the tail: a
	// head the input never terminates is one the guard never sees, and one
	// that stays on the ordinary paths (end of stream in the middle of a head).
	lines := strings.Split(reqIn, "\n")
	complete := len(lines) - 1
	i := 0

	// The tolerated blank lines before a start line are consumed first, the
	// way parseHead consumes them: the guard sees the preface behind them.
	for {
		if i >= complete {
			return false
		}
		if !fzBlankLine(lines[i]) {
			break
		}
		i++
	}
	startLine := lines[i]
	i++

	// The request line, as parseRequestLine reads it: three space-separated
	// parts, a token method, a non-empty target, a version shaped HTTP/d.d.
	parts := strings.Split(strings.TrimSuffix(startLine, "\r"), " ")
	if len(parts) != 3 || parts[1] == "" || !fzIsToken(parts[0]) || !fzIsHTTPVersion(parts[2]) {
		return false
	}
	if parts[0] != "PRI" && parts[2] != "HTTP/2.0" {
		return false
	}

	// Then the head's fields, up to the blank line that ends the head. The
	// guard only sees a preface in a head that parses; anything else takes the
	// refusal path instead. The field grammar here is parseHeaderField's, not
	// fzFieldName's: the name is what precedes the colon with trailing spaces
	// and tabs trimmed off, and that has to be a token. fzFieldName is
	// deliberately stricter -- it exists to keep body lines from counting as
	// droppable fields, so "0 :" failing it is correct there and wrong here,
	// where the question is whether the rewriter parsed the head at all.
	for {
		if i >= complete {
			return false
		}
		line := lines[i]
		i++
		if fzBlankLine(line) {
			return true
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return false // obs-fold: parseHeaderField refuses the head
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return false
		}
		if !fzIsToken(strings.TrimRight(line[:colon], " \t")) {
			return false
		}
	}
}

// fzIsHTTPVersion mirrors the request-line grammar's version shape: "HTTP/",
// then digit.digit. It is the acceptance that lets "HTTP/2.0" parse as a
// request line at all, which is why the guard has to name it.
func fzIsHTTPVersion(v string) bool {
	return len(v) == 8 && v[:5] == "HTTP/" && v[6] == '.' &&
		v[5] >= '0' && v[5] <= '9' && v[7] >= '0' && v[7] <= '9'
}

// fzIsToken reports whether s is entirely tchar (fzTokenByte), which is what
// a request method must be for parseRequestLine to accept the line.
func fzIsToken(s string) bool {
	if s == "" {
		return false
	}
	for k := 0; k < len(s); k++ {
		if !fzTokenByte(s[k]) {
			return false
		}
	}
	return true
}

// --- the policy matrix ------------------------------------------------------

// fzNoopPolicy transforms nothing. IsNoop is true for it, which is also the
// check the client uses to skip the wrapping -- so a byte change here would be
// a byte change on a connection that is not supposed to be wrapped at all.
var fzNoopPolicy = &Policy{}

// fzStaticPolicy is the hostile static policy: rewrite the Host, add and remove
// headers on both sides, inject X-Forwarded, and compress responses.
var fzStaticPolicy = &Policy{
	HostHeader:      "rewrite",
	UpstreamHost:    "upstream.internal:8080",
	ClientAddr:      "203.0.113.7",
	XForwardedProto: "https",
	Compress:        true,

	RequestHeaderAdd: []string{
		"X-Injected: yes",
		"X-With-Colon: a:b:c",
		"X-Empty:",
	},
	RequestHeaderRemove: []string{"cookie", "x-forwarded-for", "x-forwarded-proto"},

	ResponseHeaderAdd:    []string{"X-Resp: 1", "X-Resp: 2"},
	ResponseHeaderRemove: []string{"etag", "x-remove-me"},
}

// fzStaticNoCompressPolicy is fzStaticPolicy without the gzip transform. The
// one-byte read test compares a whole-read run against a byte-wise run, and the
// transform is deliberately read-size sensitive (feedGzip flushes per read, so
// the chunk boundaries follow the read sizes) -- so the equality is asserted
// for the paths where the output is a function of the parsed stream alone.
var fzStaticNoCompressPolicy = &Policy{
	HostHeader:           fzStaticPolicy.HostHeader,
	UpstreamHost:         fzStaticPolicy.UpstreamHost,
	ClientAddr:           fzStaticPolicy.ClientAddr,
	XForwardedProto:      fzStaticPolicy.XForwardedProto,
	RequestHeaderAdd:     fzStaticPolicy.RequestHeaderAdd,
	RequestHeaderRemove:  fzStaticPolicy.RequestHeaderRemove,
	ResponseHeaderAdd:    fzStaticPolicy.ResponseHeaderAdd,
	ResponseHeaderRemove: fzStaticPolicy.ResponseHeaderRemove,
}

// fzPanicHookPolicy is fzStaticPolicy with hooks that panic on every message.
// The documented rule is that a panicking hook is a skipped hook and the
// connection continues on exactly the bytes the static policy produced, so the
// assertion is not "it survives" but "it survives byte-identically".
var fzPanicHookPolicy = func() *Policy {
	p := *fzStaticPolicy
	p.RequestHook = func(*http.Request) *RequestVerdict {
		panic("fuzz: hostile request hook")
	}
	p.ResponseHook = func(*http.Response) *ResponseVerdict {
		panic("fuzz: hostile response hook")
	}
	return &p
}()

// fzEvilHookPolicy is fzStaticPolicy with hooks that return verdicts built to
// smuggle a header through CR/LF. The rewriter is the last place before the
// wire (newHookRewrite's doc: "by the time it reaches the wire the only safe
// thing to do with one is not to write it"), so not one of these names may
// reach a header.
var fzEvilHookPolicy = func() *Policy {
	p := *fzStaticPolicy
	p.RequestHook = func(*http.Request) *RequestVerdict {
		return &RequestVerdict{
			Add: []string{
				"X-Evil: a\r\nInjected-Request: 1",
				"Host: evil.example\r\nInjected-Host: 1",
				"X-Fine: ok",
			},
			Remove: []string{"host", "x-forwarded-for"},
		}
	}
	p.ResponseHook = func(*http.Response) *ResponseVerdict {
		return &ResponseVerdict{
			Add:    []string{"X-Evil: a\r\nInjected-Response: 1", "X-Fine: ok"},
			Remove: []string{"content-type"},
		}
	}
	return &p
}()

// fzInjectedNames are the field names fzEvilHookPolicy tries to smuggle in.
// The comparison is against the input's own count, not against zero: arbitrary
// fuzz bytes may legitimately contain a header by one of these names, and the
// hook is only forbidden from *adding* one.
var fzInjectedNames = []string{"Injected-Request", "Injected-Host", "Injected-Response"}

// fzNoInjection checks that the hostile hook's CR/LF entries never became
// header fields. It needs both ends to be readable messages, which is exactly
// the case where the question is answerable.
func fzNoInjection(t *testing.T, what string, sd side, in, out []byte) {
	t.Helper()
	inMsg, ok := fzComplete(in, sd)
	if !ok {
		return
	}
	outMsg, ok := fzComplete(out, sd)
	if !ok {
		return // fzOneMessage has already reported this
	}
	for _, name := range fzInjectedNames {
		was, now := len(inMsg.header.Values(name)), len(outMsg.header.Values(name))
		if now > was {
			t.Fatalf("%s: a hook smuggled a header past the last line of defence: %q is on the wire %d time(s) in the output and %d in the input\ninput:  %q\noutput: %q",
				what, name, now, was, in, out)
		}
	}
}

// fzFuzzRequest is what the response-side fuzz feeds the request direction. It
// is a complete HTTP/1.1 GET that names gzip, so that the compress policy's
// skip matrix has something to accept and the transform -- the only path in the
// package that rewrites a body -- actually runs.
const fzFuzzRequest = "GET /fuzz HTTP/1.1\r\nHost: fuzz.example\r\nAccept-Encoding: gzip\r\n\r\n"

// fzCheck is one fuzz input against the whole policy matrix. sd says which
// source the fuzz bytes landed on; other is the fixed input the other direction
// gets.
func fzCheck(t *testing.T, sd side, in, other []byte) {
	t.Helper()

	reqIn, respIn := string(in), string(other)
	if sd == sideResponse {
		reqIn, respIn = string(other), string(in)
	}

	// Invariant 3: a policy that transforms nothing is the identity.
	noop := fzFinished(t, "no-op policy", fzRun(reqIn, respIn, fzNoopPolicy))
	fzNoopIdentity(t, "no-op policy, request", reqIn, string(noop.reqOut))
	fzNoopIdentity(t, "no-op policy, response", respIn, string(noop.respOut))

	// Invariants 4 and 5 with a policy that does transform.
	static := fzFinished(t, "static policy", fzRun(reqIn, respIn, fzStaticPolicy))
	fzOneMessage(t, "static policy, request", sideRequest, []byte(reqIn), static.reqOut, false)
	fzOneMessage(t, "static policy, response", sideResponse, []byte(respIn), static.respOut, true)

	// Invariant 1 for a hook that panics: recovered, and therefore invisible on
	// the wire -- with one exception, checked by name rather than waved through,
	// because it is not the hook failing that changes the bytes but the hook
	// existing at all: a head the request side cannot process (oversized, or one
	// parseHead refuses) is refused outright when a request hook is armed
	// (refuseHead), where an unarmed policy passes it through (the fail-open
	// path). The refused head can be any message of the stream, not just the
	// first, so the exception is not "the armed run forwarded nothing" but "the
	// armed run stopped where the unarmed run carried an unprocessable head
	// through" -- fzRefusedHead is where that narrowness lives. It covers the
	// whole run, so it is computed once.
	panics := fzFinished(t, "panicking hooks", fzRun(reqIn, respIn, fzPanicHookPolicy))
	refused := fzRefusedHead(t, static, panics)

	// The second exception, and it is the same shape: a connection that opens
	// with the HTTP/2 prior-knowledge preface is closed outright when any hook
	// is armed (h2Preface) -- passthrough would carry every request on it
	// straight past the hook -- where an unarmed policy passes the bytes
	// through untouched. "Closed" has one observable here, and it is stricter
	// than the 431 refusal above: nothing is forwarded and nothing is written
	// back, because an h2 visitor cannot read an HTTP/1-text error, so the
	// connection ends without an answer. The unarmed runs (noop, static) are
	// unaffected by the guard and need no exception: passing a preface through
	// is their identity or their fail-open, which the checks above already
	// cover.
	preface := fzPrefaceInput(reqIn)
	if preface {
		if len(panics.reqOut) != 0 || len(panics.respOut) != 0 {
			t.Fatalf("a connection that opened with the h2 preface was carried under armed hooks:\nwith hooks: %q / %q\nwithout:    %q / %q",
				panics.reqOut, panics.respOut, static.reqOut, static.respOut)
		}
	} else {
		if !bytes.Equal(panics.reqOut, static.reqOut) && !refused {
			t.Fatalf("a request hook that panics changed the bytes on the wire:\nwith hooks: %q\nwithout:    %q", panics.reqOut, static.reqOut)
		}
		if !bytes.Equal(panics.respOut, static.respOut) && !refused {
			t.Fatalf("a response hook that panics changed the bytes on the wire:\nwith hooks: %q\nwithout:    %q", panics.respOut, static.respOut)
		}
	}

	// Invariant 1 for a hook that tries to inject: dropped at the wire. An
	// oversized head never reaches the hook either, so the request-side one-
	// message check is skipped with the same exception (the injection check
	// needs no exemption: an empty output is not a message and it says nothing
	// about the hook, which never ran). The preface connection joins the
	// exception for the same reason its armed run above is empty: the hook is
	// never asked, and the run writes nothing.
	evil := fzFinished(t, "CRLF hooks", fzRun(reqIn, respIn, fzEvilHookPolicy))
	fzNoInjection(t, "CRLF hooks, request", sideRequest, []byte(reqIn), evil.reqOut)
	fzNoInjection(t, "CRLF hooks, response", sideResponse, []byte(respIn), evil.respOut)
	if preface {
		if len(evil.reqOut) != 0 {
			t.Fatalf("a connection that opened with the h2 preface was carried under armed hooks: %q", evil.reqOut)
		}
	} else if !refused {
		fzOneMessage(t, "CRLF hooks, request", sideRequest, []byte(reqIn), evil.reqOut, false)
	}
	fzOneMessage(t, "CRLF hooks, response", sideResponse, []byte(respIn), evil.respOut, true)
}

// --- the two fuzz targets ---------------------------------------------------

// fzReqSeeds are the request-side byte fixtures, copied out of rewriter_test.go
// (cases 1, 6, 7, 8, 9, 10, 12, 13, 14, 15 and TestMalformedChunkSizeFailsOpen)
// so that the corpus starts on the shapes the package is already known to care
// about rather than on noise.
var fzReqSeeds = []string{
	// Case 1: the default preserve policy -- order, casing and spacing survive.
	"GET /path?q=1 HTTP/1.1\r\nHost: myapp.ngrok.io\r\nuser-agent: curl/8.5.0\r\nX-Custom: keep-me\r\n\r\n",
	// Case 6: a Content-Length body with CRLFCRLF and NULs inside it.
	"POST /upload HTTP/1.1\r\nHost: a.example\r\nContent-Length: 26\r\n\r\n\x00\x01\x02\r\n\r\n\xff\xfe binary \r\n\r\n tail",
	// Case 7: chunk extension, trailers, and a second request behind them.
	"POST /chunked HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5;name=value\r\nhello\r\n6\r\n world\r\n0\r\nTrailer-One: t1\r\ntrailer-two: t2\r\n\r\n" +
		"GET /next HTTP/1.1\r\nHost: a.example\r\n\r\n",
	// Case 8: two pipelined requests.
	"GET /one HTTP/1.1\r\nHost: a.example\r\n\r\nGET /two HTTP/1.1\r\nHost: a.example\r\n\r\n",
	// Case 9: Expect: 100-continue with a body.
	"POST /e HTTP/1.1\r\nHost: a.example\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello",
	// Case 10: HEAD.
	"HEAD /h HTTP/1.1\r\nHost: a.example\r\n\r\n",
	// Case 12/13: an upgrade request, and websocket frames behind it that
	// themselves contain CRLFCRLF.
	"GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" +
		"\x81\x85\x00\x00\x00\x00hello\x88\x82\x00\x00\x00\x00\r\n\r\nraw\r\n\r\nbytes",
	// Case 14: a head past the 64 KiB cap, with bytes behind it.
	"GET / HTTP/1.1\r\nX-Big: " + fzBig + "\r\n\r\n" + "tail bytes",
	// Case 15 and TestMalformedChunkSizeFailsOpen: the streams that must not be
	// parsed at all.
	"SSH-2.0-OpenSSH_9.4\r\n\r\n",
	"GET /only-two-parts\r\nHost: a.example\r\n\r\n",
	"GET / HTTP/1.1\r\nnot a header line\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nnot hex\r\n0\r\n\r\n",
	// TestLeadingBlankLineIsTolerated.
	"\r\nGET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
	// TestChunkedWinsOverContentLength.
	"POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
}

// fzRespSeeds are the response-side fixtures (cases 6, 7, 9, 11, 12, 18 and
// TestResponseCloseDelimitedGoesRaw).
var fzRespSeeds = []string{
	// Case 6: a binary body with CRLFCRLF inside it.
	"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n\x89PNG\r\n\x1a\n\r\n\r\nmore",
	// Case 7: chunks, then a second response behind them.
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n" +
		"HTTP/1.1 204 No Content\r\n\r\n",
	// Case 9: an interim 1xx ahead of the final response.
	"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
	// Case 11: statuses that take no body whatever their framing claims.
	"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
	// Case 12: 101 plus websocket frames.
	"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" +
		"\x81\x85\x00\x00\x00\x00hello\x88\x82\x00\x00\x00\x00\r\n\r\n",
	// Case 18 territory: a compressible response the transform should take.
	"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 200\r\n\r\n" + fzRepeat,
	// TestResponseCloseDelimitedGoesRaw: no framing at all.
	"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nclose delimited body",
}

// fzBig and fzRepeat are the repeat counts the seed literals need. They are
// vars rather than inline strings.Repeat calls so that the seed list stays a
// list of literals, which is what makes it readable next to the test it was
// copied from.
var (
	fzBig    = strings.Repeat("a", 70*1024)
	fzRepeat = strings.Repeat("z", 200)
)

// FuzzRewriterRequest feeds arbitrary bytes to the request direction of a pair
// (public -> upstream) and checks the invariants at the top of this file.
func FuzzRewriterRequest(f *testing.F) {
	for _, s := range fzReqSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		fzCheck(t, sideRequest, in, nil)
	})
}

// FuzzRewriterResponse feeds arbitrary bytes to the response direction of a
// pair (upstream -> public). The request direction gets fzFuzzRequest, so that
// the response side has a real method and a real Accept-Encoding to work from
// and the compress policy is reachable.
func FuzzRewriterResponse(f *testing.F) {
	for _, s := range fzRespSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		fzCheck(t, sideResponse, in, []byte(fzFuzzRequest))
	})
}

// --- the edge matrix --------------------------------------------------------

// TestRewriterOneByteAtATime is edge (a): the same streams delivered one byte
// per Read, and handed back one byte at a time. Both shapes have to produce the
// bytes the whole-read run produced.
//
// The gzip transform is excluded from the equality for the reason feedGzip
// documents: it flushes once per source read, so its chunk boundaries follow
// the read sizes by design. The transform's own invariants are checked in
// TestRewriterByteWiseGzipFraming instead.
func TestRewriterOneByteAtATime(t *testing.T) {
	fixtures := []struct {
		name string
		req  string
		resp string
	}{
		{"preserve", fzReqSeeds[0], ""},
		{"content-length", fzReqSeeds[1], fzRespSeeds[0]},
		{"chunked", fzReqSeeds[2], fzRespSeeds[1]},
		{"pipelined", fzReqSeeds[3], fzRespSeeds[2]},
		{"expect-continue", fzReqSeeds[4], fzRespSeeds[2]},
		{"head", fzReqSeeds[5], fzRespSeeds[3]},
		{"upgrade", fzReqSeeds[6], fzRespSeeds[4]},
		{"oversized-head", fzReqSeeds[7], ""},
		{"non-http", fzReqSeeds[8], fzRespSeeds[6]},
		{"interim-then-final", fzReqSeeds[4], fzRespSeeds[3]},
	}

	policies := map[string]*Policy{
		"noop":        fzNoopPolicy,
		"static":      fzStaticNoCompressPolicy,
		"panic-hooks": fzPanicHookPolicy,
		"crlf-hooks":  fzEvilHookPolicy,
	}

	for _, fx := range fixtures {
		for pname, p := range policies {
			t.Run(fx.name+"/"+pname, func(t *testing.T) {
				whole := fzFinished(t, "whole reads", fzRun(fx.req, fx.resp, p))
				byteWise := fzFinished(t, "byte-wise reads", fzRunOpts(fx.req, fx.resp, p, fzOptions{byteWise: true}))
				if !bytes.Equal(whole.reqOut, byteWise.reqOut) {
					t.Fatalf("the request output depends on the read sizes\nwhole: %q\nbyte:  %q", whole.reqOut, byteWise.reqOut)
				}
				if !bytes.Equal(whole.respOut, byteWise.respOut) {
					t.Fatalf("the response output depends on the read sizes\nwhole: %q\nbyte:  %q", whole.respOut, byteWise.respOut)
				}
				// ...and the one-byte caller buffer has to produce them too: a
				// step that only works when the caller asks for 32 KiB at once
				// is a step that is not actually driving the machine.
				oneOut := fzFinished(t, "one-byte output buffer",
					fzRunOpts(fx.req, fx.resp, p, fzOptions{byteWise: true, outBuf: 1}))
				if !bytes.Equal(whole.reqOut, oneOut.reqOut) || !bytes.Equal(whole.respOut, oneOut.respOut) {
					t.Fatalf("the output depends on the caller's buffer size\nwhole: %q\none:   %q", whole.reqOut, oneOut.reqOut)
				}
			})
		}
	}
}

// TestRewriterByteWiseGzipFraming: the transform is allowed to pick different
// chunk boundaries per read size, but not to break its framing, and its body
// contract has to hold however the source was cut up.
func TestRewriterByteWiseGzipFraming(t *testing.T) {
	body := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 64)
	resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
		fmt.Sprint(len(body)) + "\r\n\r\n" + body

	for _, opt := range []fzOptions{{}, {byteWise: true}, {byteWise: true, outBuf: 1}, {outBuf: 1}} {
		got := fzFinished(t, "gzip framing", fzRunOpts(fzFuzzRequest, resp, fzStaticPolicy, opt))
		fzOneMessage(t, "gzip framing, response", sideResponse, []byte(resp), got.respOut, true)
		if !bytes.Contains(got.respOut, []byte("Content-Encoding: gzip")) {
			t.Fatalf("the transform did not run on a compressible response the client asked for gzip on: %q", got.respOut)
		}
	}
}

// TestRewriterTransferEncodingWinsOverContentLength is edge (b). The bytes
// cannot show which framing was used -- both readings copy every byte, one of
// them by failing open -- so the phase is what has to be looked at, which is
// the claim nextPhase's comment makes.
//
// (TestChunkedWinsOverContentLength in rewriter_test.go already checks that the
// bytes and the second request survive; this checks the phase itself.)
func TestRewriterTransferEncodingWinsOverContentLength(t *testing.T) {
	const req = "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n" +
		"GET /after HTTP/1.1\r\nHost: a\r\n\r\n"

	reqR, respR := NewPair(strings.NewReader(req), strings.NewReader(""), fzNoopPolicy)
	r := reqR.(*streamRewriter)

	buf := make([]byte, 4096)
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("reading the first head failed: %v", err)
	}
	if r.phase != stChunkSize {
		t.Fatalf("a message with both Content-Length and Transfer-Encoding was framed as %v, not chunked; "+
			"reading the Content-Length instead would desync the connection", r.phase)
	}

	// Draining the rest still has to produce the input: the second request is
	// parsed as a head rather than swallowed as body.
	if _, err := io.Copy(io.Discard, reqR); err != nil {
		t.Fatalf("draining after the phase check failed: %v", err)
	}
	if _, err := io.Copy(io.Discard, respR); err != nil {
		t.Fatalf("draining the response side failed: %v", err)
	}
	got := fzFinished(t, "both framings", fzRun(req, "", fzStaticPolicy))
	if n := bytes.Count(got.reqOut, []byte("GET /after")); n != 1 {
		t.Fatalf("the pipelined request behind a dual-framed body was not passed through once: %d occurrences in %q", n, got.reqOut)
	}

	// The response half: with the transform on, the head may declare one
	// framing and one length only, and both have to describe what follows.
	//
	// The body is over minCompressBytes on purpose: a declared body below it is
	// not worth re-framing (gzip's own header and trailer are 18 bytes), so a
	// five-byte fixture would take the identity path and prove nothing about
	// the dual-framing case.
	body := strings.Repeat("x", 200)
	dual := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 200\r\nTransfer-Encoding: chunked\r\n\r\n" +
		fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
	out := fzFinished(t, "dual-framed response", fzRun(fzFuzzRequest, dual, fzStaticPolicy))
	if !bytes.Contains(out.respOut, []byte("Content-Encoding: gzip")) {
		t.Fatalf("the transform declined a dual-framed compressible response: %q", out.respOut)
	}
	fzOneMessage(t, "dual-framed response", sideResponse, []byte(dual), out.respOut, true)
	if n := bytes.Count(out.respOut, []byte("Content-Length")); n != 0 {
		t.Fatalf("a compressed response still declares a Content-Length that describes the bytes it replaced: %q", out.respOut)
	}
	if n := bytes.Count(out.respOut, []byte("Transfer-Encoding: chunked")); n != 1 {
		t.Fatalf("a compressed response declares the chunked framing %d times: %q", n, out.respOut)
	}
}

// TestHostRewriteDoesNotInjectCRLF is edge (c), end to end.
//
// A HostHeader value carrying a CR/LF is the classic header-splitting shape:
// rewriteRequestHead writes it with appendFieldValue / appendHeaderLine
// straight into a field line. Policy.Validate rejects exactly that value, so
// the property holds *if Validate ran*.
//
// When this test was written, nothing in the repository called Validate(): the
// live path was client/headers.go's policyFromTunnel, a field copy, and the
// guard that actually ran was client/config.go's own validateHostHeader -- a
// second copy of the rules, which is the finding the fuzzing report carries as
// R1. The fix is that client/config.go's loader now builds the same rewriter.Policy
// it would run and calls Validate() on it, so the gate below is the gate a
// tunnel config has to pass. The test still pins both halves: that Validate
// rejects the value, and what the wire looks like when a caller skips it --
// because "someone wired the gate up" is a property of today's callers, and the
// second half is what stops the next caller from making it untrue.
func TestHostRewriteDoesNotInjectCRLF(t *testing.T) {
	evil := "evil.example\r\nInjected-Host: 1"

	if err := (&Policy{HostHeader: evil}).Validate(); err == nil {
		t.Fatalf("Policy.Validate accepted a host_header value carrying CR/LF: %q", evil)
	}

	const req = "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"

	// The add-entry path, which does carry its own guard (compileAdds drops an
	// entry whose value has a CR or LF, Validate or not).
	adds := &Policy{RequestHeaderAdd: []string{"X-Evil: a\r\nInjected-Add: 1", "X-Fine: ok"}}
	got := fzFinished(t, "crlf add entry", fzRun(req, "", adds))
	if bytes.Contains(got.reqOut, []byte("Injected-Add")) {
		t.Fatalf("an add entry carrying CR/LF reached the wire: %q", got.reqOut)
	}
	if !bytes.Contains(got.reqOut, []byte("X-Fine: ok")) {
		t.Fatalf("the usable entry beside it was dropped too: %q", got.reqOut)
	}

	// The host_header path, which does not.
	host := &Policy{HostHeader: evil}
	got = fzFinished(t, "crlf host_header", fzRun(req, "", host))
	m, err := fzReadHTTP(got.reqOut, sideRequest)
	if err != nil {
		t.Fatalf("reading the rewritten request failed: %v", err)
	}
	if m.header.Get("Injected-Host") != "1" {
		t.Logf("host_header %q no longer reached the wire: %q", evil, got.reqOut)
		return
	}
	t.Logf("FINDING (R1): a caller that skips Policy.Validate gets a header split out of the "+
		"host_header value. Requests rewritten from %q carry two fields:\n%q", req, got.reqOut)
}

// TestRewriterObsoleteLineFolding is edge (d). RFC 7230 removed obs-fold
// outside trailers; parseHeaderField rejects a continuation line rather than
// guessing where the value ends, so the head fails open and the bytes are the
// input's -- for every policy, including one that would otherwise rewrite it.
//
// The residual risk is not in this package: the bytes are forwarded verbatim,
// so an upstream that still accepts obs-fold may read a field the rewriter
// never saw. That is a differential, not a dropped byte, and fail-open is the
// documented answer to it.
func TestRewriterObsoleteLineFolding(t *testing.T) {
	cases := []string{
		"GET / HTTP/1.1\r\nHost: a.example\r\nX-Fold: one\r\n two\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: a.example\r\nX-Fold: one\r\n\ttwo\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Fold: one\r\n two\r\n\r\nhi",
	}
	for _, in := range cases {
		sd, other := sideRequest, ""
		if strings.HasPrefix(in, "HTTP/") {
			sd, other = sideResponse, fzFuzzRequest
			out := fzFinished(t, "obs-fold response", fzRun(other, in, fzStaticPolicy))
			fzNoopIdentity(t, "obs-fold response, static policy", in, string(out.respOut))
			continue
		}
		out := fzFinished(t, "obs-fold request", fzRun(in, other, fzStaticPolicy))
		fzNoopIdentity(t, "obs-fold request, static policy", in, string(out.reqOut))
		_ = sd
	}
}

// TestRewriterUnterminatedHeadIsForwarded is edge (e): the peer closed in the
// middle of a head. The connection is over either way, but every byte it sent
// has to come out, and it has to come out in order.
func TestRewriterUnterminatedHeadIsForwarded(t *testing.T) {
	// Per direction: exact says the direction never assembles a complete head
	// and therefore has to come out byte-identical even under the static
	// policy; tail is the unterminated part of an input whose earlier heads
	// *were* complete, and it has to survive verbatim at the end of the output.
	cases := []struct {
		name              string
		req, resp         string
		reqExact          bool
		respExact         bool
		reqTail, respTail string
	}{
		{"head-open", "GET / HTTP/1.1\r\nHost: a\r\nX-Last: 1\r\n", "", true, true, "", ""},
		{"one-field", "GET / HTTP/1.1\r\n", "", true, true, "", ""},
		{"no-terminator", "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /two HTTP/1.1\r\nHost: b", "", false, true, "GET /two HTTP/1.1\r\nHost: b", ""},
		{"chunk-cut", "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab", "", false, true, "3\r\nab", ""},
		{"response-head-open", fzFuzzRequest, "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n", false, true, "", ""},
		{"response-body-cut", fzFuzzRequest, "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort", false, false, "", "short"},
		{"response-mid-chunk", fzFuzzRequest, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwi", false, false, "", "4\r\nwi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Whatever else happens, a policy that transforms nothing is the
			// identity -- truncation included.
			noop := fzFinished(t, tc.name+" no-op", fzRun(tc.req, tc.resp, fzNoopPolicy))
			fzNoopIdentity(t, tc.name+" request, no-op policy", tc.req, string(noop.reqOut))
			fzNoopIdentity(t, tc.name+" response, no-op policy", tc.resp, string(noop.respOut))

			out := fzFinished(t, tc.name+" static", fzRun(tc.req, tc.resp, fzStaticPolicy))
			for _, d := range []struct {
				what  string
				sd    side
				in    string
				out   []byte
				exact bool
				tail  string
			}{
				{"request", sideRequest, tc.req, out.reqOut, tc.reqExact, tc.reqTail},
				{"response", sideResponse, tc.resp, out.respOut, tc.respExact, tc.respTail},
			} {
				if d.in == "" {
					continue
				}
				if d.exact {
					fzNoopIdentity(t, tc.name+" "+d.what+", static policy", d.in, string(d.out))
					continue
				}
				if d.tail != "" && !bytes.HasSuffix(d.out, []byte(d.tail)) {
					t.Fatalf("%s %s: the unterminated tail %q was not forwarded verbatim\noutput: %q",
						tc.name, d.what, d.tail, d.out)
				}
				// The heads before the truncation were complete, so the
				// truncation may not have damaged them either.
				fzOneMessage(t, tc.name+" "+d.what+", static policy", d.sd, []byte(d.in), d.out, d.sd == sideResponse)
			}
		})
	}
}

// TestRewriterHeadSizeBoundary is edge (f): the exact byte where a head stops
// being a head. One byte under the cap is parsed and rewritten; one byte over
// it fails open and the connection is copied raw.
func TestRewriterHeadSizeBoundary(t *testing.T) {
	// len("GET / HTTP/1.1\r\nHost: a\r\nX-Big: ") == 31, plus the value, plus
	// the "\r\n\r\n" that ends the head.
	const headPrefix = "GET / HTTP/1.1\r\nHost: a\r\nX-Big: "
	build := func(total int) string {
		return headPrefix + strings.Repeat("a", total-len(headPrefix)-4) + "\r\n\r\n"
	}

	atCap := build(maxHeadBytes)
	if len(atCap) != maxHeadBytes {
		t.Fatalf("fixture is %d bytes, wanted %d", len(atCap), maxHeadBytes)
	}
	out := fzFinished(t, "head at the cap", fzRun(atCap, "", fzStaticPolicy))
	if !bytes.Contains(out.reqOut, []byte("X-Injected: yes")) {
		t.Fatalf("a head of exactly %d bytes was not rewritten: %q", maxHeadBytes, out.reqOut)
	}

	overCap := build(maxHeadBytes + 1)
	if len(overCap) != maxHeadBytes+1 {
		t.Fatalf("fixture is %d bytes, wanted %d", len(overCap), maxHeadBytes+1)
	}
	out = fzFinished(t, "head over the cap", fzRun(overCap, "", fzStaticPolicy))
	fzNoopIdentity(t, "head over the cap", overCap, string(out.reqOut))

	// A single line past the read buffer trips the line check rather than the
	// head check, one buffer earlier.
	longLine := "GET / HTTP/1.1\r\nHost: a\r\nX-Big: " + strings.Repeat("a", readBufferSize) + "\r\n\r\n"
	out = fzFinished(t, "line over the buffer", fzRun(longLine, "", fzStaticPolicy))
	fzNoopIdentity(t, "line over the buffer", longLine, string(out.reqOut))

	// ...and a head that is over the cap only because it has many lines still
	// fails open rather than being truncated.
	var many strings.Builder
	many.WriteString("GET / HTTP/1.1\r\nHost: a\r\n")
	for many.Len() < maxHeadBytes+64 {
		many.WriteString("X-Filler: x\r\n")
	}
	many.WriteString("\r\n")
	out = fzFinished(t, "many lines over the cap", fzRun(many.String(), "", fzStaticPolicy))
	fzNoopIdentity(t, "many lines over the cap", many.String(), string(out.reqOut))
}

// --- the one flake this pass did not resolve --------------------------------

// fzFlakeInput is the corpus entry the fuzzer wrote during the timed
// FuzzRewriterResponse run: rewriter/testdata/fuzz/FuzzRewriterResponse/dc224d9c3a3a3d22.
// It is quoted here so that the stress test below is self-contained and so that
// the entry itself can be read next to the test that exercises it.
//
// Its shape is worth a look, because it is not random junk: the head uses bare
// LF line endings ("HTTP/1.1 200\n", not "\r\n"), the field name is spelled in
// mixed case ("Content-TYpe"), the value is unterminated-looking ("teXt/"), and
// the body is four high bytes followed by 180 'z's with no Content-Length and no
// Transfer-Encoding -- so the body is close-delimited. Every one of those is a
// decision point in the head parser, and the entry is what the fuzzer minimized
// down to after hitting one of them.
var fzFlakeInput = "HTTP/1.1 200\nContent-TYpe:teXt/\n\n\x9e\xbc\xbe\xee" +
	strings.Repeat("z", 180)

// TestRewriterFlakeInputIsStable is the diagnostic for that entry. The entry
// passes when re-run on its own (go test -run=FuzzRewriterResponse/dc224d9c3a3a3d22)
// and the fuzz target has since run another ~3.9M executions without a
// recurrence, so what it caught is not a deterministic property of the input --
// but "it went away" is not an explanation, and leaving one without looking is
// how a real hang gets forgotten.
//
// What this test can do that re-running the corpus entry cannot is run the same
// pair many times in one process, concurrently, and report the *drain time*
// distribution. The only time-dependent thing in the harness is the watchdog in
// fzRunOpts (fzDrainTimeout, 5s), and the only way that fires on a 200-byte
// in-memory input is if a drain is not making progress. So the measurement that
// distinguishes "the watchdog fired because a drain stalled" from "something
// else" is whether a drain ever takes a long time here.
//
// The assertion is deliberately loose (a whole second for a 200-byte drain) and
// the reason is in the numbers it prints: the point is to catch a stall, not to
// measure this machine.
func TestRewriterFlakeInputIsStable(t *testing.T) {
	const rounds = 2000

	var (
		slowest time.Duration
		slow    fzRunResult
	)
	start := time.Now()
	for i := 0; i < rounds; i++ {
		t0 := time.Now()
		got := fzRun(fzFuzzRequest, fzFlakeInput, fzStaticPolicy)
		d := time.Since(t0)
		if d > slowest {
			slowest, slow = d, got
		}
	}
	t.Logf("%d runs of the corpus entry in %s, slowest drain %s", rounds, time.Since(start), slowest)
	if slowest > time.Second {
		t.Errorf("a drain of a %d-byte input took %s, which is the shape of the interruptible window the 5s watchdog sits in: the watchdog is the flake, and the entry is not a product bug. Slow result: %+v", len(fzFlakeInput), slowest, slow)
	}

	// The result itself must be the same every time: this is the property the
	// fuzz target asserts, and it is what would fail if the rewriter had state
	// that carried between pairs in one process.
	first := fzRun(fzFuzzRequest, fzFlakeInput, fzStaticPolicy)
	for i := 0; i < 200; i++ {
		got := fzRun(fzFuzzRequest, fzFlakeInput, fzStaticPolicy)
		if !bytes.Equal(got.respOut, first.respOut) {
			t.Fatalf("round %d produced different bytes for the same pair:\nfirst: %q\ngot:   %q", i, first.respOut, got.respOut)
		}
	}

	// And the output must still be a complete, net/http-readable message: the
	// fuzz target's invariant 4, asserted here for this input specifically so
	// that the corpus entry is not merely "a file that exists".
	if _, ok := fzComplete([]byte(fzFlakeInput), sideResponse); !ok {
		t.Fatalf("the fixture is no longer one complete message net/http can read; this test and the corpus entry need to be re-derived")
	}
	fzOneMessage(t, "the flake entry", sideResponse, []byte(fzFlakeInput), first.respOut, true)

	// The other half of the question: if the watchdog fired because a drain
	// stalled, the stall was not special to this entry -- so measure the seed
	// corpus and the read shapes as well. The ceiling is 2s against a 5s
	// watchdog: high enough that a busy machine cannot trip it, low enough that
	// a real stall cannot hide under it.
	var (
		worst time.Duration
		which string
	)
	measure := func(what, reqIn, respIn string, opt fzOptions) {
		t0 := time.Now()
		fzFinished(t, what, fzRunOpts(reqIn, respIn, fzStaticPolicy, opt))
		if d := time.Since(t0); d > worst {
			worst, which = d, what
		}
	}
	for _, s := range fzReqSeeds {
		for _, opt := range []fzOptions{{}, {byteWise: true}, {outBuf: 1}} {
			measure("request seed", s, fzFuzzRequest, opt)
		}
	}
	for _, s := range fzRespSeeds {
		for _, opt := range []fzOptions{{}, {byteWise: true}, {outBuf: 1}} {
			measure("response seed", fzFuzzRequest, s, opt)
		}
	}
	// The flake input under the byte-wise shape, which takes the most
	// state-machine steps per byte and is therefore the most expensive way to
	// feed it, and under a one-byte output buffer.
	measure("the flake entry, byte-wise", fzFuzzRequest, fzFlakeInput, fzOptions{byteWise: true})
	measure("the flake entry, 1-byte out buffer", fzFuzzRequest, fzFlakeInput, fzOptions{outBuf: 1})
	t.Logf("slowest drain over the seed corpus: %s (%s); watchdog is %s", worst, which, fzDrainTimeout)
	if worst > 2*time.Second {
		t.Errorf("a drain of an in-memory seed took %s (%s): the watchdog at %s is no longer the margin it was meant to be", worst, which, fzDrainTimeout)
	}
}
