package server

// Event export (SPEC-CLUSTER9 §4): ship the event hub's stream to configured
// destinations instead of leaving it reachable only through the /events SSE
// endpoint.
//
// The shape is copied from the KeenIoMetrics writer (metrics.go:177-257),
// which is the codebase's one precedent for "bounded queue + single drain
// goroutine + batched flush": each destination subscribes to the hub with a
// 1000-slot queue, and exactly one goroutine per destination drains it --
// batching for http (batch_size / flush_interval), one line per event for
// jsonl. Every blocking operation (the POST, the file write, the retry
// backoff) happens on the drain goroutine only, so the hub's publish path --
// a non-blocking select/default into the subscription queues -- can never
// block on a destination, whatever state the destination is in. When a
// destination cannot drain, its queue fills and the hub's drop branch counts
// the loss; that counter in /metrics is the operator's signal, which is why
// the queue overflows by design instead of growing.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"ngrok/policy"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ngrok/log"
)

const (
	// eventExportQueueCap is each destination's queue size: the KeenIoMetrics
	// precedent (metrics.go). Fixed, not configurable -- see
	// subscribeBuffered for the reasoning.
	eventExportQueueCap = 1000

	// Defaults for the optional http keys; applied in newHTTPDestination so
	// the config struct can stay a faithful image of the file.
	defaultEventBatchSize   = 100
	defaultEventFlushEvery  = 5 * time.Second
	defaultEventHTTPTimeout = 10 * time.Second

	// Retry backoff for a failing destination. Both are fields on the
	// destination (overridable by tests) rather than config keys: an operator
	// tuning retry timing is tuning around a problem that should have shown
	// up as drop counters, and the cap keeps a dead collector from
	// monopolizing the drain goroutine any more than it already does.
	eventRetryBackoffStart = 500 * time.Millisecond
	eventRetryBackoffMax   = 10 * time.Second
)

// eventDestination is one configured exporter. The interface is what /metrics
// surfaces (admin.go) plus the drain loop; the delivery mechanics are private
// to each implementation's single goroutine.
type eventDestination interface {
	// run is the drain goroutine's body. It exits when stop has closed the
	// subscription queue, after flushing whatever it still holds.
	run()
	// kind is the config "type" ("http", "jsonl").
	kind() string
	// target is where events go: the url or the file path, for /metrics.
	target() string
	// droppedCount is events this destination lost: queue overflow counted by
	// the hub on its subscription, plus (jsonl only) lines a failing file
	// could not take. See each implementation.
	droppedCount() uint64
	// queueDepth is how many events are buffered waiting for the drain
	// goroutine; a value parked near the cap is a destination about to drop.
	queueDepth() int
	// stop unsubscribes the destination from its hub, which closes its queue.
	stop()
}

var (
	exportMu    sync.Mutex
	exportDests []eventDestination
)

// startEventExport builds and starts one destination per config entry against
// the process-wide hub. Called once from Main, before any listener starts, so
// the first tunnel_open already has somewhere to go. Config load has already
// validated every entry (config.go validateEventDestinations), so a
// construction error here is a bug, not bad input: it is logged and the other
// destinations still start, because losing one exporter must not lose the
// server.
func startEventExport(cfgs []eventDestinationConfig) {
	for _, c := range cfgs {
		var d eventDestination
		var err error
		switch c.Type {
		case "http":
			d, err = newHTTPDestination(c, observe.events)
		case "jsonl":
			d, err = newJSONLDestination(c, observe.events)
		default:
			// validateEventDestinations refuses anything else; this arm
			// documents that startEventExport trusts its caller.
			err = fmt.Errorf("unknown type %q", c.Type)
		}
		if err != nil {
			log.Error("Failed to start event destination %s (%s): %v", destinationLabel(c), c.Type, err)
			continue
		}
		exportMu.Lock()
		exportDests = append(exportDests, d)
		exportMu.Unlock()
		log.Info("Exporting events to %s destination %s", d.kind(), d.target())
		go d.run()
	}
}

func destinationLabel(c eventDestinationConfig) string {
	if c.URL != "" {
		return c.URL
	}
	return c.Path
}

// exportedDestinationStats is the event_destinations section of the /metrics
// payload: one row per destination, with its loss and backlog counters.
func exportedDestinationStats() []map[string]interface{} {
	exportMu.Lock()
	dests := append([]eventDestination(nil), exportDests...)
	exportMu.Unlock()

	out := make([]map[string]interface{}, 0, len(dests))
	for _, d := range dests {
		out = append(out, map[string]interface{}{
			"type":        d.kind(),
			"target":      d.target(),
			"dropped":     d.droppedCount(),
			"queue_depth": d.queueDepth(),
		})
	}
	return out
}

// stopEventExport exists for tests; Main never stops destinations because it
// never stops anything else either (the process exits on signal).
func stopEventExport() {
	exportMu.Lock()
	dests := exportDests
	exportDests = nil
	exportMu.Unlock()
	for _, d := range dests {
		d.stop()
	}
}

// ---------------------------------------------------------------------------
// http destination

type httpDestination struct {
	url string

	// The auth header as a name/value pair, split at construction so the hot
	// path does no string work. The value is held in memory for the life of
	// the process and never logged (failures log the url and the error, never
	// the request). Vault composition happens upstream: secret("vault/...")
	// values arrive here already resolved, as literals, per the composition
	// point note in config.go.
	headerName  string
	headerValue string

	batchSize  int
	flushEvery time.Duration

	// retryStart/retryMax shape the exponential backoff; the queue keeps
	// filling while deliver sleeps, which is exactly how a failing
	// destination degrades into drop-counter signal instead of blocking
	// anyone.
	retryStart time.Duration
	retryMax   time.Duration

	client *http.Client

	sub         *eventSubscription
	hub         *eventHub
	failSampler *logSampler
	logger      log.Logger
}

// newHTTPDestination parses one validated config entry.
func newHTTPDestination(c eventDestinationConfig, hub *eventHub) (*httpDestination, error) {
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, fmt.Errorf("url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("url scheme must be http or https, got %q", u.Scheme)
	}

	batchSize := c.BatchSize
	if batchSize == 0 {
		batchSize = defaultEventBatchSize
	}
	flushEvery := defaultEventFlushEvery
	if c.FlushInterval != "" {
		if flushEvery, err = time.ParseDuration(c.FlushInterval); err != nil {
			return nil, fmt.Errorf("flush_interval: %v", err)
		}
	}

	d := &httpDestination{
		url:         c.URL,
		batchSize:   batchSize,
		flushEvery:  flushEvery,
		retryStart:  eventRetryBackoffStart,
		retryMax:    eventRetryBackoffMax,
		client:      &http.Client{Timeout: defaultEventHTTPTimeout},
		sub:         hub.subscribeBuffered(eventExportQueueCap),
		hub:         hub,
		failSampler: newLogSampler(30 * time.Second),
		logger:      log.NewPrefixLogger("events"),
	}
	if c.AuthHeader != "" {
		name, value, _ := strings.Cut(c.AuthHeader, ":")
		d.headerName = strings.TrimSpace(name)
		// The value may be a whole-value secret("vault/key") reference into
		// the server's vaults (SPEC-CLUSTER9 4.2): resolve it here, at
		// construction, against the set loadServerVaults installed -- the
		// one moment the plaintext must exist, held by this destination and
		// never logged. An unresolved reference would otherwise travel to
		// the collector as a literal header value, which is a credential
		// leak to the one place that must not see it.
		resolved, err := policy.ResolveSecretRef(strings.TrimSpace(value))
		if err != nil {
			d.stop()
			return nil, fmt.Errorf("event destination %s: auth_header: %v", c.Type, err)
		}
		d.headerValue = resolved
	}
	return d, nil
}

func (d *httpDestination) kind() string    { return "http" }
func (d *httpDestination) target() string  { return d.url }
func (d *httpDestination) queueDepth() int { return len(d.sub.ch) }

// droppedCount: the batch is never abandoned -- deliver retries until the
// collector answers -- so the only events this destination loses are the ones
// the hub dropped on its full queue.
func (d *httpDestination) droppedCount() uint64 { return d.sub.dropped.Load() }

func (d *httpDestination) stop() { d.hub.unsubscribe(d.sub) }

// run is the destination's single drain goroutine. It is the KeenIoMetrics
// loop (metrics.go:195-222) with two changes the event stream needs: the
// batch is a JSON array of the hub's pre-marshaled payloads (publish already
// paid for the marshal once -- re-marshaling through interface{} would pay
// twice for every event), and a failed POST retries with backoff instead of
// dropping the batch.
func (d *httpDestination) run() {
	ticker := time.NewTicker(d.flushEvery)
	defer ticker.Stop()

	batch := make([][]byte, 0, d.batchSize)
	for {
		select {
		case payload, ok := <-d.sub.ch:
			if !ok {
				// stop() closed the queue: flush what is buffered and exit.
				if len(batch) > 0 {
					d.deliver(batch)
				}
				return
			}
			batch = append(batch, payload)
			if len(batch) >= d.batchSize {
				d.deliver(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				d.deliver(batch)
				batch = batch[:0]
			}
		}
	}
}

// deliver POSTs one batch, retrying with capped exponential backoff until the
// collector accepts it. Retrying forever is a deliberate reading of
// SPEC-CLUSTER9 §4.2 ("a permanently failing destination backs off ... never
// blocks the hub"): the batch is never abandoned, because the alternative --
// give up after N attempts -- silently loses events that the queue/drop
// counters exist to account for. While deliver sleeps, the queue fills and
// drops, which is the observable cost of the dead collector.
func (d *httpDestination) deliver(batch [][]byte) {
	body := marshalEventBatch(batch)
	failing := false
	delay := d.retryStart
	for attempts := 1; ; attempts++ {
		err := d.post(body)
		if err == nil {
			if failing {
				d.logger.Info("Event destination %s recovered after %d failed attempts", d.url, attempts-1)
			}
			return
		}
		// The first failure of a failing stretch logs unconditionally (that
		// is the state change an operator needs to have seen); the ones after
		// go through the same sampler as the connection warn paths
		// (sampler.go): 3 per window, then every 50th.
		if !failing || d.failSampler.allow("events:"+d.url) {
			d.logger.Error("Event destination %s failed (attempt %d): %v", d.url, attempts, err)
		}
		failing = true

		time.Sleep(delay)
		delay *= 2
		if delay > d.retryMax {
			delay = d.retryMax
		}
	}
}

func (d *httpDestination) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.headerName != "" {
		req.Header.Set(d.headerName, d.headerValue)
	}
	req.ContentLength = int64(len(body))

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain the body so the connection returns to the pool.
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("collector returned %s", resp.Status)
	}
	return nil
}

// marshalEventBatch joins the pre-marshaled event payloads into a JSON array.
// The payloads are trusted (the hub produced them), so this is byte surgery
// rather than a decode/encode round trip.
func marshalEventBatch(payloads [][]byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, p := range payloads {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(p)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// jsonl destination

type jsonlDestination struct {
	path string

	// mu guards file: the drain goroutine reads and replaces it, and a test
	// may close it underneath to simulate the handle going bad (the
	// log-rotation case the reopen path exists for).
	mu   sync.Mutex
	file *os.File

	// lostWrite counts lines that could not be appended even after a reopen
	// attempt, or that arrived while the reopen backoff held. It joins the
	// hub's queue-overflow count in droppedCount: one number per destination,
	// "events lost here", whatever the mechanism.
	lostWrite atomic.Uint64

	sub         *eventSubscription
	hub         *eventHub
	failSampler *logSampler
	logger      log.Logger

	// retryStart is the minimum spacing between open attempts, so a missing
	// directory cannot turn a flood of events into a flood of ENOENTs. The
	// events that arrive within the spacing are counted lost.
	retryStart time.Duration

	// lastAttempt is when the drain goroutine last tried to open the file.
	lastAttempt time.Time
}

func newJSONLDestination(c eventDestinationConfig, hub *eventHub) (*jsonlDestination, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	return &jsonlDestination{
		path:        c.Path,
		sub:         hub.subscribeBuffered(eventExportQueueCap),
		hub:         hub,
		failSampler: newLogSampler(30 * time.Second),
		logger:      log.NewPrefixLogger("events"),
		retryStart:  eventRetryBackoffStart,
	}, nil
}

func (d *jsonlDestination) kind() string    { return "jsonl" }
func (d *jsonlDestination) target() string  { return d.path }
func (d *jsonlDestination) queueDepth() int { return len(d.sub.ch) }

func (d *jsonlDestination) droppedCount() uint64 {
	return d.sub.dropped.Load() + d.lostWrite.Load()
}

func (d *jsonlDestination) stop() { d.hub.unsubscribe(d.sub) }

// run is the destination's single drain goroutine. No batching: jsonl's value
// is that a tail -f (or a log shipper) sees each event as it happens, so the
// line is written the moment the event arrives. The hub's pre-marshaled
// payload is appended verbatim -- the file is a valid JSON-lines image of the
// /events stream by construction.
func (d *jsonlDestination) run() {
	for payload := range d.sub.ch {
		d.writeLine(payload)
	}
}

// writeLine appends one event as one line. Two attempts, not a retry loop: the
// cached handle, and then -- if that write failed -- one fresh open (the
// reopen-on-failure path; the file is only useful when there is an event to
// put in it, so the reopen rides the event instead of a timer). If both fail
// the line is counted lost, which is what droppedCount promises an operator.
func (d *jsonlDestination) writeLine(payload []byte) {
	line := make([]byte, 0, len(payload)+1)
	line = append(line, payload...)
	line = append(line, '\n')

	for attempt := 0; attempt < 2; attempt++ {
		f := d.fileForWrite()
		if f == nil {
			// openFile already logged the failure and spaces its attempts;
			// this event is the cost.
			d.lostWrite.Add(1)
			return
		}
		if _, err := f.Write(line); err == nil {
			return
		} else {
			d.logFailure("write %s: %v", d.path, err)
			// The handle is suspect (rotation, ENOSPC, a closed fd
			// underneath us): drop it so the next attempt pays a fresh open.
			d.abandon(f)
		}
	}
	d.lostWrite.Add(1)
}

// abandon closes f and forgets it, unless the drain goroutine has already
// swapped in a different handle (a test forcing the reopen path can close the
// old one out from under us).
//
// It also clears lastAttempt: that spacing exists to keep a missing directory
// from turning a flood of events into a flood of failed OPENS, but a write
// failing on a handle we had successfully opened is different evidence -- the
// handle died under us (rotation, ENOSPC) and the fresh open is the recovery
// step, not part of any flood. Throttling it here meant a recreated file
// waited out the full window before coming back.
func (d *jsonlDestination) abandon(f *os.File) {
	d.mu.Lock()
	if d.file == f {
		_ = f.Close()
		d.file = nil
	}
	d.lastAttempt = time.Time{}
	d.mu.Unlock()
}

// fileForWrite returns the cached handle, opening the file if a previous
// failure nil'd it. Open attempts are spaced retryStart apart; within the
// spacing the caller's event is counted lost rather than buffered, because a
// jsonl destination that cannot open its file has nowhere to buffer to except
// memory it will never get credit for.
func (d *jsonlDestination) fileForWrite() *os.File {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file != nil {
		return d.file
	}
	now := time.Now()
	if !d.lastAttempt.IsZero() && now.Sub(d.lastAttempt) < d.retryStart {
		return nil
	}
	d.lastAttempt = now
	// O_APPEND is the whole file format: the kernel re-seeks to end on every
	// write, so concurrent writers cannot interleave a partial line. No
	// O_TRUNC: a destination that survives a restart must not erase the log
	// it is restarting into.
	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		d.logFailure("open %s: %v", d.path, err)
		return nil
	}
	d.logger.Info("Event destination %s opened", d.path)
	d.file = f
	return f
}

// logFailure samples the failing stretch: 3 per window, then every 50th, the
// same sampler the connection warn paths use (sampler.go). The recovery side
// does not need sampling -- "opened" is rare by definition.
func (d *jsonlDestination) logFailure(format string, args ...interface{}) {
	if d.failSampler.allow("events:" + d.path) {
		d.logger.Error("Event destination "+format, args...)
	}
}
