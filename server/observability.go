package server

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

type tunnelSnapshot struct {
	URL               string    `json:"url"`
	Protocol          string    `json:"protocol"`
	StartedAt         time.Time `json:"started_at"`
	ActiveConnections int64     `json:"active_connections"`
	TotalConnections  int64     `json:"total_connections"`
	BytesIn           int64     `json:"bytes_in"`
	BytesOut          int64     `json:"bytes_out"`
}

type observabilityStore struct {
	mu      sync.RWMutex
	started time.Time
	tunnels map[string]*tunnelSnapshot
	events  *eventHub
	history []metricsPoint
}

type metricsPoint struct {
	At                 time.Time `json:"at"`
	PublicConnections  int64     `json:"public_connections"`
	ControlConnections int64     `json:"control_connections"`
	TunnelsActive      int64     `json:"tunnels_active"`
	PublicConnOpened   uint64    `json:"public_conn_open_total"`
	RateDropCount      uint64    `json:"rate_drop_count"`
	AuthRejectCount    uint64    `json:"auth_reject_count"`
}

// The event stream is the /events SSE endpoint's payload: one JSON object per
// event, the type in its "type" field.
//
// Every event is a typed struct with a constant type name, and the fields an
// event carries are declared with it, because both the type and the shape are
// part of an admin consumer's API. A hand-written map literal at each publish
// site -- which is what these were -- makes a typo in a type name ("rate_limit_dropped")
// a silent change to that API and leaves the shape of an event discoverable
// only by reading every call site. Here a typo is a compile error, the set of
// event types is one const block, and the scope and reason values a consumer
// switches on cannot drift either.
const (
	eventTunnelOpen        = "tunnel_open"
	eventTunnelClose       = "tunnel_close"
	eventConnectionClose   = "connection_close"
	eventAuthReject        = "auth_reject"
	eventRateLimitDrop     = "rate_limit_drop"
	eventConnectionCapDrop = "connection_cap_drop"

	// scope names the limiter a drop came from: the public HTTP handler, the
	// public TCP listener, or the control-channel auth path.
	scopePublicHTTP = "public_http"
	scopePublicTCP  = "public_tcp"
	scopeAuth       = "auth"

	// reason says what an auth_reject refused: a bad auth token, or a valid id
	// presented without the secret that proves it.
	reasonInvalidToken         = "invalid_token"
	reasonInvalidSessionSecret = "invalid_session_secret"
)

// eventHeader is the pair of fields every event carries: its type and when it
// happened. Embedded in each event below, so that the type name is written once
// per publish method and the timestamp is taken in one place.
type eventHeader struct {
	Type string    `json:"type"`
	At   time.Time `json:"at"`
}

// newEventHeader stamps an event of the given type. The timestamp is UTC, and
// it is the time the event was published -- not, say, when an operation that
// the event describes started: a consumer ordering two events from one stream
// is ordering them by this field.
func newEventHeader(typ string) eventHeader {
	return eventHeader{Type: typ, At: time.Now().UTC()}
}

// authRejectEvent is a refused control connection: a bad auth token, or a
// resume of an existing session id that did not prove the id with its secret.
type authRejectEvent struct {
	eventHeader
	Reason string `json:"reason"`
}

// dropEvent is a connection (or a request) refused by one of the limiters. IP
// is the address the limiter keyed on, which is what an operator needs to
// decide whether the drop is an attack or their own monitoring.
type dropEvent struct {
	eventHeader
	Scope string `json:"scope"`
	IP    string `json:"ip"`
}

// tunnelOpenEvent is an endpoint coming online, published once the url is
// claimed and the listener is up.
type tunnelOpenEvent struct {
	eventHeader
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
}

// tunnelCloseEvent is an endpoint going away, whatever the reason (the client
// disconnected, the url was taken over, the server is shutting down).
type tunnelCloseEvent struct {
	eventHeader
	URL string `json:"url"`
}

// connectionCloseEvent is one public connection finishing, with the byte
// counts in each direction.
type connectionCloseEvent struct {
	eventHeader
	URL      string `json:"url"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

type eventHub struct {
	mu        sync.RWMutex
	listeners map[chan []byte]struct{}
}

func newEventHub() *eventHub {
	return &eventHub{listeners: make(map[chan []byte]struct{})}
}

func (h *eventHub) subscribe() chan []byte {
	ch := make(chan []byte, 128)
	h.mu.Lock()
	h.listeners[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *eventHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.listeners[ch]; ok {
		delete(h.listeners, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// publish hands one event to every subscriber. A slow subscriber's buffer is
// dropped rather than waited for (the events are a stream, and a subscriber
// that cannot keep up with it is not a reason to stall a limiter), and a
// marshal failure is dropped because every event here is a struct of strings,
// times and integers that json cannot refuse.
//
// The parameter is an interface rather than map[string]interface{} on purpose:
// it is what a call site cannot forge. Use the publishXxx methods below instead
// of calling this directly.
func (h *eventHub) publish(event interface{}) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.listeners {
		select {
		case ch <- payload:
		default:
		}
	}
}

// publishTunnelOpen announces an endpoint that came online.
func (h *eventHub) publishTunnelOpen(url, protocol string) {
	h.publish(tunnelOpenEvent{
		eventHeader: newEventHeader(eventTunnelOpen),
		URL:         url,
		Protocol:    protocol,
	})
}

// publishTunnelClose announces an endpoint that went away.
func (h *eventHub) publishTunnelClose(url string) {
	h.publish(tunnelCloseEvent{
		eventHeader: newEventHeader(eventTunnelClose),
		URL:         url,
	})
}

// publishConnectionClose reports one public connection finishing.
func (h *eventHub) publishConnectionClose(url string, bytesIn, bytesOut int64) {
	h.publish(connectionCloseEvent{
		eventHeader: newEventHeader(eventConnectionClose),
		URL:         url,
		BytesIn:     bytesIn,
		BytesOut:    bytesOut,
	})
}

// publishAuthReject reports a refused control connection. reason is one of the
// reason constants above.
func (h *eventHub) publishAuthReject(reason string) {
	h.publish(authRejectEvent{
		eventHeader: newEventHeader(eventAuthReject),
		Reason:      reason,
	})
}

// publishRateLimitDrop reports a connection refused by the per-IP rate limiter.
func (h *eventHub) publishRateLimitDrop(scope, ip string) {
	h.publish(dropEvent{
		eventHeader: newEventHeader(eventRateLimitDrop),
		Scope:       scope,
		IP:          ip,
	})
}

// publishConnectionCapDrop reports a connection refused by the per-IP
// concurrent-connection cap.
func (h *eventHub) publishConnectionCapDrop(scope, ip string) {
	h.publish(dropEvent{
		eventHeader: newEventHeader(eventConnectionCapDrop),
		Scope:       scope,
		IP:          ip,
	})
}

func newObservabilityStore() *observabilityStore {
	o := &observabilityStore{
		started: time.Now().UTC(),
		tunnels: make(map[string]*tunnelSnapshot),
		events:  newEventHub(),
	}
	go o.sampler()
	return o
}

var observe = newObservabilityStore()

func (o *observabilityStore) onTunnelOpen(t *Tunnel) {
	o.mu.Lock()
	o.tunnels[t.url] = &tunnelSnapshot{
		URL:       t.url,
		Protocol:  t.req.Protocol,
		StartedAt: time.Now().UTC(),
	}
	o.mu.Unlock()
	o.events.publishTunnelOpen(t.url, t.req.Protocol)
}

func (o *observabilityStore) onTunnelClose(t *Tunnel) {
	o.mu.Lock()
	delete(o.tunnels, t.url)
	o.mu.Unlock()
	o.events.publishTunnelClose(t.url)
}

func (o *observabilityStore) onConnOpen(t *Tunnel) {
	o.mu.Lock()
	if s := o.tunnels[t.url]; s != nil {
		s.ActiveConnections++
		s.TotalConnections++
	}
	o.mu.Unlock()
}

func (o *observabilityStore) onConnClose(t *Tunnel, bytesIn, bytesOut int64) {
	o.mu.Lock()
	if s := o.tunnels[t.url]; s != nil {
		if s.ActiveConnections > 0 {
			s.ActiveConnections--
		}
		s.BytesIn += bytesIn
		s.BytesOut += bytesOut
	}
	o.mu.Unlock()
	o.events.publishConnectionClose(t.url, bytesIn, bytesOut)
}

func (o *observabilityStore) snapshots() []tunnelSnapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]tunnelSnapshot, 0, len(o.tunnels))
	for _, t := range o.tunnels {
		out = append(out, *t)
	}
	return out
}

func (o *observabilityStore) uptimeSeconds() int64 {
	return int64(time.Since(o.started).Seconds())
}

func (o *observabilityStore) sampler() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for range t.C {
		p := metricsPoint{
			At:                 time.Now().UTC(),
			PublicConnections:  atomic.LoadInt64(&publicConnCount),
			ControlConnections: atomic.LoadInt64(&controlConnCount),
			TunnelsActive:      int64(len(o.snapshots())),
			PublicConnOpened:   atomic.LoadUint64(&publicConnOpenTotal),
			RateDropCount:      atomic.LoadUint64(&rateDropCount),
			AuthRejectCount:    atomic.LoadUint64(&authRejectCount),
		}

		o.mu.Lock()
		o.history = append(o.history, p)
		if len(o.history) > 3600 {
			o.history = o.history[len(o.history)-3600:]
		}
		o.mu.Unlock()
	}
}

func (o *observabilityStore) historyWindow(windowSeconds int64) []metricsPoint {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	cutoff := time.Now().UTC().Add(-time.Duration(windowSeconds) * time.Second)

	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]metricsPoint, 0, len(o.history))
	for _, p := range o.history {
		if p.At.After(cutoff) || p.At.Equal(cutoff) {
			out = append(out, p)
		}
	}
	return out
}
