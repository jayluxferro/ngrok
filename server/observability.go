package server

import (
	"encoding/json"
	"sync"
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

func (h *eventHub) publish(event map[string]interface{}) {
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

func newObservabilityStore() *observabilityStore {
	return &observabilityStore{
		started: time.Now().UTC(),
		tunnels: make(map[string]*tunnelSnapshot),
		events:  newEventHub(),
	}
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
	o.events.publish(map[string]interface{}{"type": "tunnel_open", "url": t.url, "protocol": t.req.Protocol, "at": time.Now().UTC()})
}

func (o *observabilityStore) onTunnelClose(t *Tunnel) {
	o.mu.Lock()
	delete(o.tunnels, t.url)
	o.mu.Unlock()
	o.events.publish(map[string]interface{}{"type": "tunnel_close", "url": t.url, "at": time.Now().UTC()})
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
	o.events.publish(map[string]interface{}{"type": "connection_close", "url": t.url, "bytes_in": bytesIn, "bytes_out": bytesOut, "at": time.Now().UTC()})
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
