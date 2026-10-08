package bot

// Alerts and the health watcher (SPEC-CLUSTER20 §5). Both are one-way
// pumps: ngrokd's event stream and /healthz in, the sender queue out. The
// event vocabulary here is the server's (server/observability.go's const
// block); it is declared independently because the bot versions itself
// against the wire, not the server package -- importing server/ would pull
// the whole ngrokd into a 5 MB tool, and the vocabulary crosses a wire, not
// a link.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// The known event type vocabulary. Config-time strict: an alert_events
// value outside this set is refused at startup (typo protection -- a
// mistyped name can never fire, and silence is the worst failure mode for
// an alert). Runtime tolerant: an event whose type is outside this set
// formats generically instead, because a newer ngrokd legitimately grows
// types this build has not heard of.
var knownTypes = map[string]bool{
	"tunnel_open":         true,
	"tunnel_close":        true,
	"connection_open":     true,
	"connection_close":    true,
	"auth_reject":         true,
	"rate_limit_drop":     true,
	"connection_cap_drop": true,
}

// defaultAlertEvents is the config default: the anomalous-by-default set.
// connection_open/close exist as formatters so an operator CAN opt into the
// noise, but they are not in the default set -- on any busy server they are
// the firehose.
func defaultAlertEvents() []string {
	return []string{
		"auth_reject",
		"rate_limit_drop",
		"connection_cap_drop",
		"tunnel_open",
		"tunnel_close",
	}
}

func knownEventTypes() map[string]bool { return knownTypes }

// eventFormatters renders one known event type as a single plain line. The
// [ngrok] prefix is prepended by formatEvent, not here, so every entry stays
// about the payload.
//
// Strings from the payload are interpolated verbatim. The bot never claims
// a markup dialect (§6), so there is nothing to inject and nothing to
// escape; the spec chose verbatim over sanitizing on purpose: an escaped
// url is a changed url, and an operator diffing it against logs loses the
// match. A newline smuggled inside a url renders as a newline -- cosmetic
// in plain text, forgeable of nothing.
var eventFormatters = map[string]func(eventFrame) string{
	"auth_reject": func(f eventFrame) string {
		var e struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(f.Raw, &e); err != nil {
			return rawEventLine(f)
		}
		return fmt.Sprintf("auth rejected: %s", e.Reason)
	},
	"rate_limit_drop": func(f eventFrame) string {
		return dropLine(f)
	},
	"connection_cap_drop": func(f eventFrame) string {
		return dropLine(f)
	},
	"tunnel_open": func(f eventFrame) string {
		var e struct {
			URL      string `json:"url"`
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal(f.Raw, &e); err != nil {
			return rawEventLine(f)
		}
		return fmt.Sprintf("tunnel open: %s (%s)", e.URL, e.Protocol)
	},
	"tunnel_close": func(f eventFrame) string {
		var e struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(f.Raw, &e); err != nil {
			return rawEventLine(f)
		}
		return fmt.Sprintf("tunnel close: %s", e.URL)
	},
	"connection_open": func(f eventFrame) string {
		var e struct {
			ClientAddr string `json:"client_addr"`
			URL        string `json:"url"`
			Protocol   string `json:"protocol"`
		}
		if err := json.Unmarshal(f.Raw, &e); err != nil {
			return rawEventLine(f)
		}
		return fmt.Sprintf("connection: %s from %s (%s)", e.URL, e.ClientAddr, e.Protocol)
	},
	"connection_close": func(f eventFrame) string {
		var e struct {
			URL      string `json:"url"`
			BytesIn  int64  `json:"bytes_in"`
			BytesOut int64  `json:"bytes_out"`
		}
		if err := json.Unmarshal(f.Raw, &e); err != nil {
			return rawEventLine(f)
		}
		return fmt.Sprintf("connection closed: %s (%s in / %s out)", e.URL, humanBytes(e.BytesIn), humanBytes(e.BytesOut))
	},
}

// dropLine is the shared shape of the two drop events: the limiter that
// dropped and the ip it keyed on -- the pair an operator needs to tell an
// attack from their own monitoring.
func dropLine(f eventFrame) string {
	var e struct {
		Scope string `json:"scope"`
		IP    string `json:"ip"`
	}
	if err := json.Unmarshal(f.Raw, &e); err != nil {
		return rawEventLine(f)
	}
	return fmt.Sprintf("%s: scope=%s ip=%s", f.Type, e.Scope, e.IP)
}

// rawEventLine is the runtime-tolerant fallback: a type the bot does not
// know (a newer ngrokd) still alerts, as type + raw JSON -- losing the
// formatting beats losing the event.
func rawEventLine(f eventFrame) string {
	return fmt.Sprintf("event %s: %s", f.Type, string(f.Raw))
}

// formatEvent renders any frame through the vocabulary table, prefixing
// [ngrok] so multi-bot chats stay readable (§5).
func formatEvent(f eventFrame) string {
	line := f.Type
	if fn, ok := eventFormatters[f.Type]; ok {
		line = fn(f)
	} else {
		line = rawEventLine(f)
	}
	return "[ngrok] " + line
}

// humanBytes renders a byte count the way an ops chat reads it. Exact below
// a kibibyte, one decimal above; nobody wants twelve significant digits for
// a connection close.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	val := float64(n)
	names := []string{"KB", "MB", "GB", "TB"}
	for _, name := range names {
		val /= unit
		if val < unit {
			return fmt.Sprintf("%.1f%s", val, name)
		}
	}
	return fmt.Sprintf("%.1fPB", val/unit)
}

// pumpEvents consumes the SSE subscription and fans every alert-event out to
// all allowed chats. Non-matching types are dropped silently -- the filter is
// the config's job, the formatter only sees what the operator asked for. The
// frames channel closes only on cancellation, so this returns when ctx does.
func (b *Bot) pumpEvents(ctx context.Context) {
	frames, stop, err := b.admin.events(ctx)
	if err != nil {
		logger.Error("event stream subscribe failed: %v", err)
		return
	}
	defer stop()

	wanted := make(map[string]bool, len(b.cfg.AlertEvents))
	for _, ev := range b.cfg.AlertEvents {
		wanted[ev] = true
	}

	for frame := range frames {
		if !wanted[frame.Type] {
			continue
		}
		line := formatEvent(frame)
		for _, chat := range b.cfg.AllowedChats {
			b.tg.send(chat, line)
		}
	}
}

// healthWatcher is the latched /healthz probe (§5). Two consecutive failures
// alert once; the next success alerts the outage duration. The latch exists
// because one blip is noise -- a GC pause, a wifi hop -- and an alert that
// fires per-blip trains the operator to ignore it.
type healthWatcher struct {
	admin     *adminClient
	interval  time.Duration
	broadcast func(string)

	// latched state, owned by the watcher goroutine only.
	fails     int
	latched   bool
	downSince time.Time
}

// runHealthWatcher probes on the interval until ctx is cancelled. Startup is
// unlatched: a server already down at boot alerts on the second failed probe
// like any other outage (the spec calls this out -- there is no grace period
// that would silence it).
func (w *healthWatcher) run(ctx context.Context) {
	// The probe is bounded by the command timeout, not the interval: a hung
	// admin API must not stretch the watcher's cadence arbitrarily.
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, w.probeTimeout())
			_, err := w.admin.health(probeCtx)
			cancel()
			w.observe(time.Now(), err)
		}
	}
}

func (w *healthWatcher) probeTimeout() time.Duration {
	d := w.admin.http.Timeout
	if d <= 0 {
		d = 10 * time.Second
	}
	return d
}

// observe folds one probe result into the latch. Split from run so the
// transition table is testable without a ticker.
func (w *healthWatcher) observe(now time.Time, err error) {
	if err != nil {
		// downSince is the first failed probe, not the alert: the outage an
		// operator cares about is how long the API was unreachable, and the
		// second probe only exists to confirm it.
		if w.fails == 0 {
			w.downSince = now
		}
		w.fails++
		if w.fails >= 2 && !w.latched {
			w.latched = true
			w.broadcast(fmt.Sprintf("[ngrok] admin API unreachable (%d consecutive failed probes)", w.fails))
		}
		return
	}
	w.fails = 0
	if w.latched {
		outage := now.Sub(w.downSince)
		w.latched = false
		w.broadcast(fmt.Sprintf("[ngrok] admin API recovered after %s", outage.Round(time.Second)))
	}
}
