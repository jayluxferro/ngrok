package bot

// The admin API client (SPEC-CLUSTER20 §2). The read-only property of the
// whole bot is enforced here, structurally: the type has four methods, each
// pinned to one path, and every request in the file is a GET. There is no
// method that takes a path or a method name as an argument, so no future
// command, config value or chat message can widen what this client can do
// without editing this file.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ngrok/version"
)

// The four paths the client can ever request. Declared once, as constants,
// because a review gate greps the source for exactly this set; a fifth entry
// here is a spec change, not a code change.
const (
	pathHealth  = "/healthz"
	pathMetrics = "/metrics"
	pathTunnels = "/tunnels"
	pathEvents  = "/events"
)

// sseMaxLineBytes caps one SSE line. The default bufio.Scanner cap (64 KB)
// would silently end the stream on a long event; a megabyte is far past
// anything ngrokd publishes (events are a few hundred bytes) while still
// bounding what a confused proxy echoing something else down this connection
// can allocate.
const sseMaxLineBytes = 1 << 20

// metricsSnapshot mirrors the /metrics payload (server/admin.go) for the
// fields the bot renders. Unknown fields are ignored by encoding/json, which
// is the forward-compatibility story: a newer ngrokd may add keys freely.
type metricsSnapshot struct {
	UptimeSeconds       int64              `json:"uptime_seconds"`
	PublicConnections   int64              `json:"public_connections"`
	ControlConnections  int64              `json:"control_connections"`
	TunnelsActive       int                `json:"tunnels_active"`
	AuthRejectCount     uint64             `json:"auth_reject_count"`
	RateDropCount       uint64             `json:"rate_drop_count"`
	EventDropCount      uint64             `json:"event_drop_count"`
	PublicConnPeak      int64              `json:"public_connections_peak"`
	PublicConnOpenTotal uint64             `json:"public_conn_open_total"`
	Rates               map[string]float64 `json:"rates"`
}

// tunnelRow mirrors one entry of the /tunnels answer (the server's
// tunnelSnapshot, server/observability.go) for the fields /tunnels renders.
type tunnelRow struct {
	URL               string `json:"url"`
	Protocol          string `json:"protocol"`
	ActiveConnections int64  `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
	Owner             string `json:"owner"`
	Pooling           bool   `json:"pooling"`
	PolicyAttached    bool   `json:"policy_attached"`
}

// eventFrame is one decoded SSE event: the header fields every event carries
// (server/observability.go's eventHeader) plus the raw payload. Raw is kept
// because an unknown type is rendered generically as type + raw JSON (§5):
// config-time strict, runtime tolerant, since the event vocabulary crosses a
// wire the bot does not version.
type eventFrame struct {
	Type string
	At   time.Time
	Raw  json.RawMessage
}

// adminClient is a read-only client for one ngrokd admin API.
type adminClient struct {
	base  *url.URL
	http  *http.Client
	token string
	user  string
	pass  string
	ua    string
	// streamHTTP has no Timeout on purpose: http.Client.Timeout bounds the
	// whole exchange including the body, so the command client's cap would
	// silently end the SSE stream after command_timeout_seconds. The stream
	// bounds itself by context instead (§2).
	streamHTTP *http.Client
	// wait sleeps for d or until ctx is done. A field rather than inline so
	// the reconnect-backoff test can stub the clock instead of sleeping.
	wait func(ctx context.Context, d time.Duration) error
}

// newAdminClient validates the transport-relevant parts of the config and
// builds the client. The timeout applies to every non-SSE call (§2); the SSE
// stream is long-lived by design and bounds itself by context instead.
func newAdminClient(cfg *config) (*adminClient, error) {
	u, err := url.Parse(cfg.AdminURL)
	if err != nil {
		return nil, fmt.Errorf("admin_url %q does not parse: %w", cfg.AdminURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("admin_url %q must use the http or https scheme", cfg.AdminURL)
	}

	a := &adminClient{
		base:       u,
		http:       &http.Client{Timeout: time.Duration(cfg.CommandTimeoutSeconds) * time.Second},
		streamHTTP: &http.Client{},
		token:      cfg.AdminToken,
		ua:         "ngrok-bot/" + version.Full(),
		wait: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
	a.user, a.pass = adminAuthParts(cfg.AdminAuth)
	return a, nil
}

// adminAuthParts splits user:pass. The server's own parser (parseAdminAuth)
// splits on the first colon and treats a missing colon as no credentials;
// matching that here keeps "admin_auth: user" behaving identically on both
// sides of the wire.
func adminAuthParts(auth string) (user, pass string) {
	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// get issues the only kind of request this client can make: a GET to one of
// the four fixed paths, with auth and the bot's User-Agent attached. It is
// unexported and takes no path argument, so adding a read means adding a
// method that calls get with a constant -- the capability to fetch anything
// else does not exist.
func (a *adminClient) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base.String()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", a.ua)
	req.Header.Set("Accept", "application/json")
	if a.token != "" {
		req.Header.Set("X-Ngrok-Admin-Token", a.token)
	}
	if a.user != "" || a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	return a.http.Do(req)
}

// decode reads a JSON answer body, closing it either way. A non-200 is an
// error carrying the status: an operator debugging a /status reply needs to
// know ngrokd said 401, not that it "failed".
func (a *adminClient) decode(ctx context.Context, path string, into interface{}) error {
	resp, err := a.get(ctx, path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("admin %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// health probes /healthz and reports the round-trip latency. Any 200 counts;
// the server's answer body is exactly "ok\n" and is not worth parsing.
func (a *adminClient) health(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	resp, err := a.get(ctx, pathHealth)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("admin %s: %s", pathHealth, resp.Status)
	}
	return time.Since(start), nil
}

// metrics fetches the /metrics snapshot.
func (a *adminClient) metrics(ctx context.Context) (metricsSnapshot, error) {
	var snap metricsSnapshot
	if err := a.decode(ctx, pathMetrics, &snap); err != nil {
		return metricsSnapshot{}, err
	}
	return snap, nil
}

// tunnels fetches the /tunnels list.
func (a *adminClient) tunnels(ctx context.Context) ([]tunnelRow, error) {
	var reply struct {
		Tunnels []tunnelRow `json:"tunnels"`
	}
	if err := a.decode(ctx, pathTunnels, &reply); err != nil {
		return nil, err
	}
	return reply.Tunnels, nil
}

// events subscribes to the /events SSE stream. It returns a channel of
// decoded frames and a cancel func; the background reader reconnects on any
// error or EOF with capped exponential backoff (1s doubling to 60s) until
// cancel or ctx, so a ngrokd restart -- exactly when an operator most wants
// the alert feed -- is survived rather than silently ending the subscription.
// The channel closes only on cancellation.
func (a *adminClient) events(ctx context.Context) (<-chan eventFrame, func(), error) {
	frames := make(chan eventFrame, 64)
	loopCtx, cancel := context.WithCancel(ctx)

	go func() {
		defer close(frames)
		backoff := time.Second
		for {
			if loopCtx.Err() != nil {
				return
			}
			ok := a.streamOnce(loopCtx, frames)
			if !ok {
				return
			}
			// The wait is what makes the backoff a stubbed clock in tests and
			// an interruptible sleep in production; on cancellation it returns
			// and the loop exits.
			if a.wait(loopCtx, backoff) != nil {
				return
			}
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
	}()

	stop := func() { cancel() }
	return frames, stop, nil
}

// streamOnce runs one SSE connection to completion. It returns whether the
// caller should reconnect (true) or the context is done (false). Frame
// parsing follows the SSE convention the server's /events emits ("data: "
// lines): comment lines starting with ':' are skipped, multiple data lines
// in one frame join with newline, a blank line dispatches the frame.
func (a *adminClient) streamOnce(ctx context.Context, frames chan<- eventFrame) bool {
	// The SSE call must not inherit the client's command timeout: it is long-
	// lived on purpose. Dial it with a context-scoped request instead.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base.String()+pathEvents, nil)
	if err != nil {
		return true
	}
	req.Header.Set("User-Agent", a.ua)
	req.Header.Set("Accept", "text/event-stream")
	if a.token != "" {
		req.Header.Set("X-Ngrok-Admin-Token", a.token)
	}
	if a.user != "" || a.pass != "" {
		req.SetBasicAuth(a.user, a.pass)
	}

	resp, err := a.streamHTTP.Do(req)
	if err != nil {
		// A cancelled context ends everything; anything else is reconnectable.
		return ctx.Err() == nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A refused stream (401 after a token rotation, say) should not spin
		// hot: the caller's backoff applies, same as a network error.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return true
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), sseMaxLineBytes)

	var data strings.Builder
	dispatch := func() {
		if data.Len() == 0 {
			return
		}
		payload := []byte(data.String())
		data.Reset()

		var frame eventFrame
		frame.Raw = payload
		var header struct {
			Type string    `json:"type"`
			At   time.Time `json:"at"`
		}
		if err := json.Unmarshal(payload, &header); err != nil {
			// A line that is not the JSON we know is dropped, not panicked on:
			// the stream crosses proxies that may interleave keep-alives.
			return
		}
		frame.Type = header.Type
		frame.At = header.At
		select {
		case frames <- frame:
		case <-ctx.Done():
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			dispatch()
		case strings.HasPrefix(line, ":"):
			// SSE comment (the server sends none today; intermediaries may).
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		default:
			// Other SSE fields (event:, id:, retry:) carry nothing the bot
			// needs; the type travels inside the JSON payload.
		}
		if ctx.Err() != nil {
			return false
		}
	}
	// Scanner ended: EOF or a read error. Flush any pending frame, then let
	// the caller reconnect.
	dispatch()
	return ctx.Err() == nil
}
