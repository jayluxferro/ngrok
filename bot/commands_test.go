package bot

// Command tests (SPEC-CLUSTER20 testing strategy): help generated from the
// table, the two renderers against fixed snapshots, the hostile-string
// corpus through every formatter, and the per-chat budget's
// notice-then-silence shape.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHelpIsGeneratedFromTheTable(t *testing.T) {
	// A row the table does not ship, to prove /help cannot drift from the
	// command set: if the help text were hand-written, this row would not
	// appear and the test would fail. Removed on cleanup so other tests see
	// the real vocabulary.
	commands["fakeop"] = command{"the test-only operation", func(ctx context.Context, b *Bot) (string, error) {
		return "ran", nil
	}}
	t.Cleanup(func() { delete(commands, "fakeop") })

	b := &Bot{cfg: &config{CommandTimeoutSeconds: 5}}
	help, err := cmdHelp(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"status", "tunnels", "health", "help", "fakeop"} {
		if !strings.Contains(help, "/"+name+" -- ") {
			t.Errorf("help does not mention /%s:\n%s", name, help)
		}
	}
	// Every table row is mentioned, exactly: the generated list and the
	// table cannot disagree.
	if n := strings.Count(help, "\n/"); n != len(commands) {
		t.Errorf("help lists %d commands, table has %d:\n%s", n, len(commands), help)
	}
}

func TestRunCommandUnknownGetsHint(t *testing.T) {
	b := &Bot{cfg: &config{CommandTimeoutSeconds: 5}}
	if got := b.runCommand(context.Background(), "restart-everything"); got != "unknown command; send /help" {
		t.Errorf("unknown command reply = %q, want the one-line hint", got)
	}
}

func TestRenderStatusAgainstFixedSnapshot(t *testing.T) {
	var snap metricsSnapshot
	if err := json.Unmarshal([]byte(metricsFixture), &snap); err != nil {
		t.Fatal(err)
	}
	out := renderStatus(snap)

	for _, want := range []string{
		"uptime: 2h44m",
		"public connections: 7 (peak 42)",
		"control connections: 2",
		"tunnels active: 3",
		"auth rejects: 5",
		"rate-limit drops: 6",
		"event drops: 9",
		"connections opened: 1234",
		"public_conn_open_rate_per_sec: 0.50",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTunnelsAgainstFixedRows(t *testing.T) {
	out := renderTunnels([]tunnelRow{
		{URL: "https://b.example.ngrok.app", Protocol: "https", ActiveConnections: 1, TotalConnections: 9, Owner: "ci", PolicyAttached: true},
		{URL: "tcp://0.0.0.0:49152", Protocol: "tcp", ActiveConnections: 0, TotalConnections: 2, Owner: ""},
	})
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per tunnel:\n%s", len(lines), out)
	}
	// Sorted by url, so the output is stable for a given snapshot.
	if !strings.Contains(lines[0], "https://b.example.ngrok.app (https) 1/9 conns, owner ci, policy") {
		t.Errorf("line 0 = %q", lines[0])
	}
	if !strings.Contains(lines[1], "tcp://0.0.0.0:49152 (tcp) 0/2 conns, owner -,") {
		t.Errorf("line 1 = %q (empty owner renders as -)", lines[1])
	}
	if strings.Contains(out, "pooling") {
		t.Errorf("pooling flag rendered for a non-pooled row:\n%s", out)
	}
}

func TestRenderTunnelsCapsAndCountsTheRest(t *testing.T) {
	rows := make([]tunnelRow, tunnelsLineCap+7)
	for i := range rows {
		rows[i] = tunnelRow{URL: "https://tunnel.example/" + strings.Repeat("a", 1), Protocol: "https"}
	}
	// Distinct urls so the count is meaningful.
	for i := range rows {
		rows[i].URL = fmt.Sprintf("https://t%d.example.ngrok.app", i)
	}
	out := renderTunnels(rows)
	if got := strings.Count(out, "\n"); got != tunnelsLineCap {
		t.Fatalf("output has %d newlines, want %d tunnel lines + footer", got, tunnelsLineCap)
	}
	if !strings.Contains(out, "(+7 more)") {
		t.Errorf("output missing the (+7 more) footer:\n%s", out[len(out)-40:])
	}
}

func TestRenderTunnelsEmpty(t *testing.T) {
	if got := renderTunnels(nil); got != "no tunnels" {
		t.Errorf("renderTunnels(nil) = %q, want the honest one-liner", got)
	}
}

// TestHostileStringsThroughEveryFormatter walks the §6 corpus -- newlines,
// backticks, markup lookalikes, a 10 KB owner-shaped blob -- through every
// entry of the formatter table. The requirement is verbatim: nothing
// reflowed, nothing interpreted. (There is no escaping to check, on
// purpose: the bot never claims a markup dialect, §6.)
func TestHostileStringsThroughEveryFormatter(t *testing.T) {
	hostiles := []string{
		"line one\nline two\n[ngrok] forged alert line",
		"`backticks` and __underscores__ and _bold_",
		"*stars* [link](https://evil.example) <b>html</b> &amp;",
		"emoji \U0001F6A8 and unicode café",
		strings.Repeat("OWNER", 2048), // 10 KB
	}

	// Every formatter's decode target gets the hostile string in whichever
	// field it renders: url for tunnel/connection events, reason for
	// auth_reject, scope+ip for drops.
	typedPayload := map[string]func(string) string{
		"auth_reject": func(s string) string {
			return `{"type":"auth_reject","at":"2026-02-14T10:00:00Z","reason":` + jsonString(s) + `}`
		},
		"rate_limit_drop": func(s string) string {
			return `{"type":"rate_limit_drop","at":"2026-02-14T10:00:00Z","scope":` + jsonString(s) + `,"ip":"10.0.0.1"}`
		},
		"connection_cap_drop": func(s string) string {
			return `{"type":"connection_cap_drop","at":"2026-02-14T10:00:00Z","scope":"public_http","ip":` + jsonString(s) + `}`
		},
		"tunnel_open": func(s string) string {
			return `{"type":"tunnel_open","at":"2026-02-14T10:00:00Z","url":` + jsonString(s) + `,"protocol":"https"}`
		},
		"tunnel_close": func(s string) string {
			return `{"type":"tunnel_close","at":"2026-02-14T10:00:00Z","url":` + jsonString(s) + `}`
		},
		"connection_open": func(s string) string {
			return `{"type":"connection_open","at":"2026-02-14T10:00:00Z","client_addr":"10.0.0.9","url":` + jsonString(s) + `,"protocol":"https"}`
		},
		"connection_close": func(s string) string {
			return `{"type":"connection_close","at":"2026-02-14T10:00:00Z","url":` + jsonString(s) + `,"bytes_in":1,"bytes_out":2}`
		},
	}

	if len(typedPayload) != len(eventFormatters) {
		t.Fatalf("corpus covers %d types, table has %d -- a formatter is untested", len(typedPayload), len(eventFormatters))
	}

	for typ, payloadFor := range typedPayload {
		fn, ok := eventFormatters[typ]
		if !ok {
			t.Fatalf("formatter table is missing %q (the corpus and the table must agree)", typ)
		}
		for _, hostile := range hostiles {
			got := fn(eventFrame{Type: typ, Raw: json.RawMessage(payloadFor(hostile))})
			if !strings.Contains(got, hostile) {
				t.Errorf("%s: formatter mangled a hostile string (len %d):\ngot len %d, hostile not present verbatim", typ, len(hostile), len(got))
			}
			// The [ngrok] prefix rides in formatEvent, not the formatter --
			// checking both layers here.
			full := formatEvent(eventFrame{Type: typ, Raw: json.RawMessage(payloadFor(hostile))})
			if !strings.HasPrefix(full, "[ngrok] ") {
				t.Errorf("%s: formatEvent output missing the [ngrok] prefix", typ)
			}
			if !strings.Contains(full, hostile) {
				t.Errorf("%s: formatEvent mangled a hostile string", typ)
			}
		}
	}
}

// jsonString marshals one Go string as a JSON string literal for building
// fixture payloads above.
func jsonString(s string) string {
	enc, _ := json.Marshal(s)
	return string(enc)
}

func TestUnknownEventTypeAlertsRaw(t *testing.T) {
	// A newer ngrokd emits a type this build does not know: runtime is
	// tolerant where config is strict. The alert still goes out, as type +
	// raw JSON -- losing the formatting beats losing the event.
	raw := `{"type":"quantum_interference","at":"2026-02-14T10:00:00Z","field":"0.42"}`
	got := formatEvent(eventFrame{Type: "quantum_interference", Raw: json.RawMessage(raw)})
	if !strings.Contains(got, "quantum_interference") || !strings.Contains(got, "0.42") {
		t.Errorf("unknown type rendered as %q, want type + raw payload", got)
	}
}

func TestChatBudgetNoticeThenSilence(t *testing.T) {
	b := &Bot{
		cfg:     &config{CommandRatePerMin: 10},
		budgets: make(map[int64]chatBudget),
		now:     func() time.Time { return time.Unix(1700000000, 0) },
	}

	for i := 0; i < 10; i++ {
		allow, notice := b.allowBudget(42, b.now())
		if !allow || notice {
			t.Fatalf("command %d denied (allow=%v notice=%v); the first ten must pass", i+1, allow, notice)
		}
	}

	allow, notice := b.allowBudget(42, b.now().Add(time.Second))
	if allow || !notice {
		t.Fatalf("11th command: allow=%v notice=%v, want denied with the one notice", allow, notice)
	}
	allow, notice = b.allowBudget(42, b.now().Add(time.Second*2))
	if allow || notice {
		t.Fatalf("12th command: allow=%v notice=%v, want denied silently (no reply storms)", allow, notice)
	}

	// A new window resets everything, including the notified latch.
	allow, notice = b.allowBudget(42, b.now().Add(2*time.Minute))
	if !allow || notice {
		t.Fatalf("command after window: allow=%v notice=%v, want allowed", allow, notice)
	}
}

func TestChatBudgetIsPerChat(t *testing.T) {
	b := &Bot{
		cfg:     &config{CommandRatePerMin: 2},
		budgets: make(map[int64]chatBudget),
		now:     func() time.Time { return time.Unix(1700000000, 0) },
	}
	// Chat 42 exhausts its own window; chat 43 is untouched by it.
	b.allowBudget(42, b.now())
	b.allowBudget(42, b.now())
	allow, _ := b.allowBudget(42, b.now())
	if allow {
		t.Fatal("chat 42 over budget but was allowed")
	}
	allow, _ = b.allowBudget(43, b.now())
	if !allow {
		t.Fatal("chat 43 denied for chat 42's spending")
	}
}

func TestChatBudgetZeroDisables(t *testing.T) {
	b := &Bot{
		cfg:     &config{CommandRatePerMin: 0},
		budgets: make(map[int64]chatBudget),
		now:     func() time.Time { return time.Unix(1700000000, 0) },
	}
	for i := 0; i < 50; i++ {
		if allow, _ := b.allowBudget(42, b.now()); !allow {
			t.Fatalf("command %d denied with the budget off", i+1)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[int64]string{
		58:     "58s",
		125:    "2m5s",
		7500:   "2h5m",
		187200: "2d4h",
	}
	for in, want := range cases {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%d) = %q, want %q", in, got, want)
		}
	}
}
