package bot

// The command table (SPEC-CLUSTER20 §4). Argument-free verbs, rendered from
// live admin reads. The table is the single source of truth: /help is
// generated from it, so help cannot drift from the command set -- adding a
// command is one row, and the help text follows.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// command is one row of the table. run does the admin reads and renders the
// reply; an error becomes the reply itself (operator-debuggable, §7).
type command struct {
	summary string
	run     func(ctx context.Context, b *Bot) (string, error)
}

// commands is the vocabulary. Keys are the bare verb (without the slash).
// /help registers itself in init below: its row is generated from this very
// table, and a package-level literal would be an initialization cycle
// (commands -> cmdHelp -> commands).
var commands = map[string]command{
	"status": {"ngrokd at a glance (uptime, connections, counters, rates)", func(ctx context.Context, b *Bot) (string, error) {
		snap, err := b.admin.metrics(ctx)
		if err != nil {
			return "", err
		}
		return renderStatus(snap), nil
	}},
	"tunnels": {"live tunnels, one line each", func(ctx context.Context, b *Bot) (string, error) {
		rows, err := b.admin.tunnels(ctx)
		if err != nil {
			return "", err
		}
		return renderTunnels(rows), nil
	}},
	"health": {"one /healthz probe: latency and verdict", func(ctx context.Context, b *Bot) (string, error) {
		took, err := b.admin.health(ctx)
		if err != nil {
			return fmt.Sprintf("health: FAILED after %s: %v", took.Round(time.Millisecond), err), nil
		}
		return fmt.Sprintf("health: ok in %s", took.Round(time.Millisecond)), nil
	}},
}

func init() {
	commands["help"] = command{"what the bot can do", cmdHelp}
}

// commandTimeoutFor is how long one command's admin reads may take in total.
// The admin client already bounds each call; this bounds the whole run so a
// command that ever grows several calls cannot stack its timeouts.
func commandTimeoutFor(b *Bot) time.Duration {
	return time.Duration(b.cfg.CommandTimeoutSeconds) * time.Second
}

// runCommand executes one parsed command with its timeout and returns the
// reply text. A command error becomes the error text, not a shrug: an
// operator who asked for /status and got "admin /metrics: 401 Unauthorized"
// can act on that immediately.
func (b *Bot) runCommand(ctx context.Context, name string) string {
	cmd, ok := commands[name]
	if !ok {
		return "unknown command; send /help"
	}
	runCtx, cancel := context.WithTimeout(ctx, commandTimeoutFor(b))
	defer cancel()

	text, err := cmd.run(runCtx, b)
	if err != nil {
		return "error: " + err.Error()
	}
	if text == "" {
		// Never send an empty message: Telegram refuses it and the sender
		// would count the loss.
		return "(no output)"
	}
	return text
}

// cmdHelp renders the table. Output is deterministic (sorted) so tests can
// pin it and operators can diff it.
func cmdHelp(ctx context.Context, b *Bot) (string, error) {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)

	var sb strings.Builder
	sb.WriteString("ngrok-bot: read-only view of the ngrokd admin API.\n")
	for _, name := range names {
		fmt.Fprintf(&sb, "/%s -- %s\n", name, commands[name].summary)
	}
	sb.WriteString("Alerts are pushed from the event stream; plain text is ignored.")
	return sb.String(), nil
}

// renderStatus renders /status from the /metrics snapshot. One metric per
// line, names matching the API's own keys, so an operator can cross-reference
// the dashboard or curl without a translation table.
func renderStatus(s metricsSnapshot) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "uptime: %s\n", humanDuration(s.UptimeSeconds))
	fmt.Fprintf(&sb, "public connections: %d (peak %d)\n", s.PublicConnections, s.PublicConnPeak)
	fmt.Fprintf(&sb, "control connections: %d\n", s.ControlConnections)
	fmt.Fprintf(&sb, "tunnels active: %d\n", s.TunnelsActive)
	fmt.Fprintf(&sb, "auth rejects: %d\n", s.AuthRejectCount)
	fmt.Fprintf(&sb, "rate-limit drops: %d\n", s.RateDropCount)
	fmt.Fprintf(&sb, "event drops: %d\n", s.EventDropCount)
	fmt.Fprintf(&sb, "connections opened: %d\n", s.PublicConnOpenTotal)
	if len(s.Rates) > 0 {
		sb.WriteString("rates (per sec):\n")
		for _, k := range sortedKeys(s.Rates) {
			fmt.Fprintf(&sb, "  %s: %.2f\n", k, s.Rates[k])
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

// tunnelsLineCap is how many tunnels /tunnels renders before the "+N more"
// footer. Telegram caps the message anyway; the point is an ops chat that
// scrolls, not a full inventory.
const tunnelsLineCap = 20

// renderTunnels renders /tunnels: one line per tunnel -- url (proto),
// active/total connections, owner, policy flag -- capped with a footer.
func renderTunnels(rows []tunnelRow) string {
	if len(rows) == 0 {
		return "no tunnels"
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].URL < rows[j].URL })

	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		flags := ""
		if r.PolicyAttached {
			flags += " policy"
		}
		if r.Pooling {
			flags += " pooling"
		}
		owner := r.Owner
		if owner == "" {
			owner = "-"
		}
		lines = append(lines, fmt.Sprintf("%s (%s) %d/%d conns, owner %s,%s",
			r.URL, r.Protocol, r.ActiveConnections, r.TotalConnections, owner, flags))
	}

	if len(lines) > tunnelsLineCap {
		kept := lines[:tunnelsLineCap]
		return strings.Join(kept, "\n") + fmt.Sprintf("\n(+%d more)", len(lines)-tunnelsLineCap)
	}
	return strings.Join(lines, "\n")
}

// humanDuration renders an uptime seconds count as the units an operator
// speaks: 3d4h, 2h15m, 58s. Days are the largest unit -- a bot that says
// "uptime: 1296000s" is asking to be ignored.
func humanDuration(seconds int64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// chatBudget is the fixed-window per-chat command counter (§4). The bot
// holds admin credentials; even an allowed chat must not be able to hammer
// ngrokd's admin limiter through it -- and a runaway loop in some dashboard
// calling the bot is more likely than an attack.
type chatBudget struct {
	windowStart time.Time
	used        int
	notified    bool // the one "rate limited" reply per window has been sent
}

// budgetWindow is the fixed window length. A field-shaped constant for the
// tests that walk the boundary.
const budgetWindow = time.Minute

// allowBudget accounts one command attempt for chat. It returns whether the
// command may run and whether a rate-limit notice is owed (exactly one per
// window -- after the notice, silence, so an over-budget chat cannot convert
// its own throttling into a reply storm).
func (b *Bot) allowBudget(chat int64, now time.Time) (allow, notice bool) {
	if b.cfg.CommandRatePerMin <= 0 {
		return true, false
	}

	budget, ok := b.budgets[chat]
	if !ok || now.Sub(budget.windowStart) >= budgetWindow {
		budget = chatBudget{windowStart: now}
	}
	if budget.used >= b.cfg.CommandRatePerMin {
		if !budget.notified {
			budget.notified = true
			b.budgets[chat] = budget
			return false, true
		}
		b.budgets[chat] = budget
		return false, false
	}
	budget.used++
	b.budgets[chat] = budget
	return true, false
}
