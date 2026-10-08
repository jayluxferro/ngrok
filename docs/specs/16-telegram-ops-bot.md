# SPEC-CLUSTER20 — ngrok-bot: a read-only Telegram ops surface over the admin API

Status: shipped (v1.0.20)

The admin listener is a complete observability API — `/metrics`,
`/tunnels`, `/events` SSE, `/healthz`, three-mode auth, per-IP rate
limits — and cluster 19 made it programmable. This cluster adds the
smallest useful program over it: `ngrok-bot`, a standalone binary the
operator runs beside ngrokd, which answers a few read-only commands in
Telegram and pushes anomaly alerts from the event stream.

The organizing rule is **read-only by construction**. The bot holds
admin credentials, so it must be structurally incapable of anything but
GETs against a fixed path allowlist — not disciplined into it, built so
the capability does not exist. Control actions (restart, tunnel
manipulation, config application) stay out: an authenticated chat
message that starts processes or changes server state is an RCE-class
surface (the spec-15 non-goal analysis applies unchanged), and it would
need its own threat model before existing at all.

## Objectives

1. `main/ngrok-bot` — a new binary in the existing layout, zero changes
   to any existing Go package (the whole cluster is additive: `bot/` is
   a new top-level package, `main/ngrok-bot/` a new entry point, and
   the only touched existing files are build/docs/version).
2. Commands in any allowed chat:
   - `/help` — what the bot can do, one message.
   - `/status` — from `/metrics`: uptime, public/control connections,
     tunnels active, auth rejects, rate drops, event drops, the rates
     block.
   - `/tunnels` — from `/tunnels`: one line per tunnel — url (proto),
     active/total connections, owner, policy flag; capped at 20 lines
     with a `+N more` footer.
   - `/health` — one `/healthz` GET, latency and verdict.
3. Alerts: the bot subscribes to `/events` SSE and forwards events
   whose type is in the configured `alert_events` set to every allowed
   chat, one plain line each. Default set: `auth_reject`,
   `rate_limit_drop`, `connection_cap_drop`, `tunnel_open`,
   `tunnel_close`.
4. A `/healthz` watcher: probe on an interval, alert when ngrokd goes
   unreachable (two consecutive failures — one blip is noise) and again
   on recovery with the outage duration.
5. Operates as a plain long-polling Telegram client: no webhook, no
   inbound listener, no TLS server of its own.

## Non-goals (binding)

- **Any control action.** No restart, no tunnel start/stop, no policy
  edit, no config application, no `/api/render` use — nothing write-
  shaped exists in the bot's vocabulary. Extending it later requires a
  threat-model cluster of its own (this is the spec-15 remote-control
  non-goal, restated for a chat surface).
- **Webhook mode.** Inbound HTTPS is an attack surface the bot does not
  need; long polling through the Telegram API is enough.
- **Interactive UI.** No inline keyboards, callbacks, pagination,
  arguments. Commands are argument-free verbs.
- **Multi-server.** One bot process watches one ngrokd. Run more
  processes for more servers.
- **Vault integration.** Two secrets (telegram token, admin token)
  read from config or env; pulling `ngrok/policy` in for `secret()`
  would drag cel-go into a 5 MB tool. Env fallback is the honest
  80% here.
- **Markdown/HTML formatting.** Messages are plain text,
  `parse_mode` is never sent (see Design §6) — so there is nothing to
  escape, ever.

## Design

### 1. Configuration — `bot/config.go`

YAML, `-config` flag, default `$HOME/.ngrok-bot`:

```yaml
telegram_token: "123:abc"        # env NGROK_BOT_TELEGRAM_TOKEN overrides
telegram_api: "https://api.telegram.org"   # default; override = Bot API
                                 # proxy or the e2e fake
admin_url: "http://127.0.0.1:9090"   # required, http(s) scheme enforced
admin_token: "..."               # env NGROK_BOT_ADMIN_TOKEN overrides
admin_auth: "user:pass"          # basic auth alternative to the token
allowed_chats: [123456789]       # REQUIRED — empty set = startup error
alert_events: [auth_reject, rate_limit_drop, connection_cap_drop,
               tunnel_open, tunnel_close]   # default = this set
health_interval_seconds: 30      # 0 disables the /healthz watcher
command_rate_per_min: 10         # per-chat command budget; 0 = off
command_timeout_seconds: 10      # admin call timeout
```

Rules, all loud at startup:

- `allowed_chats` empty → refuse to start. A bot that answers anyone
  is an ops-data leak; fail-closed is the only correct default.
- `admin_url` must parse with http/https scheme; anything else refuses.
- Unknown `alert_events` value → refuse, naming the valid set (typo
  protection). At *runtime*, an event arriving with a type the bot does
  not know (a newer ngrokd) formats generically as `type` + raw JSON —
  config-time strict, runtime tolerant, because the vocabulary crosses
  a wire the bot does not version.
- `admin_token` and `admin_auth` may both be set (the admin API
  accepts either; the bot sends both, token as
  `X-Ngrok-Admin-Token`, auth as basic).
- Secrets never appear in logs: the startup log line prints the config
  with tokens replaced by `***` (test pins the masking).

### 2. The admin client — `bot/admin.go`

One struct, typed methods, **no generic request method**:

```go
type adminClient struct { ... }
func newAdminClient(cfg *config) (*adminClient, error)
func (a *adminClient) health(ctx) (time.Duration, error)   // GET /healthz
func (a *adminClient) metrics(ctx) (metricsSnapshot, error) // GET /metrics
func (a *adminClient) tunnels(ctx) ([]tunnelRow, error)     // GET /tunnels
func (a *adminClient) events(ctx) (<-chan eventFrame, func(), error)
                                                            // GET /events SSE
```

- The path set is fixed: `/healthz`, `/metrics`, `/tunnels`,
  `/events`. There is no method that takes an arbitrary path, and no
  verb anywhere but GET — the read-only property is the type system,
  not a convention (review gate 1 greps for it and finds nothing).
  Read-only scopes to the *admin* API: the one write-shaped call in
  the package is Telegram's own `sendMessage` POST (§3), which is the
  Bot API's protocol and not a use of the bot's admin credentials.
- `events` returns decoded frames off a background reader:
  `bufio.Scanner` over the response body, `data: ` lines,
  `json.RawMessage` payloads. On read error or EOF it reconnects with
  backoff (1s → 2s → … capped 60s) until the context is cancelled; the
  channel closes only on cancellation.
- `metricsSnapshot`/`tunnelRow` mirror the admin JSON (the field names
  cluster 19 ships): metrics carries `uptime_seconds`,
  `public_connections`, `control_connections`, `tunnels_active`,
  `auth_reject_count`, `rate_drop_count`, `event_drop_count`, `rates`;
  tunnel rows carry `url`, `protocol`, `active_connections`,
  `total_connections`, `owner`, `policy_attached`, `pooling`.
  Unknown JSON fields are ignored (forward compatibility).
- Timeouts: every non-SSE call uses `command_timeout_seconds`.

### 3. The Telegram client — `bot/telegram.go`

- **Long polling**: `GET {api}/bot{token}/getUpdates?timeout=50&offset=N`.
  One in-flight poll at a time; offset persisted in memory only.
  Errors back off 1s → 60s cap.
- **Startup identity check**: `getMe` before anything else; a 401 or
  network error exits non-zero ("the bot would run deaf" is worse than
  not starting).
- **Send path**: a bounded queue (256) and one sender goroutine.
  `sendMessage` posts `{chat_id, text}` — **no `parse_mode` field, ever**
  (§6). Per-chat pacing 1 msg/s (Telegram's documented guidance) is a
  simple last-send timestamp check, not a limiter framework.
- **Drop accounting** (the event_destinations precedent: loss must be
  visible): queue full → drop, count. Once a minute, if drops occurred
  since the last notice, the sender emits one `N alerts dropped`
  message per affected chat. If Telegram itself is down, that notice
  is dropped too and counted — the log WARN is then the only record,
  stated honestly in the README.
- Text cap 4096 (Telegram's limit): messages longer than 4096
  characters are truncated at the last whole line that fits, with a
  `… (+N lines cut)` footer — formatters never see the limit; the
  sender enforces it once.

### 4. Commands — `bot/commands.go`

- A table: `map[string]command` where `command` is
  `{summary string, run func(ctx) (string, error)}`. Adding a command
  is one row; the help text is generated from the table (single source
  of truth — help cannot drift from the command set).
- `/start` is aliased to `/help` (Telegram convention).
- Unknown command → one-line help hint. Plain non-command text →
  ignored entirely (group chats are noisy; the bot speaks when spoken
  to via commands).
- **Per-chat command budget**: `command_rate_per_min` (default 10, 0 =
  off) as a fixed-window counter map — the bot holds admin
  credentials, and even an allowed chat must not be able to hammer
  ngrokd's admin limiter through it. Over budget → one "rate limited"
  reply per window, then silence (no reply storms).

### 5. Alerts + health — `bot/alerts.go`

- The event vocabulary table — one entry per known type:

  ```go
  var eventFormatters = map[string]func(eventFrame) string{ ... }
  ```

  `auth_reject` → reason line; `rate_limit_drop`/`connection_cap_drop`
  → scope + ip; `tunnel_open` → url + protocol;
  `tunnel_close` → url; `connection_open`/`connection_close` → short
  url/byte line (present so an operator CAN opt into the noise);
  unknown types → `type` + raw JSON (see §1). Every line is prefixed
  `[ngrok]` so multi-bot chats stay readable.
- The SSE consumer filters: type in `alert_events` → enqueue to the
  sender for every allowed chat; else drop silently.
- **Health watcher**: ticker at `health_interval_seconds`; two
  consecutive failures → one `[ngrok] admin API unreachable` alert
  (latched); success after a latch → `[ngrok] recovered after Xs`.
  Startup state is unlatched; a server already down at boot alerts on
  the second failed probe like any other outage.

### 6. Security model (the section a reviewer reads first)

- **Read-only by construction** (§2): no generic request method, no
  non-GET verb against the *admin* API, no other admin path in the
  source. (The package's one write-shaped call is Telegram's own
  `sendMessage` POST — the Bot API's protocol, spelled
  `http.MethodPost`; a query-string body alternative would leak
  message content into intermediary access logs, and read-only is a
  property of how the bot uses its admin credentials, not of the Bot
  API.) Gate 1 greps `bot/` for `POST|PUT|DELETE|PATCH` (zero hits —
  the send site spells `http.MethodPost`) and pins that the admin
  client's request builders are GET-only over exactly the four
  allowed paths.
- **Chat allowlist, fail-closed** (§1): strangers get *nothing* — not
  a help hint, not an error, zero messages. Test pins it: an update
  from a non-allowed chat produces no `sendMessage` call at all.
- **No `parse_mode`** (§3): every message is plain text. Tunnel URLs,
  owner names, reject reasons — all attacker- or operator-influenced
  strings — cannot smuggle Telegram markup because the bot never
  claims any markup dialect. This deletes the escaping problem rather
  than solving it. Gate: grep for `parse_mode` in `bot/` finds only
  the test that asserts its absence.
- **No inbound surface**: the bot dials out to Telegram and ngrokd
  only; it binds nothing.
- **Secrets** (§1): env-over-file for both tokens; logs mask them.
- **No file writes, no exec, no shell** — the binary reads one config
  file and optionally writes one log file (`-log`, the repo's existing
  `ngrok/log` package); nothing else touches the filesystem. Gate 1
  greps for `os/exec`, `Command(`, `WriteFile` in `bot/`.

### 7. Wiring — `bot/bot.go`, `main/ngrok-bot/ngrok-bot.go`

- `Bot` owns: config, admin client, telegram client, command table,
  alert pump, health watcher. `Run(ctx)` blocks on the update loop;
  SIGINT/SIGTERM cancel the context; shutdown closes the SSE
  subscription and drains nothing (alerts in flight may drop; a
  shutdown notice is not worth the complexity).
- Update routing: allowed chat? → command? → run with timeout →
  reply. Each hop fails closed (stranger → drop; unknown → hint;
  command error → the error text as the reply — operator-debuggable).
- `User-Agent: ngrok-bot/<version.Full()>` on every outbound call
  (both APIs) — imports `ngrok/version`, the one existing package the
  bot touches besides `ngrok/log`.

## File ownership (workstreams)

| Lane | Owns |
|---|---|
| **A — bot** | `bot/*.go` (all), `main/ngrok-bot/ngrok-bot.go` |
| **B — build & docs** | `Makefile`, `.github/workflows/release.yml`, `README.md`, `docs/CHANGELOG.md`, `version/version.go`, `docs/specs/README.md` (index row — status flip after ship is the architect's) |
| **D — e2e** (after A) | `scripts/e2e.sh` (`bot` group + fake-Telegram helper), helper source under `scripts/` |

A and B run in parallel (B's Makefile/release references
`./main/ngrok-bot` before it exists — fine, nothing builds until A
lands; B must not `go build` in gates). D starts when A reports. No
lane touches `server/`, `client/`, `msg/`, `policy/`, `rewriter/`,
`conn/`, `proto/`.

## Build & release

- `make bot` (debug) / `make release-bot` — same shape as the
  client/server targets. The bot embeds no assets; `deps` for it is a
  no-op (`go mod download` only).
- Release workflow: one more build step per matrix cell
  (`go build ... ./main/ngrok-bot`), the binary joins the existing
  per-platform archives (`tar`/`zip` lines + upload globs grow one
  name each). No new archive, no new asset count class — the bot rides
  the existing 44-cell matrix inside the same archives. Asset count
  stays 176.
- `go.mod`: **no new dependencies.** `gopkg.in/yaml.v3` is already a
  direct dependency.

## Testing strategy

- **config**: env-over-file precedence; empty `allowed_chats` refusal;
  bad `admin_url` scheme refusal; unknown `alert_event` refusal naming
  valid ones; defaults (alert set, intervals, rates); secret masking
  in the startup log line.
- **admin** (httptest): each typed method parses its endpoint's real
  JSON shape (fixtures copied from cluster 19's handlers, not
  hand-typed); SSE frame parsing incl. multi-line `data:` skips and
  comment lines (`: ping` keep-alives); reconnect-on-EOF with a
  stubbed clock; auth headers present (both modes); unknown JSON
  fields tolerated.
- **telegram** (fake server): offset advance (an update acked is never
  re-fetched); backoff on 500s; send queue drop accounting + the
  once-a-minute notice; 4096 truncation at a whole line with the
  footer; **absence of `parse_mode` asserted on every captured
  sendMessage** (the pin).
- **commands**: help generated from the table (a new row shows up in
  `/help` — test adds a fake row); `/status` and `/tunnels` rendering
  against fixed snapshots; hostile strings through every formatter
  (newlines, backticks, `_bold_`, 10 KB owner names) — output is the
  string verbatim, nothing reflowed or interpreted; per-chat budget:
  11th command in a window gets the one-line notice, 12th silence.
- **bot** (both fakes + real routing): allowed chat `/status` answered
  from a stubbed admin; stranger update → zero sends (the
  fail-closed pin); an `auth_reject` event on the SSE stub → alert to
  every allowed chat; health latch fires on two failures and clears
  with duration.
- **e2e** (`bot` group; ports grepped for collisions first — the
  standing rule; logs outside the `/tmp/ngrok-e2e-*.log` glob):
  1. refuses to start with no `allowed_chats` (non-zero exit,
     message).
  2. refuses an unknown `alert_events` value (names valid ones).
  3. `getMe` failure exits non-zero (fake returns 401).
  4. allowed chat `/status` → sendMessage recorded containing
     `uptime_seconds`-derived uptime and `tunnels_active`.
  5. stranger chat `/status` → no sendMessage at all.
  6. `/tunnels` with one live tunnel (real agent registered) →
     message contains the tunnel URL.
  7. bad-token agent connect → `auth_reject` alert recorded.
  8. ngrokd stopped → unreachable alert after 2 intervals; ngrokd
     back → recovery line.
  9. every recorded sendMessage payload lacks `parse_mode` (assert
     over the whole record file — the gate-1 grep made executable).
  10. `/help` mentions every command; unknown command gets the hint.
- Fake Telegram helper (D's, prebuilt to `$TMPDIR/helpers` per the
  e2e standing rules): serves `getMe`, `getUpdates` (queued via a
  script-side inject endpoint), `sendMessage` (JSONL record file the
  scenarios grep). One port, `-addr -record` flags.

## Review gates

1. **Read-only pins**: `grep -nE 'POST|PUT|DELETE|PATCH' bot/` →
   nothing (the Telegram send site spells `http.MethodPost` — the
   Bot API's own write, outside the admin client);
   `grep -n 'parse_mode' bot/` → only the absence test;
   `grep -nE 'os/exec|exec.Command|WriteFile|Create\(' bot/` → only
   the log path; admin paths in source are exactly the four allowed,
   and the admin client's request builders are GET-only.
2. **Fail-closed**: no `allowed_chats` → non-zero exit; stranger chat
   produces zero sends — both pinned by tests, asserted again in e2e.
3. **Alerts honest**: drop accounting counted and surfaced (test);
   the default alert set matches the spec table; unknown event type
   at runtime alerts raw (test).
4. **Message safety**: hostile-string corpus through every formatter;
   4096 truncation; `parse_mode` never sent (unit + e2e record scan).
5. **Additivity**: `git diff --stat v1.0.19..HEAD` touches no Go file
   outside `bot/`, `main/ngrok-bot/`, `version/version.go`,
   `client/config.go`, `client/config_test.go` (the two carry the
   fb697c3 post-1.0.19 correction that moved `proxy_transport` into
   the extracted validation — a release rider, not bot work; named
   here so the gate stays checkable against the real diff); `msg/`
   untouched; no `go.mod`/`go.sum` change at all.
6. **Full gates**: `go vet` + `go test` + `-race` for `bot/`; all
   three entry points build (debug + release tags); full e2e green
   including the new `bot` group.
7. Docs: README bot section (quickstart: create bot with BotFather,
   chat ID, env tokens, run beside ngrokd), CHANGELOG 1.0.20 (with the
   honest note that Telegram-side outages make the drop notice itself
   droppable), spec index row + status flip, version 20.

## Release

v1.0.20.
