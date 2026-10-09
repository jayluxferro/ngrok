# SPEC-CLUSTER27 — workbench snapshot diffing: the tunnels tab tells you what changed

`/tunnels` polls redraw the table wholesale; an operator watching a flap
sees a table, not a story. This cluster diffs consecutive payloads SPA-side
and classifies the difference — added / removed / reconfigured / restarted
— surfacing it as a changes panel plus one-poll row highlights. Zero Go
changes: every field the diff needs already rides every `/tunnels` poll
(the spec-15 snapshot), and the classification runs on data, never on the
DOM.

## Objectives

1. Change classification on the existing `/tunnels` poll loop, keyed by
   `url`.
2. A capped, newest-first changes panel with a clear button, plus one-poll
   highlight on added/changed rows.
3. The watched-field immutability the diff rests on, PINNED by e2e — today
   it is a design intention, not a tested contract.
4. Zero server changes; zero new endpoints.

## Non-goals (binding)

- NO DOM diffing. Table render stays wholesale `clear()`+append (~360-377);
  the comment at app.js ~28-30 is AMENDED, not deleted — it bans DOM
  diffing, which stays true (stale-row bugs live there); the new code
  diffs DATA to classify and annotate, never patches the DOM.
- Counters (`active`/`total conns`/`bytes`) are NOT watched: they move
  every poll, and diffing them flashes every row every 2 seconds.
- No smoothing of pooled-owner flaps: pooled tunnels share a url and the
  store keys by url, so contention flaps `owner` between polls. The diff
   SHOWS `changed: owner` — that is the live-ops signal, not noise.
- NO `since=` delta endpoint: stateless auth (admin.go ~374-404) would need
  per-client server state to save hundreds of bytes per poll — a bad trade.
  `/events` SSE is fire-and-forget push with a 128-slot drop queue
  (observability.go ~179-182): a hint, not a picture. Poll+diff is the
  reconciliation.

## Design

### 1. SPA state

Previous payload + a changes list capped at ~200 entries (the `EV_CAP`
precedent, app.js ~382). Polls pause on hidden/inactive tabs (~153-192)
but state survives, so the return poll diffs the whole gap — "while you
were away" falls out free. The first poll after load is baseline only: no
changes are recorded against an empty prior.

### 2. Watched fields

The 7 registration facts + `protocol` + `started_at` — immutable per
registration (observability.go ~19-25). Key = `url` (the store's map key;
SPA sorts by it, ~365). A same-url watched-field change therefore proves
close + re-register (`onTunnelOpen` replaces the map entry, ~333) — the
strongest signal the data can produce.

### 3. Classification

One pass over prev/next key sets: `added` (new url), `removed` (missing
url), `changed` (watched-field diff). Sub-classify `changed` with one if:
any watched field OTHER than `started_at` differs → `reconfigured`; only
`started_at` differs → `restarted`.

### 4. UI

Collapsible changes panel on the tunnels tab, rows in the `addEventRow`
style (~431-458), newest-first, capped, clear button mirroring `ev-clear`
(~699-702). Added/changed table rows get a highlight class for exactly one
poll. All DOM via textContent; table rendering stays wholesale.

### 5. e2e — pins the DATA contract (curl can't run JS; the diff is asserted in python3 over consecutive payloads)

- Extend the existing second-tunnel scenario (admin2-2, ~4383-4411 — today
  it checks only owner+pooling): the added row must carry all 7 fact
  fields, typed.
- Kill that client; the consecutive-payload diff classifies `removed`.
- A surviving row's watched fields are byte-identical across polls.
- NEGATIVE (the pin that matters most): N polls 1s apart show zero watched
  change on untouched rows — guards any future mutation of "immutable"
  registration facts. Without this, the diff rests on an assumption
  nothing enforces.

## File ownership (workstreams)

- **A** — `assets/server/dashboard/app.js` (+ `style.css` panel/highlight
  classes; the comment amendment at ~28-30 rides here).
- **B** (after A) — `scripts/e2e_run.sh` (the data-contract scenarios).

## Review gates

1. Full e2e green (admin2 group extended); app.js diff greps clean of
   `innerHTML`/`localStorage`; polls still pause on hidden tabs.
2. The immutability negative test exists and passes — gate 5 above is a
   review gate, not a suggestion.
3. No new endpoint, no Go change: `git diff --stat` touches only app.js,
   style.css, scripts/e2e_run.sh.
4. CI green before tag.

## Release

Wave 3, first train (expected v1.0.26 — after presets, whose app.js work
this builds on; zero file overlap once presets has landed).
