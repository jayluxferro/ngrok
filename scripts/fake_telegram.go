//go:build ignore

// scripts/fake_telegram.go — the Bot API stand-in of the e2e bot group
// (SPEC-CLUSTER20): the three methods ngrok-bot actually speaks (getMe,
// getUpdates, sendMessage) plus the two endpoints the script uses to drive
// it, on one port.
//
// The envelope shapes are the real Bot API's, mirrored from bot/telegram.go's
// decoder: {"ok":true,"result":...} on success, {"ok":false,"description":..}
// with any HTTP status on refusal — the bot checks the ok bit, not the status,
// so the 401 mode answers 401 AND ok:false, exactly like the real API.
//
// The two script-side endpoints are what make absence provable:
//
//   POST /inject  — queue one update (object) or many (array). A held
//                   getUpdates long poll is woken and answers immediately,
//                   like the real server delivering a message mid-poll.
//   GET  /debug/offsets — the offset query param of the most recent
//                   getUpdates, plus the poll count. Scenario "stranger chat
//                   gets nothing" cannot be proven by sleeping: no reply is
//                   indistinguishable from a slow bot. The offset IS the
//                   witness — the bot advances it past every update it has
//                   processed, so once last_offset passes an injected
//                   update_id, "the bot saw it and sent nothing" is a fact,
//                   not a hope.
//
// sendMessage bodies are appended to -record one per line (JSONL). Go's
// json.Marshal never emits a raw newline inside a string, so the file stays
// line-greppable no matter what the messages contain.
//
// Build-ignored on purpose, like the other scripts/ helpers: test tooling,
// not module code. The harness prebuilds it to a binary (the standing e2e
// rule — a `go run` that listens orphans its compiled child past the cleanup
// trap) and runs that directly.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Updates travel as raw bytes end to end: the script injects them verbatim,
// the fake stores them verbatim, and the bot decodes them with its own
// telegramUpdate type — the fake never re-shapes a payload the scenarios
// assert about.
type fakeTelegram struct {
	addr   string
	record string
	refuse bool

	mu      sync.Mutex
	queue   []json.RawMessage
	notify  chan struct{} // closed (and replaced) on every inject: the wake for held polls
	nextID  int64         // sendMessage's message_id counter
	polls   int           // getUpdates calls served
	lastOff int64         // offset param of the most recent getUpdates (0 = none sent)

	recordMu sync.Mutex
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	record := flag.String("record", "", "append every sendMessage payload to this JSONL file")
	refuse := flag.Bool("refuse", false, "answer every Bot API call 401 ok:false (the dead-token mode)")
	flag.Parse()

	f := &fakeTelegram{addr: *addr, record: *record, refuse: *refuse, notify: make(chan struct{})}

	mux := http.NewServeMux()
	mux.HandleFunc("/inject", f.handleInject)
	mux.HandleFunc("/debug/offsets", f.handleOffsets)
	mux.HandleFunc("/", f.handleBotAPI)

	srv := &http.Server{Addr: f.addr, Handler: mux}
	log.Printf("fake telegram listening on %s (record=%s refuse=%v)", f.addr, f.record, f.refuse)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// splitBotPath parses "/bot<token>/<method>". The token rides the path (the
// Bot API's actual scheme) and may itself contain colons.
func splitBotPath(path string) (token, method string, ok bool) {
	rest := strings.TrimPrefix(path, "/")
	if !strings.HasPrefix(rest, "bot") {
		return "", "", false
	}
	rest = rest[len("bot"):]
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", "", false
	}
	return rest[:i], rest[i+1:], true
}

func (f *fakeTelegram) handleBotAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_, method, ok := splitBotPath(r.URL.Path)
	if !ok {
		http.Error(w, "not a bot api path", http.StatusNotFound)
		return
	}

	if f.refuse {
		// The dead-token answer: status AND envelope both say no, because the
		// bot checks the envelope's ok bit and the spec's scenario wants the
		// 401 the real API sends for a revoked token.
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"ok":false,"description":"Unauthorized"}`)
		return
	}

	switch method {
	case "getMe":
		fmt.Fprint(w, `{"ok":true,"result":{"id":999999999,"username":"e2e_ngrok_bot","first_name":"e2e"}}`)

	case "getUpdates":
		hold := time.Duration(0)
		if n, err := strconv.Atoi(r.URL.Query().Get("timeout")); err == nil && n > 0 {
			hold = time.Duration(n) * time.Second
		}
		offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		updates := f.takeUpdates(offset, hold)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"result":[`)
		for i, u := range updates {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			w.Write(u)
		}
		fmt.Fprint(w, `]}`)

	case "sendMessage":
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			fmt.Fprint(w, `{"ok":false,"description":"unreadable body"}`)
			return
		}
		if err := f.recordSend(raw); err != nil {
			log.Printf("record append failed: %v", err)
			fmt.Fprint(w, `{"ok":false,"description":"record write failed"}`)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d}}`, f.nextMessageID())

	default:
		// Unknown methods succeed emptily, like the unit fake: the bot only
		// speaks three methods, and a stricter answer would invent behavior
		// the real API does not share.
		fmt.Fprint(w, `{"ok":true,"result":{}}`)
	}
}

// takeUpdates implements Telegram's offset contract: updates with
// update_id < offset are acknowledged and discarded; the rest are returned in
// order and stay queued until a later offset supersedes them. An empty queue
// holds the poll up to `hold` (the long-poll timeout), waking the moment an
// inject arrives.
func (f *fakeTelegram) takeUpdates(offset int64, hold time.Duration) []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.polls++
	f.lastOff = offset

	if len(f.queue) == 0 && hold > 0 {
		timer := time.NewTimer(hold)
		defer timer.Stop()
		for len(f.queue) == 0 {
			wake := f.notify
			f.mu.Unlock()
			select {
			case <-wake:
			case <-timer.C:
				f.mu.Lock()
				return nil
			}
			f.mu.Lock()
		}
	}

	out := make([]json.RawMessage, 0, len(f.queue))
	kept := f.queue[:0]
	for _, u := range f.queue {
		var header struct {
			UpdateID int64 `json:"update_id"`
		}
		if err := json.Unmarshal(u, &header); err != nil {
			continue // not decodable as an update at all: drop, don't loop on it
		}
		if header.UpdateID < offset {
			continue // acknowledged
		}
		kept = append(kept, u)
		out = append(out, u)
	}
	f.queue = kept
	return out
}

func (f *fakeTelegram) handleInject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}

	// One update or an array of them — the script sends single updates, the
	// array form is here because it costs four lines.
	var batch []json.RawMessage
	var one json.RawMessage
	if err := json.Unmarshal(raw, &batch); err != nil {
		batch = nil
		if err := json.Unmarshal(raw, &one); err != nil {
			http.Error(w, "body is neither an update nor an array of updates", http.StatusBadRequest)
			return
		}
		batch = []json.RawMessage{one}
	}

	f.mu.Lock()
	f.queue = append(f.queue, batch...)
	close(f.notify)               // wake every held poll
	f.notify = make(chan struct{})
	n := len(batch)
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"ok":true,"queued":%d}`, n)
}

func (f *fakeTelegram) handleOffsets(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"polls":%d,"last_offset":%d}`, f.polls, f.lastOff)
}

// recordSend appends the payload byte-for-byte. The whole parse_mode gate
// (bot group scenario 9) scans this file, so the recorded bytes must be the
// sent bytes, not a re-marshal.
func (f *fakeTelegram) recordSend(raw []byte) error {
	f.recordMu.Lock()
	defer f.recordMu.Unlock()
	if f.record == "" {
		return nil
	}
	file, err := os.OpenFile(f.record, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(raw, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (f *fakeTelegram) nextMessageID() int64 {
	f.recordMu.Lock()
	defer f.recordMu.Unlock()
	f.nextID++
	return f.nextID
}
