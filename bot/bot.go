package bot

// The Bot wiring and update routing (SPEC-CLUSTER20 §7). Every routing hop
// fails closed: a stranger produces zero messages, non-command text is
// ignored, an unknown command gets a hint, a command error becomes the error
// text. Nothing the chat can say widens what the bot does.

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	log "ngrok/log"
)

// logger is the package's voice in the log (the repo's ngrok/log, pointed at
// -log by the binary's main). Chat content never reaches it; wire errors and
// drop accounting do.
var logger log.Logger = log.NewPrefixLogger("bot")

// Bot owns the config, the two clients, the per-chat budgets, and the two
// pumps (alerts, health). One process watches one ngrokd (the multi-server
// non-goal: run more processes instead).
type Bot struct {
	cfg   *config
	admin *adminClient
	tg    *telegramClient

	mu      sync.Mutex
	budgets map[int64]chatBudget

	// now is the budget clock, swappable so the budget test can walk window
	// boundaries instead of sleeping a minute.
	now func() time.Time
}

// New builds the bot from a validated config. It performs no network calls:
// the identity check lives at the top of Run so that "the bot would run
// deaf" (a refused token) stops the process before any pump starts.
func New(cfg *config) (*Bot, error) {
	admin, err := newAdminClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Bot{
		cfg:     cfg,
		admin:   admin,
		tg:      newTelegramClient(cfg),
		budgets: make(map[int64]chatBudget),
		now:     time.Now,
	}, nil
}

// Run starts the pumps and blocks on the update loop until ctx is
// cancelled. The identity check runs first: a 401 here is the caller's
// non-zero exit, not a bot polling forever with a token nobody accepts.
// Shutdown drains nothing by design (§7) -- alerts in flight at SIGTERM may
// drop, and a shutdown notice is not worth the complexity it would need to
// be reliable.
func (b *Bot) Run(ctx context.Context) error {
	username, err := b.tg.identify(ctx)
	if err != nil {
		return err
	}
	logger.Info("authenticated as @%s; watching %s", username, b.cfg.AdminURL)

	go b.tg.runSender(ctx)
	go b.tg.runNotices(ctx)
	go b.pumpEvents(ctx)

	if b.cfg.HealthIntervalSeconds > 0 {
		watcher := &healthWatcher{
			admin:     b.admin,
			interval:  time.Duration(b.cfg.HealthIntervalSeconds) * time.Second,
			broadcast: func(text string) { b.broadcast(text) },
		}
		go watcher.run(ctx)
	} else {
		logger.Info("health watcher disabled (health_interval_seconds is 0)")
	}

	b.tg.runUpdates(ctx, b.handleUpdate)
	return ctx.Err()
}

// chatAllowed is the allowlist check, and it is the security boundary: the
// only place a chat id is compared against the config's set. Failures here
// are total -- no hint, no help, no error -- because a reply to a stranger
// is an ops-data leak dressed up as politeness.
func (b *Bot) chatAllowed(chat int64) bool {
	for _, allowed := range b.cfg.AllowedChats {
		if chat == allowed {
			return true
		}
	}
	return false
}

// handleUpdate routes one Telegram update: allowlist, then command parse,
// then budget, then run-and-reply.
func (b *Bot) handleUpdate(u telegramUpdate) {
	chat := u.Message.Chat.ID
	if !b.chatAllowed(chat) {
		return
	}

	text := strings.TrimSpace(u.Message.Text)
	// Plain non-command text is ignored entirely: group chats are noisy, and
	// the bot speaks when spoken to via commands (§4).
	if !strings.HasPrefix(text, "/") {
		return
	}

	// No arguments exist in the vocabulary; anything after the first space is
	// stripped rather than treated as a second command.
	name := strings.SplitN(strings.TrimPrefix(text, "/"), " ", 2)[0]
	// /start is Telegram's convention for "introduce yourself"; it is the
	// help text here like everywhere else.
	if name == "start" {
		name = "help"
	}

	allow, notice := b.allowBudget(chat, b.now())
	if !allow {
		if notice {
			b.tg.send(chat, "rate limited: "+strconv.Itoa(b.cfg.CommandRatePerMin)+" commands per minute; wait a minute")
		}
		return
	}

	if _, ok := commands[name]; !ok {
		b.tg.send(chat, "unknown command; send /help")
		return
	}

	// The command's own timeout bounds it (commandTimeoutFor); the process
	// context is not threaded down here because runUpdates owns it and a
	// command finishing after SIGTERM is bounded and harmless.
	b.tg.send(chat, b.runCommand(context.Background(), name))
}

// broadcast fans one alert line out to every allowed chat (the alerts and
// health paths).
func (b *Bot) broadcast(text string) {
	for _, chat := range b.cfg.AllowedChats {
		b.tg.send(chat, text)
	}
}
