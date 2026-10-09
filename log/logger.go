package log

import (
	"encoding/json"
	"fmt"
	log "github.com/alecthomas/log4go"
	"strings"
	"sync"
	"time"
)

var root log.Logger = make(log.Logger)

// rootMu guards root and jsonFormat. The logger is a process-wide map of
// filters that every log call reads and LogTo rewrites, and log4go mutates and
// iterates that map without a lock of its own ("this function should not be
// called from multiple goroutines", says AddFilter). LogTo is therefore only
// safe as long as it cannot run while anything else is logging: it is called
// once at startup in Main, but a test that points the log at a file of its own
// -- or any future reconfiguration -- would otherwise be a data race on the
// filter map at best and a "concurrent map read and map write" crash at worst.
// Readers take the read lock, LogTo takes the write lock.
var (
	rootMu     sync.RWMutex
	jsonFormat bool
)

// LogTo points the process-wide root logger at target ("stdout", "none", or a
// file path) at the named level, in the named format. It is the one place a
// log level is set from user input, and an unrecognized level name is an
// error, not a silent fall-back to DEBUG: a level that is not what the
// operator asked for hides exactly the lines being debugged, and said nothing
// when it happened. The accepted set is the one both CLIs document --
// DEBUG, INFO, WARNING, ERROR. (It is narrower than log4go's own vocabulary:
// the undocumented FINEST/FINE/TRACE/CRITICAL spellings used to work by
// falling through this very switch, which is the drift being fixed here.)
//
// The error is returned before anything is mutated, so a refused call leaves
// the logger -- filter and format flag alike -- exactly as it was.
//
// server/main.go still discards the returned error (its call predates it);
// surfacing it there belongs to the server workstream. The client's Main
// turns it into the startup error it should be.
func LogTo(target string, level_name string, format string) error {
	rootMu.Lock()
	defer rootMu.Unlock()

	// Validate the level before anything else: a refused call must not have
	// touched the writer state or the format flag on its way out.
	var level log.Level
	switch level_name {
	case "DEBUG":
		level = log.DEBUG
	case "INFO":
		level = log.INFO
	case "WARNING":
		level = log.WARNING
	case "ERROR":
		level = log.ERROR
	default:
		return fmt.Errorf("Invalid log level %q: must be one of DEBUG, INFO, WARNING, ERROR", level_name)
	}

	var writer log.LogWriter = nil
	jsonFormat = strings.EqualFold(format, "json")

	switch target {
	case "stdout":
		writer = log.NewConsoleLogWriter()
	case "none":
		// no logging
	default:
		writer = log.NewFileLogWriter(target, true)
	}

	if writer != nil {
		root.AddFilter("log", level, writer)
	}

	return nil
}

type Logger interface {
	AddLogPrefix(string)
	SetLogPrefixes(...string)
	Debug(string, ...interface{})
	Info(string, ...interface{})
	Warn(string, ...interface{}) error
	Error(string, ...interface{}) error
}

type PrefixLogger struct {
	*log.Logger

	// mu guards prefix. The prefix is written by the connection-lifecycle
	// path -- loggedConn.SetType's SetLogPrefixes rename, and AddLogPrefix
	// at wrap time -- and read by every log call through the
	// logger, and the two run on different goroutines: RegisterProxy logs
	// "Registered" after handing the conn to the proxy pool, whose handout
	// side re-types it. pfx() therefore takes this lock on every log line,
	// and the cost is deliberate: one uncontended Lock/Unlock pair (~20ns)
	// is noise next to what the same call already pays -- the rootMu.RLock
	// pair in log(), the Sprintf, and log4go's handoff to its writer
	// goroutine. A plain Mutex rather than RWMutex (the critical sections on
	// either side are nanoseconds and the writers are per-conn-lifecycle
	// rare) or atomic.Value (AddLogPrefix's append is a read-modify-write;
	// plain atomics would leave two concurrent Adds free to silently lose
	// one, where the mutex linearizes every pair). It must not be rootMu:
	// log() already holds that read-lock when it calls pfx(), and recursive
	// read acquisition against a queued writer is RWMutex's documented
	// deadlock.
	mu     sync.Mutex
	prefix string
}

func NewPrefixLogger(prefixes ...string) Logger {
	logger := &PrefixLogger{Logger: &root}
	logger.SetLogPrefixes(prefixes...)
	return logger
}

// snapshotPrefix reads the prefix under the same lock the mutators hold, so a
// rename concurrent with a log call is observed whole or not at all -- never a
// torn string header.
func (pl *PrefixLogger) snapshotPrefix() string {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return pl.prefix
}

func (pl *PrefixLogger) pfx(fmtstr string) interface{} {
	return fmt.Sprintf("%s %s", pl.snapshotPrefix(), fmtstr)
}

func (pl *PrefixLogger) Debug(arg0 string, args ...interface{}) {
	pl.log("DEBUG", arg0, args...)
}

func (pl *PrefixLogger) Info(arg0 string, args ...interface{}) {
	pl.log("INFO", arg0, args...)
}

func (pl *PrefixLogger) Warn(arg0 string, args ...interface{}) error {
	return pl.log("WARNING", arg0, args...)
}

func (pl *PrefixLogger) Error(arg0 string, args ...interface{}) error {
	return pl.log("ERROR", arg0, args...)
}

// appendPrefixLocked joins one more prefix into the bracketed,
// space-separated form every log line carries. Callers must hold mu.
func (pl *PrefixLogger) appendPrefixLocked(prefix string) {
	if len(pl.prefix) > 0 {
		pl.prefix += " "
	}

	pl.prefix += "[" + prefix + "]"
}

func (pl *PrefixLogger) AddLogPrefix(prefix string) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.appendPrefixLocked(prefix)
}

// SetLogPrefixes replaces the whole prefix set under one acquisition of mu.
// The rename it exists for -- loggedConn.SetType -- used to run as a
// ClearLogPrefixes+AddLogPrefix pair: two critical sections, with a window
// between them where a concurrent log call observed a conn with no prefix at
// all, a line that reads as if it belongs to nothing. Renames ride this
// method so a reader sees the whole old prefix or the whole new one, never
// the empty between. Clearing without replacing is the zero-arg call.
func (pl *PrefixLogger) SetLogPrefixes(prefixes ...string) {
	pl.mu.Lock()
	defer pl.mu.Unlock()

	pl.prefix = ""
	for _, p := range prefixes {
		pl.appendPrefixLocked(p)
	}
}

func (pl *PrefixLogger) log(level string, format string, args ...interface{}) error {
	rootMu.RLock()
	defer rootMu.RUnlock()

	if jsonFormat {
		msg := fmt.Sprintf(format, args...)
		payload, _ := json.Marshal(map[string]string{
			"level": level,
			"time":  time.Now().UTC().Format(time.RFC3339Nano),
			"tag":   pl.snapshotPrefix(),
			"msg":   msg,
		})
		switch level {
		case "ERROR":
			return pl.Logger.Error("%s", string(payload))
		case "WARNING":
			return pl.Logger.Warn("%s", string(payload))
		case "DEBUG":
			pl.Logger.Debug("%s", string(payload))
			return nil
		default:
			pl.Logger.Info("%s", string(payload))
			return nil
		}
	}

	switch level {
	case "ERROR":
		return pl.Logger.Error(pl.pfx(format), args...)
	case "WARNING":
		return pl.Logger.Warn(pl.pfx(format), args...)
	case "DEBUG":
		pl.Logger.Debug(pl.pfx(format), args...)
		return nil
	default:
		pl.Logger.Info(pl.pfx(format), args...)
		return nil
	}
}

// we should never really use these . . . always prefer logging through a prefix logger
func Debug(arg0 string, args ...interface{}) {
	rootMu.RLock()
	defer rootMu.RUnlock()
	root.Debug(arg0, args...)
}

func Info(arg0 string, args ...interface{}) {
	rootMu.RLock()
	defer rootMu.RUnlock()
	root.Info(arg0, args...)
}

func Warn(arg0 string, args ...interface{}) error {
	rootMu.RLock()
	defer rootMu.RUnlock()
	return root.Warn(arg0, args...)
}

func Error(arg0 string, args ...interface{}) error {
	rootMu.RLock()
	defer rootMu.RUnlock()
	return root.Error(arg0, args...)
}
