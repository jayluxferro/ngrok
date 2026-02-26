package log

import (
	"encoding/json"
	"fmt"
	log "github.com/alecthomas/log4go"
	"strings"
	"time"
)

var root log.Logger = make(log.Logger)
var jsonFormat bool

func LogTo(target string, level_name string, format string) {
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
		var level = log.DEBUG

		switch level_name {
		case "FINEST":
			level = log.FINEST
		case "FINE":
			level = log.FINE
		case "DEBUG":
			level = log.DEBUG
		case "TRACE":
			level = log.TRACE
		case "INFO":
			level = log.INFO
		case "WARNING":
			level = log.WARNING
		case "ERROR":
			level = log.ERROR
		case "CRITICAL":
			level = log.CRITICAL
		default:
			level = log.DEBUG
		}

		root.AddFilter("log", level, writer)
	}
}

type Logger interface {
	AddLogPrefix(string)
	ClearLogPrefixes()
	Debug(string, ...interface{})
	Info(string, ...interface{})
	Warn(string, ...interface{}) error
	Error(string, ...interface{}) error
}

type PrefixLogger struct {
	*log.Logger
	prefix string
}

func NewPrefixLogger(prefixes ...string) Logger {
	logger := &PrefixLogger{Logger: &root}

	for _, p := range prefixes {
		logger.AddLogPrefix(p)
	}

	return logger
}

func (pl *PrefixLogger) pfx(fmtstr string) interface{} {
	return fmt.Sprintf("%s %s", pl.prefix, fmtstr)
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

func (pl *PrefixLogger) AddLogPrefix(prefix string) {
	if len(pl.prefix) > 0 {
		pl.prefix += " "
	}

	pl.prefix += "[" + prefix + "]"
}

func (pl *PrefixLogger) ClearLogPrefixes() {
	pl.prefix = ""
}

func (pl *PrefixLogger) log(level string, format string, args ...interface{}) error {
	if jsonFormat {
		msg := fmt.Sprintf(format, args...)
		payload, _ := json.Marshal(map[string]string{
			"level": level,
			"time":  time.Now().UTC().Format(time.RFC3339Nano),
			"tag":   pl.prefix,
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
	root.Debug(arg0, args...)
}

func Info(arg0 string, args ...interface{}) {
	root.Info(arg0, args...)
}

func Warn(arg0 string, args ...interface{}) error {
	return root.Warn(arg0, args...)
}

func Error(arg0 string, args ...interface{}) error {
	return root.Error(arg0, args...)
}
