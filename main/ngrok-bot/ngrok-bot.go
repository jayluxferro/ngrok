package main

// ngrok-bot (SPEC-CLUSTER20): a read-only Telegram ops surface over ngrokd's
// admin API. The main is deliberately thin: flags, config, logging, signals,
// and bot.Run, in that order. All behavior lives in the bot package.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "ngrok/log"

	"ngrok/bot"
)

func main() {
	configPath := flag.String("config", bot.DefaultConfigPath(), "Path to the ngrok-bot YAML config file (default $HOME/.ngrok-bot)")
	logto := flag.String("log", "stdout", "Write log messages to this file. 'stdout' and 'none' have special meanings")
	loglevel := flag.String("log-level", "INFO", "The level of messages to log. One of: DEBUG, INFO, WARNING, ERROR")
	logformat := flag.String("log-format", "text", "Log format: text or json")
	flag.Parse()

	cfg, err := bot.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to load config:", err.Error())
		os.Exit(1)
	}

	if err := log.LogTo(*logto, *loglevel, *logformat); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// The startup line prints the config with both secrets masked (config.go
	// owns the masking; the test pins it). It is the one place the operator
	// can eyeball what the bot thinks it was told, which is worth more than
	// the log noise.
	log.Info("starting ngrok-bot with config:\n%s", cfg.String())

	b, err := bot.New(cfg)
	if err != nil {
		log.Error("failed to initialize: %v", err)
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("shutdown signal received")
		cancel()
	}()

	// Run's error at startup is the identity check (or a refused config
	// remnant) and exits non-zero; after a cancel it is just ctx.Err().
	if err := b.Run(ctx); err != nil {
		select {
		case <-ctx.Done():
			// Shutdown path: not a failure.
		default:
			log.Error("%v", err)
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}
}
