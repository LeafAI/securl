//go:build unix

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LeafAI/securl/internal/climode"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/daemon"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
)

// runDaemon runs `securl daemon [-config file]` (the daemon) and `securl daemon status` (is one running).
func runDaemon(args []string) int {
	if !daemon.Supported {
		fmt.Fprintln(os.Stderr, "securl daemon: this system cannot tell who is on the other end of a socket, which a daemon needs; run the commands without it")
		return 3
	}
	if len(args) > 0 && args[0] == "status" {
		return daemonStatus(args[1:])
	}
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon: config: %v\n", err)
		return 3
	}
	sock := climode.SocketPath(climode.Env{Config: cfg})
	l, err := daemon.Listen(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl: %v\n", err)
		return 3
	}
	logf := func(format string, a ...any) { fmt.Fprintf(os.Stderr, "securl daemon: "+format+"\n", a...) }
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Log: logf, Vault: vault.New(cfg.Vault.Dir)})
	if err != nil {
		l.Close()
		fmt.Fprintf(os.Stderr, "securl daemon: setup: %v\n", err)
		return 3
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logf("listening on %s (the vault is %s)", sock, app.VaultState())
	daemon.Serve(ctx, l, srv, daemon.Options{Log: logf})
	app.Lock() // the passphrase is not kept past the daemon
	app.Close()
	logf("stopped")
	return 0
}

// daemonStatus says whether a daemon is running on the socket, and what state its vault is in.
func daemonStatus(args []string) int {
	args, path := climode.SplitConfig(args)
	if path == "" {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon: config: %v\n", err)
		return 3
	}
	_ = args
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	state, version, err := climode.DaemonState(ctx, climode.Env{Config: cfg, Err: os.Stderr})
	switch {
	case err == nil:
		fmt.Printf("daemon: running (version %s, vault %s) on %s\n", version, state, climode.SocketPath(climode.Env{Config: cfg}))
		return 0
	case climode.IsNotRunning(err):
		fmt.Printf("daemon: not running (%s)\n", climode.SocketPath(climode.Env{Config: cfg}))
		return 1
	}
	fmt.Fprintf(os.Stderr, "securl daemon: %v\n", err)
	return 3
}
