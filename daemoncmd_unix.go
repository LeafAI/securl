//go:build unix

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LeafAI/securl/internal/climode"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/daemon"
	"github.com/LeafAI/securl/internal/daemonlog"
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
	if len(args) > 0 {
		if handled, code := daemonAgent(args[0], args[1:]); handled {
			return code
		}
	}
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	cfgPath := fs.String("config", config.DefaultPath(), "config file")
	logSpec := fs.String("log", "", `where to write the log instead of standard error: an absolute path, or "default" for Library/Logs/securl-daemon.log in the home of the user who runs it (what the login agent uses: launchd gives a job no terminal)`)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logOut, closeLog, err := openDaemonLog(*logSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon: %v\n", err)
		return 3
	}
	defer closeLog()
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(logOut, "securl daemon: config: %v\n", err)
		return 3
	}
	sock := climode.SocketPath(climode.Env{Config: cfg})
	l, err := daemon.Listen(sock)
	if err != nil {
		fmt.Fprintf(logOut, "securl: %v\n", err)
		return 3
	}
	logf := func(format string, a ...any) { fmt.Fprintf(logOut, "securl daemon: "+format+"\n", a...) }
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Log: logf, Vault: vault.New(cfg.Vault.Dir)})
	if err != nil {
		l.Close()
		fmt.Fprintf(logOut, "securl daemon: setup: %v\n", err)
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
	line := agentStatusLine(path)
	switch {
	case err == nil:
		fmt.Printf("daemon: running (version %s, vault %s) on %s\n", version, state, climode.SocketPath(climode.Env{Config: cfg}))
		if line != "" {
			fmt.Println(line)
		}
		return 0
	case climode.IsNotRunning(err):
		fmt.Printf("daemon: not running (%s)\n", climode.SocketPath(climode.Env{Config: cfg}))
		if line != "" {
			fmt.Println(line)
		}
		return 1
	}
	fmt.Fprintf(os.Stderr, "securl daemon: %v\n", err)
	return 3
}

// openDaemonLog is where the daemon's messages go: standard error, or the file that -log names. A log that cannot be opened stops the
// daemon with the reason: started by launchd with nowhere to say it, it would otherwise run and tell nobody anything.
func openDaemonLog(spec string) (io.Writer, func(), error) {
	home, _ := os.UserHomeDir()
	path, err := daemonlog.Resolve(spec, home)
	if err != nil {
		return nil, nil, err
	}
	if path == "" {
		return os.Stderr, func() {}, nil
	}
	f, err := daemonlog.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}
