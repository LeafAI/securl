package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/LeafAI/securl/internal/climode"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
)

// runTool runs `securl <group> <command> --flags`: one MCP tool, from the command line. -config may stand anywhere.
func runTool(args []string) int {
	args, path, noDaemon, err := climode.Prepare(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl: %v\n", err)
		return 3
	}
	if path == "" {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl: config: %v\n", err)
		return 3
	}
	env := climode.Env{Config: cfg, Vault: vault.New(cfg.Vault.Dir), In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Server: mcpserver.Options{}, NoDaemon: noDaemon}
	// The passphrase is read here and nowhere else, and only from a terminal, without echo. A pipe, an argument or an
	// environment variable is never a source of it.
	if term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())) {
		env.Secret = func() (string, error) {
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			return string(b), err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return climode.Run(ctx, args, env)
}

// runUnlock runs `securl unlock [-config file]`: the person is asked to open the running daemon's vault, by link.
func runUnlock(args []string) int {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" {
			fmt.Println("usage: securl unlock [-config file]\n\nAsk the person to open the vault of the running daemon, and wait for them. The daemon sends a link (to DingTalk, or to this\nterminal with security.link_via_agent); the passphrase is typed on its page, never here. Exit 0 when the vault is open,\n3 when there is no daemon, 4 when nobody answered in time.")
			return 0
		}
	}
	args, path, noDaemon, err := climode.Prepare(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl: %v\n", err)
		return 3
	}
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "securl unlock: unexpected argument %q (see securl unlock --help)\n", args[0])
		return 2
	}
	if path == "" {
		path = config.DefaultPath()
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl: config: %v\n", err)
		return 3
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return climode.Unlock(ctx, climode.Env{Config: cfg, Vault: vault.New(cfg.Vault.Dir), In: os.Stdin, Out: os.Stdout, Err: os.Stderr, NoDaemon: noDaemon})
}
