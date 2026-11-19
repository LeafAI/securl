//go:build unix

package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/daemon"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
)

func toolState(t *testing.T, cs *mcp.ClientSession) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "vault_status", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out struct{ State string }
	json.Unmarshal(b, &out)
	return out.State
}

// The reason for -daemon: the stdio side and the socket side are one server, so what is opened on one is open on the other. The
// process starts the same way main does, with one mcpserver.New whose *mcp.Server both transports connect to.
func TestOneUnlockOpensTheStdioSideAndTheSocketSideBecauseTheyAreOneServer(t *testing.T) {
	dir, err := tmpShort(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Vault.Dir = filepath.Join(dir, "vault")
	cfg.Audit.File = filepath.Join(dir, "audit.jsonl")
	cfg.Daemon.Socket = filepath.Join(dir, "d.sock")
	v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
	if err := v.Init("a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Vault: v})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	sock, err := openSocket(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sock.serve(ctx, srv, app)
	t.Cleanup(func() { cancel(); sock.wait() })

	ct, st := mcp.NewInMemoryTransports() // stands for stdio: the same *mcp.Server, another transport
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	stdio, err := mcp.NewClient(&mcp.Implementation{Name: "stdio", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdio.Close() })
	c, err := daemon.Dial(ctx, cfg.Daemon.Socket)
	if err != nil {
		t.Fatal(err)
	}
	viaSocket, err := mcp.NewClient(&mcp.Implementation{Name: "sock", Version: "0"}, nil).Connect(ctx, &mcp.IOTransport{Reader: c, Writer: c}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { viaSocket.Close() })

	if a, b := toolState(t, stdio), toolState(t, viaSocket); a != "locked" || b != "locked" {
		t.Fatalf("both start locked: %q %q", a, b)
	}
	if err := app.UnlockWith("a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	if a, b := toolState(t, stdio), toolState(t, viaSocket); a != "unlocked" || b != "unlocked" {
		t.Errorf("one unlock opens both sides: stdio %q, socket %q", a, b)
	}
	app.Lock()
	if a, b := toolState(t, stdio), toolState(t, viaSocket); a != "locked" || b != "locked" {
		t.Errorf("one lock closes both sides: stdio %q, socket %q", a, b)
	}
}

func openServer(t *testing.T, withSocket bool) (*mcp.Server, *mcpserver.Server, *socketServer, *config.Config) {
	t.Helper()
	dir, err := tmpShort(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Vault.Dir = filepath.Join(dir, "vault")
	cfg.Audit.File = filepath.Join(dir, "audit.jsonl")
	cfg.Daemon.Socket = filepath.Join(dir, "d.sock")
	v := vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)
	if err := v.Init("a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Vault: v}) // Init leaves it open
	if err != nil {
		t.Fatal(err)
	}
	if err := app.UnlockWith("a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	sock, err := openSocket(cfg, withSocket)
	if err != nil {
		t.Fatal(err)
	}
	return srv, app, sock, cfg
}

// A process that served the socket leaves with the vault locked, as the daemon does, so that the passphrase is not kept past it.
func TestAProcessThatServedTheSocketLocksTheVaultWhenItFinishes(t *testing.T) {
	srv, app, sock, _ := openServer(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	sock.serve(ctx, srv, app)
	if app.VaultState() != vault.Unlocked {
		t.Fatalf("it starts unlocked: %v", app.VaultState())
	}
	cancel()
	finishServing(sock, app)
	if got := app.VaultState(); got != vault.Locked {
		t.Errorf("the vault is %v after the process finished: the passphrase is still held", got)
	}
}

// Without -daemon nothing about stdio changes: finishing does not touch the vault (the process just ends, as it always has).
func TestAProcessWithoutTheSocketDoesNotLockTheVaultWhenItFinishes(t *testing.T) {
	srv, app, sock, _ := openServer(t, false)
	_ = srv
	finishServing(sock, app)
	if got := app.VaultState(); got != vault.Unlocked {
		t.Errorf("the vault is %v: finishing changed what stdio alone has always done", got)
	}
}
