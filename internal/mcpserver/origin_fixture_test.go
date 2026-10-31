package mcpserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
)

// Origin metadata needs a real MCP exchange and local login API, but no browser interaction.
func originSetup(t *testing.T, agent, locked bool) (*env, *mcpserver.Server) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Load(dir + "/none.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Security.AllowLocalAddresses = true
	cfg.Security.LinkViaAgent = agent
	cfg.Web.PageURL = "https://page.example/"
	cfg.Web.TTL = time.Minute
	cfg.MCP.MaxBlockSeconds = 1
	cfg.Audit.File = dir + "/audit.jsonl"
	cfg.Vault.Dir = dir + "/vault"
	v := testVault(t, cfg)
	if locked {
		v.Lock()
	}
	rec := &recorder{}
	srv, app, err := mcpserver.New(cfg, mcpserver.Options{Notifier: rec, Tunnels: localTunnels{}, Vault: v, Log: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "origin-test", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	gl := fakeGitLab()
	t.Cleanup(gl.Close)
	return &env{cfg.Audit.File, cs, rec, dir, gl}, app
}
