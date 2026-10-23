package climode

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/mcpserver"
)

// drainLimit is the longest a command waits for the page to read the outcome of a login before it exits.
const drainLimit = 15 * time.Second

// connectApp starts the server in this process and connects a client to it over an in-memory transport. Nothing listens on
// a port or a socket: there is no other process that could reach it. The returned function shuts the server down: it ends
// any tunnel a login opened and, with lockOnClose, locks the vault again, so nothing outlives the command.
func connectApp(ctx context.Context, env Env, lockOnClose bool) (*mcp.ClientSession, func(), *mcpserver.Server, error) {
	opt := env.Server
	opt.Vault = env.Vault
	if opt.Log == nil {
		// What the server says while it works ("waiting for the human to complete the login step ...") is what a person at
		// a terminal needs to see during a long wait. It goes to stderr, with the answer alone on stdout.
		opt.Log = func(format string, args ...any) { fmt.Fprintf(env.Err, "securl: "+format+"\n", args...) }
	}
	srv, app, err := mcpserver.New(env.Config, opt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup: %w", err)
	}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		app.Close()
		return nil, nil, nil, fmt.Errorf("starting the server: %w", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "securl-cli", Version: mcpserver.Version}, nil).Connect(ctx, ct, nil)
	if err != nil {
		ss.Close()
		app.Close()
		return nil, nil, nil, fmt.Errorf("connecting to the server: %w", err)
	}
	return cs, func() {
		if lockOnClose {
			// A login that has just ended leaves its tunnel up for a moment so that the page can read the outcome. Exiting
			// now would show the person "Lost contact with the login server" for a login that worked.
			app.Drain(drainLimit)
		}
		cs.Close()
		ss.Close()
		if lockOnClose {
			app.Lock()
		}
		app.Close()
	}, app, nil
}

// inputSchemaOf reads the input schema of a listed tool.
func inputSchemaOf(t *mcp.Tool) (*jsonschema.Schema, error) {
	b, err := json.Marshal(t.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("%s: input schema: %w", t.Name, err)
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: input schema: %w", t.Name, err)
	}
	return &s, nil
}
