//go:build unix

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/climode"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/daemon"
	"github.com/LeafAI/securl/internal/mcpserver"
)

// socketServer is the daemon's socket served from the same process as stdio. The zero value serves nothing.
type socketServer struct {
	l    net.Listener
	path string
	done chan struct{}
	once sync.Once
}

// openSocket makes the socket when -daemon was given, and returns a value that serves nothing when it was not. It fails when a daemon
// is already listening on the socket, or when this system cannot tell who is on the other end of one.
func openSocket(cfg *config.Config, want bool) (*socketServer, error) {
	if !want {
		return &socketServer{}, nil
	}
	if !daemon.Supported {
		return nil, errors.New("securl -daemon: this system cannot tell who is on the other end of a socket, which a daemon needs; run without -daemon")
	}
	path := climode.SocketPath(climode.Env{Config: cfg})
	l, err := daemon.Listen(path)
	if err != nil {
		return nil, err
	}
	return &socketServer{l: l, path: path, done: make(chan struct{})}, nil
}

// active is whether this process is serving the socket.
func (s *socketServer) active() bool { return s.l != nil }

func (s *socketServer) close() {
	if s.l != nil {
		s.l.Close()
	}
}

// serve runs the socket on the same server as stdio, so that both have one vault, one set of sessions and one set of limits.
func (s *socketServer) serve(ctx context.Context, srv *mcp.Server, app *mcpserver.Server) {
	if s.l == nil {
		return
	}
	log.Printf("securl: also listening on %s (the vault is %s)", s.path, app.VaultState())
	go func() {
		defer close(s.done)
		daemon.Serve(ctx, s.l, srv, daemon.Options{Log: log.Printf})
	}()
}

// wait returns once the socket has stopped serving and its file is gone. The process would very likely leave in time without it (the
// rest of the shutdown takes longer than closing a listener), but "the socket is closed before the process exits" is then a matter of
// timing and not something the program guarantees, so it waits.
func (s *socketServer) wait() {
	if s.l == nil {
		return
	}
	s.once.Do(func() { <-s.done })
}
