//go:build !unix

package main

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
)

// socketServer: there is no daemon on this system, so there is nothing to serve beside stdio.
type socketServer struct{}

func openSocket(_ *config.Config, want bool) (*socketServer, error) {
	if want {
		return nil, errors.New("securl --daemon: not available on this system (it needs a Unix socket and the system's report of who is on the other end); run without --daemon")
	}
	return &socketServer{}, nil
}

func (*socketServer) active() bool                                          { return false }
func (*socketServer) close()                                                {}
func (*socketServer) serve(context.Context, *mcp.Server, *mcpserver.Server) {}
func (*socketServer) wait()                                                 {}
