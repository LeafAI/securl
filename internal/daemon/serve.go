//go:build unix

package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Options tune Serve. Zero values take safe defaults.
type Options struct {
	// MaxConns is how many commands are served at once (default 32). A connection over the limit is closed at once.
	MaxConns int
	// IdleHandshake is how long a connection may stay silent before it has started an MCP session (default 10 s): a client that
	// connects and says nothing must not hold a slot for ever.
	IdleHandshake time.Duration
	// CheckPeer decides whether a connection is served (default: CheckPeer, the same user). Tests give their own.
	CheckPeer func(net.Conn) error
	// Log receives one line per refused connection. It never receives anything a command sent.
	Log func(format string, args ...any)
}

func (o *Options) defaults() {
	if o.MaxConns <= 0 {
		o.MaxConns = 32
	}
	if o.IdleHandshake <= 0 {
		o.IdleHandshake = 10 * time.Second
	}
	if o.CheckPeer == nil {
		o.CheckPeer = CheckPeer
	}
	if o.Log == nil {
		o.Log = func(string, ...any) {}
	}
}

// Serve serves the MCP server on l until ctx ends: one MCP session per connection, all of them on the same server, so they
// share its vault, its sessions and its limits. It closes the listener and every connection before it returns.
func Serve(ctx context.Context, l net.Listener, srv *mcp.Server, opt Options) {
	opt.defaults()
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
		slots = make(chan struct{}, opt.MaxConns)
	)
	go func() {
		<-ctx.Done()
		l.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			opt.Log("daemon: accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err := opt.CheckPeer(c); err != nil {
			opt.Log("%v", err)
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			opt.Log("daemon: refusing a connection: %d are being served", opt.MaxConns)
			c.Close()
			continue
		}
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer func() { mu.Lock(); delete(conns, c); mu.Unlock(); c.Close() }()
			serveConn(ctx, c, srv, opt)
		}()
	}
	wg.Wait()
}

// serveConn runs one MCP session on a connection. A client that has not started a session within IdleHandshake is dropped.
func serveConn(ctx context.Context, c net.Conn, srv *mcp.Server, opt Options) {
	guard := &handshakeConn{Conn: c, limit: opt.IdleHandshake}
	guard.arm()
	ss, err := srv.Connect(ctx, &mcp.IOTransport{Reader: guard, Writer: guard}, nil)
	if err != nil {
		return
	}
	ss.Wait()
}

// handshakeConn puts a deadline on reads until the first complete message has come in; after that the session is the MCP
// server's own to manage, and a command may take as long as the person it waits for.
type handshakeConn struct {
	net.Conn
	limit time.Duration
	once  sync.Once
}

func (h *handshakeConn) arm() { h.Conn.SetReadDeadline(time.Now().Add(h.limit)) }

func (h *handshakeConn) Read(p []byte) (int, error) {
	n, err := h.Conn.Read(p)
	if n > 0 {
		h.once.Do(func() { h.Conn.SetReadDeadline(time.Time{}) })
	}
	return n, err
}
