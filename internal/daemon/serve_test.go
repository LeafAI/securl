//go:build unix

package daemon

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func echoServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "ping"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{ Pong bool }, error) {
		return nil, struct{ Pong bool }{true}, nil
	})
	return s
}

func startServing(t *testing.T, opt Options) (path string, stop func()) {
	t.Helper()
	path = filepath.Join(shortDir(t), "d.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Serve(ctx, l, echoServer(), opt); close(done) }()
	return path, func() { cancel(); <-done }
}

func client(t *testing.T, path string) *mcp.ClientSession {
	t.Helper()
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), &mcp.IOTransport{Reader: c, Writer: c}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func TestADaemonServesTheToolsOverItsSocket(t *testing.T) {
	path, stop := startServing(t, Options{})
	defer stop()
	cs := client(t, path)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"})
	if err != nil || res.IsError {
		t.Fatalf("%v %v", err, res)
	}
}

func TestSeveralCommandsAtOnceAreServedAtOnce(t *testing.T) {
	path, stop := startServing(t, Options{})
	defer stop()
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cs := client(t, path)
			if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"}); err != nil || res.IsError {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d of 8 concurrent commands failed", bad.Load())
	}
}

func TestTooManyConnectionsAreRefusedNotQueuedForever(t *testing.T) {
	path, stop := startServing(t, Options{MaxConns: 2})
	defer stop()
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := Dial(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		defer c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	extra, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1)
	if _, err := extra.Read(buf); err == nil {
		t.Error("a third connection was served although only two are allowed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("a connection over the limit is closed at once, not left hanging")
	}
	_ = held
}

func TestAConnectionThatSaysNothingIsClosed(t *testing.T) {
	path, stop := startServing(t, Options{IdleHandshake: 300 * time.Millisecond})
	defer stop()
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("expected the daemon to close the silent connection")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("a silent connection was left open: a client that never starts takes a slot for ever")
	}
}

func TestServeReturnsWhenItsContextEndsAndClosesTheSocket(t *testing.T) {
	path, stop := startServing(t, Options{})
	cs := client(t, path)
	stop()
	if _, err := Dial(context.Background(), path); !IsNotRunning(err) {
		t.Errorf("after the daemon stopped: %v", err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"}); err == nil {
		t.Error("a client of a stopped daemon still gets answers")
	}
}

func TestAConnectionOfAnotherUserNeverReachesTheServer(t *testing.T) {
	var reached atomic.Bool
	path := filepath.Join(shortDir(t), "d.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Serve(ctx, l, echoServer(), Options{CheckPeer: func(net.Conn) error { reached.Store(true); return net.ErrClosed }})
		close(done)
	}()
	defer func() { cancel(); <-done }()
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("a refused peer was served")
	}
	if !reached.Load() {
		t.Error("the peer check was not made")
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), &mcp.IOTransport{Reader: c, Writer: c}, nil)
	if err == nil {
		cs.Close()
		t.Error("an MCP session was opened for a refused peer")
	}
}

// The handshake deadline ends when the session has started. A command that then waits for a person for minutes (a login) must
// not be cut off by a deadline that was meant for a client that says nothing at all.
func TestTheHandshakeDeadlineDoesNotCutOffASessionThatHasStarted(t *testing.T) {
	path, stop := startServing(t, Options{IdleHandshake: 300 * time.Millisecond})
	defer stop()
	cs := client(t, path)
	time.Sleep(900 * time.Millisecond) // three times the handshake limit, with a live session and no traffic
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"}); err != nil || res.IsError {
		t.Fatalf("the session was cut off after its handshake: %v %v", err, res)
	}
}

// With the limit at N, N more are refused and the ones being served keep working; a slot frees when a connection ends.
func TestTheConnectionLimitCountsOnlyTheConnectionsBeingServed(t *testing.T) {
	path, stop := startServing(t, Options{MaxConns: 2})
	defer stop()
	a, b := client(t, path), client(t, path)
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("a third connection was served")
	}
	if res, err := a.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"}); err != nil || res.IsError {
		t.Errorf("a connection being served was disturbed by the refused one: %v", err)
	}
	b.Close()
	deadline := time.Now().Add(5 * time.Second)
	var ok bool
	for time.Now().Before(deadline) && !ok {
		d, err := Dial(context.Background(), path)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), &mcp.IOTransport{Reader: d, Writer: d}, nil)
		if err == nil {
			cs.Close()
			ok = true
		}
		d.Close()
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Error("a slot was not freed when a connection ended")
	}
}
