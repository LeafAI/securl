// Package redisx is the part of the Redis protocol securl needs: connect, authenticate, send one command, read one reply.
//
// It is written for this and not taken from a library: RESP2 is a few kinds of line, the program needs one call, and every byte that
// comes back from a server is read by a parser whose limits are known. A reply whose size or depth the server chooses is bounded here
// (MaxReply, maxDepth), so that a server that is not Redis cannot make the program allocate what it names.
//
// The password is sent once, in AUTH, and is never part of an error: every error here is made of this package's own words.
package redisx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/LeafAI/securl/internal/netguard"
)

// Errors the callers act on.
var (
	ErrBadCredentials = errors.New("redis refused the password")
	ErrUnreachable    = errors.New("redis could not be reached")
	ErrTimeout        = errors.New("redis did not answer in time")
	ErrLocalAddress   = errors.New("that address is on this machine, which is not allowed here")
	ErrTooLarge       = errors.New("the reply is larger than the limit")
	ErrProtocol       = errors.New("the server did not answer in the Redis protocol")
	ErrClosed         = errors.New("the connection is closed")
)

// ReplyError is Redis answering with an error (the "-ERR ..." kind). Message is the server's own text, with the password taken out if
// it was repeated.
type ReplyError struct{ Message string }

func (e *ReplyError) Error() string { return "redis: " + e.Message }

// Credentials are what AUTH takes. A user name makes it the two-argument form (Redis 6 ACL); an empty password sends no AUTH.
type Credentials struct{ Username, Password string }

// Options tune a connection.
type Options struct {
	AllowLocal bool          // the address may be loopback or link-local (a test, or an owner who says so)
	Timeout    time.Duration // connecting, and each command when the context has no deadline (default 15 s)
	MaxReply   int           // the most bytes one reply may hold (default 1 MiB)
	TLS        func(net.Conn, string) (net.Conn, error)
}

const (
	defaultTimeout  = 15 * time.Second
	defaultMaxReply = 1 << 20
	maxDepth        = 8
	maxArray        = 100000
	maxLine         = 64 << 10
)

// Conn is one authenticated connection. It is safe for one command at a time.
type Conn struct {
	mu       sync.Mutex
	c        net.Conn
	r        *bufio.Reader
	secret   string
	timeout  time.Duration
	maxReply int
	budget   int
	broken   bool
}

// Open connects to addr (host:port) and authenticates.
func Open(ctx context.Context, addr string, cr Credentials, o Options) (*Conn, error) {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.MaxReply <= 0 {
		o.MaxReply = defaultMaxReply
	}
	dctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	nc, err := netguard.DialContext(o.AllowLocal)(dctx, "tcp", addr)
	if err != nil {
		switch {
		case errors.Is(err, netguard.ErrBlocked):
			return nil, ErrLocalAddress
		case errors.Is(dctx.Err(), context.DeadlineExceeded):
			return nil, fmt.Errorf("%w: connecting", ErrTimeout)
		}
		return nil, ErrUnreachable
	}
	if o.TLS != nil {
		host, _, _ := net.SplitHostPort(addr)
		tc, err := o.TLS(nc, host)
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("%w: TLS", ErrUnreachable)
		}
		nc = tc
	}
	c := &Conn{c: nc, r: bufio.NewReaderSize(nc, 4096), secret: cr.Password, timeout: o.Timeout, maxReply: o.MaxReply}
	if cr.Password != "" || cr.Username != "" {
		args := []string{"AUTH"}
		if cr.Username != "" {
			args = append(args, cr.Username)
		}
		args = append(args, cr.Password)
		if _, err := c.do(ctx, args); err != nil {
			c.Close()
			var re *ReplyError
			if errors.As(err, &re) && isAuthRefusal(re.Message) {
				return nil, ErrBadCredentials
			}
			return nil, err
		}
	} else if _, err := c.do(ctx, []string{"PING"}); err != nil {
		c.Close()
		var re *ReplyError
		if errors.As(err, &re) && isAuthRefusal(re.Message) {
			return nil, ErrBadCredentials // the server wants a password and none was given
		}
		return nil, err
	}
	return c, nil
}

func isAuthRefusal(m string) bool {
	m = strings.ToUpper(m)
	return strings.HasPrefix(m, "WRONGPASS") || strings.HasPrefix(m, "NOAUTH") || strings.Contains(m, "AUTH <PASSWORD> CALLED WITHOUT ANY PASSWORD") ||
		strings.Contains(m, "INVALID PASSWORD") || strings.Contains(m, "NOPERM") && strings.Contains(m, "AUTH")
}

// Do sends one command and returns its reply: a string (a simple or bulk string), an int64, nil, or a []any of those.
func (c *Conn) Do(ctx context.Context, name string, args ...string) (any, error) {
	return c.do(ctx, append([]string{name}, args...))
}

func (c *Conn) do(ctx context.Context, args []string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken || c.c == nil {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, ErrTimeout
	}
	nc := c.c // the callback below runs on another goroutine and must not read the field, which Close sets to nil
	nc.SetDeadline(time.Now().Add(c.timeout))
	// The context ends a call that is waiting, whether it was cancelled or its deadline came: the connection's own deadline is only the
	// longest a call may take when the context says nothing.
	stop := context.AfterFunc(ctx, func() { nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := io.WriteString(nc, encode(args)); err != nil {
		c.broken = true
		return nil, c.netErr(ctx, err)
	}
	c.budget = c.maxReply
	v, err := c.read(0)
	if err != nil {
		var re *ReplyError
		if errors.As(err, &re) {
			return nil, err // the connection is fine: Redis answered, with an error
		}
		c.broken = true
		return nil, c.netErr(ctx, err)
	}
	return v, nil
}

func (c *Conn) netErr(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, ErrTooLarge), errors.Is(err, ErrProtocol):
		return err
	case ctx.Err() != nil:
		return ErrTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrTimeout
	}
	return ErrUnreachable
}

// encode writes a command as RESP2 does: an array of bulk strings, each by its length, so that an argument holding a space or a line
// break is one argument and can never become a second command.
func encode(args []string) string {
	var b strings.Builder
	b.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		b.WriteString("$" + strconv.Itoa(len(a)) + "\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	return b.String()
}

func (c *Conn) spend(n int) error {
	c.budget -= n
	if c.budget < 0 {
		return ErrTooLarge
	}
	return nil
}

func (c *Conn) line() (string, error) {
	var out []byte
	for {
		part, isPrefix, err := c.r.ReadLine()
		if err != nil {
			return "", err
		}
		out = append(out, part...)
		if err := c.spend(len(part) + 2); err != nil {
			return "", err
		}
		if len(out) > maxLine {
			return "", ErrProtocol
		}
		if !isPrefix {
			return string(out), nil
		}
	}
}

func (c *Conn) read(depth int) (any, error) {
	if depth > maxDepth {
		return nil, ErrProtocol
	}
	l, err := c.line()
	if err != nil {
		return nil, err
	}
	if l == "" {
		return nil, ErrProtocol
	}
	body := l[1:]
	switch l[0] {
	case '+':
		return body, nil
	case '-':
		return nil, &ReplyError{Message: c.scrub(body)}
	case ':':
		n, err := strconv.ParseInt(body, 10, 64)
		if err != nil {
			return nil, ErrProtocol
		}
		return n, nil
	case '$':
		n, err := strconv.Atoi(body)
		if err != nil || n < -1 {
			return nil, ErrProtocol
		}
		if n == -1 {
			return nil, nil
		}
		if n > c.budget {
			return nil, ErrTooLarge // refused on the length it announces, before a byte of it is read
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		if err := c.spend(n + 2); err != nil {
			return nil, err
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return nil, ErrProtocol
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(body)
		if err != nil || n < -1 || n > maxArray {
			return nil, ErrProtocol
		}
		if n == -1 {
			return nil, nil
		}
		if n > c.budget { // every element is at least a few bytes: an array longer than what is left cannot be real
			return nil, ErrTooLarge
		}
		out := make([]any, 0, min(n, 1024))
		for i := 0; i < n; i++ {
			v, err := c.read(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, ErrProtocol
}

// scrub takes the password out of a message the server sent, in case it repeated it.
func (c *Conn) scrub(s string) string {
	if c.secret != "" {
		s = strings.ReplaceAll(s, c.secret, "[removed]")
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Close ends the connection.
func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.c != nil {
		c.c.Close()
		c.c = nil
	}
	c.broken = true
}
