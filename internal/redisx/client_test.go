package redisx

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/redisx/redistest"
)

const pw = "s3cret-Redis-PASSWORD-9f2"

func dial(t *testing.T, s *redistest.Server, user, pass string) (*Conn, error) {
	t.Helper()
	return Open(context.Background(), s.Addr, Credentials{Username: user, Password: pass}, Options{AllowLocal: true, Timeout: 2 * time.Second})
}

func TestAuthenticatesWithThePasswordAndRunsACommand(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	s.SetString("k", "v")
	c, err := dial(t, s, "", pw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v, err := c.Do(context.Background(), "GET", "k")
	if err != nil || v != "v" {
		t.Fatalf("%v %v", v, err)
	}
	if got := s.Names(); len(got) != 2 || got[0] != "AUTH" || got[1] != "GET" {
		t.Errorf("AUTH comes first, then the command: %v", got)
	}
}

func TestAUserAndPasswordUseTheTwoArgumentForm(t *testing.T) {
	s := redistest.New("alice", pw)
	defer s.Close()
	c, err := dial(t, s, "alice", pw)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if cmds := s.Commands(); len(cmds) < 1 || len(cmds[0]) != 3 || cmds[0][1] != "alice" {
		t.Errorf("%v", cmds)
	}
}

func TestAServerWithNoPasswordIsOpenedWithoutAuth(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, err := dial(t, s, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(context.Background(), "PING"); err != nil {
		t.Fatal(err)
	}
	for _, n := range s.Names() {
		if n == "AUTH" {
			t.Error("AUTH was sent to a server that has no password")
		}
	}
}

func TestAWrongPasswordIsBadCredentialsAndSaysNothingAboutIt(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	_, err := dial(t, s, "", "not-the-password-AAAA")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("%v", err)
	}
	for _, leak := range []string{"not-the-password", pw} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error repeats a password: %v", err)
		}
	}
}

func TestAPasswordWhereTheServerHasNoneIsBadCredentialsToo(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	if _, err := dial(t, s, "", "anything"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("%v", err)
	}
}

func TestACommandBeforeAuthIsRefusedByTheServerAndNeverReachesTheCaller(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	if _, err := dial(t, s, "", ""); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("a server that wants a password and was given none: %v", err)
	}
}

func TestRepliesOfEveryTypeAreReadAsTheyAre(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	s.SetString("s", "hello")
	s.SetList("l", "a", "b", "c")
	s.SetHash("h", "f1", "v1")
	c, _ := dial(t, s, "", "")
	defer c.Close()
	ctx := context.Background()
	for _, tc := range []struct {
		args []string
		want any
	}{
		{[]string{"GET", "s"}, "hello"},
		{[]string{"GET", "missing"}, nil},
		{[]string{"EXISTS", "s", "l"}, int64(2)},
		{[]string{"TYPE", "l"}, "list"},
		{[]string{"LRANGE", "l", "0", "-1"}, []any{"a", "b", "c"}},
		{[]string{"MGET", "s", "missing"}, []any{"hello", nil}},
		{[]string{"HGETALL", "h"}, []any{"f1", "v1"}},
		{[]string{"TTL", "missing"}, int64(-2)},
	} {
		got, err := c.Do(ctx, tc.args[0], tc.args[1:]...)
		if err != nil {
			t.Errorf("%v: %v", tc.args, err)
			continue
		}
		if !equal(got, tc.want) {
			t.Errorf("%v: got %#v, want %#v", tc.args, got, tc.want)
		}
	}
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	return a == b
}

// A value is binary-safe and may hold CR, LF and anything else: it is read by its length, never by looking for a line break.
func TestAValueWithLineBreaksAndBinaryIsReadByItsLength(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	val := "line1\r\nline2\x00\xff\r\n$5\r\nx"
	s.SetString("k", val)
	c, _ := dial(t, s, "", "")
	defer c.Close()
	got, err := c.Do(context.Background(), "GET", "k")
	if err != nil || got != val {
		t.Errorf("%q %v", got, err)
	}
}

func TestAnErrorReplyIsAnErrorWithTheServersWordsAndNoPassword(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	c, _ := dial(t, s, "", pw)
	defer c.Close()
	_, err := c.Do(context.Background(), "NOPE")
	var re *ReplyError
	if !errors.As(err, &re) || !strings.Contains(re.Message, "unknown command") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), pw) {
		t.Errorf("%v", err)
	}
}

// What a hostile or broken server sends must never make the client allocate what it asks for.
func TestAHugeLengthFromTheServerIsRefusedNotAllocated(t *testing.T) {
	for name, reply := range map[string]string{
		"bulk":     "$2147483647\r\n",
		"array":    "*2147483647\r\n",
		"negative": "$-5\r\n",
		"junk":     "?what\r\n",
		"nested":   strings.Repeat("*1\r\n", 100) + ":1\r\n",
	} {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			r := bufio.NewReader(c)
			r.ReadString('\n')
			io.WriteString(c, reply)
			time.Sleep(200 * time.Millisecond)
		}()
		c, err := Open(context.Background(), ln.Addr().String(), Credentials{}, Options{AllowLocal: true, Timeout: time.Second, MaxReply: 1 << 20})
		if err == nil {
			_, err = c.Do(context.Background(), "GET", "k")
			c.Close()
		}
		ln.Close()
		if err == nil {
			t.Errorf("%s: a reply that is not valid was accepted", name)
		}
	}
}

func TestAReplyOverTheLimitIsRefusedAndTheConnectionIsNotUsedAgain(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	s.SetString("big", strings.Repeat("x", 5000))
	c, err := Open(context.Background(), s.Addr, Credentials{}, Options{AllowLocal: true, Timeout: time.Second, MaxReply: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(context.Background(), "GET", "big"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
	if _, err := c.Do(context.Background(), "PING"); err == nil {
		t.Error("a connection that stopped in the middle of a reply is used again, and would read the rest of it as the next answer")
	}
}

func TestATimeoutIsATimeoutAndCarriesNothingOfTheAddress(t *testing.T) {
	s := redistest.New("", pw)
	defer s.Close()
	c, err := dial(t, s, "", pw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.SetSlow(make(chan struct{}))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err = c.Do(ctx, "GET", "k")
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), pw) {
		t.Errorf("%v", err)
	}
}

func TestNothingListeningIsUnreachableWithoutTheAddress(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	_, err := Open(context.Background(), addr, Credentials{Password: pw}, Options{AllowLocal: true, Timeout: time.Second})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), pw) {
		t.Errorf("%v", err)
	}
}

func TestAddressesOnThisMachineAreRefusedUnlessAllowed(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	_, err := Open(context.Background(), s.Addr, Credentials{}, Options{Timeout: time.Second})
	if !errors.Is(err, ErrLocalAddress) {
		t.Fatalf("%v", err)
	}
	if n := len(s.Commands()); n != 0 {
		t.Errorf("%d commands reached a server that should not have been dialled", n)
	}
}

func TestACommandIsSentAsABulkArrayNotAsText(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, _ := dial(t, s, "", "")
	defer c.Close()
	// an argument with a space and a line break is one argument, not several commands: the framing carries it by length
	c.Do(context.Background(), "GET", "a b\r\nFLUSHALL")
	cmds := s.Commands() // the first is the PING Open makes to find out whether the server wants a password
	if len(cmds) != 2 || cmds[0][0] != "PING" || len(cmds[1]) != 2 || cmds[1][1] != "a b\r\nFLUSHALL" {
		t.Errorf("%q", cmds)
	}
	for _, n := range s.Names() {
		if n == "FLUSHALL" {
			t.Error("an argument became a command")
		}
	}
}

func TestACancelledContextStopsBeforeAnythingIsSent(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, _ := dial(t, s, "", "")
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Do(ctx, "PING"); err == nil {
		t.Error("a cancelled call was made")
	}
}

// A server that repeats what it was sent in an error must not hand the password back.
func TestAServerThatEchoesThePasswordInAnErrorDoesNotGiveItBack(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		for {
			args, err := readArgs(r)
			if err != nil {
				return
			}
			if args[0] == "AUTH" {
				io.WriteString(c, "+OK\r\n")
				continue
			}
			io.WriteString(c, "-ERR bad thing near "+args[1]+" and the password "+pw+"\x07\x1b[31m\r\n")
		}
	}()
	c, err := Open(context.Background(), ln.Addr().String(), Credentials{Password: pw}, Options{AllowLocal: true, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Do(context.Background(), "GET", "k")
	var re *ReplyError
	if !errors.As(err, &re) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(re.Message, pw) || !strings.Contains(re.Message, "[removed]") {
		t.Errorf("the password came back, or was not marked as removed: %q", re.Message)
	}
	if strings.ContainsAny(re.Message, "\x07\x1b") {
		t.Errorf("control characters came back: %q", re.Message)
	}
}

func readArgs(r *bufio.Reader) ([]string, error) {
	l, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	n := 0
	for _, ch := range strings.TrimSpace(l)[1:] {
		n = n*10 + int(ch-'0')
	}
	var out []string
	for i := 0; i < n; i++ {
		h, _ := r.ReadString('\n')
		ln := 0
		for _, ch := range strings.TrimSpace(h)[1:] {
			ln = ln*10 + int(ch-'0')
		}
		buf := make([]byte, ln+2)
		io.ReadFull(r, buf)
		out = append(out, string(buf[:ln]))
	}
	return out, nil
}

// serveRaw makes a server that answers the first command with exactly these bytes, and returns a connection to it.
func serveRaw(t *testing.T, reply string, o Options) *Conn {
	t.Helper()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		readArgs(r) // the PING of Open
		io.WriteString(c, "+PONG\r\n")
		readArgs(r)
		io.WriteString(c, reply)
		time.Sleep(300 * time.Millisecond)
	}()
	o.AllowLocal, o.Timeout = true, time.Second
	c, err := Open(context.Background(), ln.Addr().String(), Credentials{}, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// An announced length is judged on the announcement: a server that says "$900000000" is refused before a byte of it is read, and
// nothing that size is allocated.
func TestALengthOverTheBudgetIsRefusedOnTheAnnouncementAlone(t *testing.T) {
	for name, reply := range map[string]string{
		"bulk":  "$5000\r\n",
		"array": "*5000\r\n",
	} {
		c := serveRaw(t, reply, Options{MaxReply: 1000})
		start := time.Now()
		_, err := c.Do(context.Background(), "GET", "k")
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", name, err)
		}
		if time.Since(start) > 500*time.Millisecond {
			t.Errorf("%s: it waited for the body, which never comes, instead of refusing the length", name)
		}
	}
}

func TestANestingDeeperThanTheLimitIsRefused(t *testing.T) {
	deep := strings.Repeat("*1\r\n", maxDepth+3) + ":1\r\n"
	c := serveRaw(t, deep, Options{})
	if _, err := c.Do(context.Background(), "GET", "k"); !errors.Is(err, ErrProtocol) {
		t.Errorf("%v", err)
	}
	ok := strings.Repeat("*1\r\n", maxDepth) + ":1\r\n"
	c2 := serveRaw(t, ok, Options{})
	if _, err := c2.Do(context.Background(), "GET", "k"); err != nil {
		t.Errorf("a nesting at the limit is fine: %v", err)
	}
}

func TestABulkStringWhoseEndIsNotCRLFIsRefused(t *testing.T) {
	c := serveRaw(t, "$3\r\nabcXY", Options{})
	if _, err := c.Do(context.Background(), "GET", "k"); !errors.Is(err, ErrProtocol) {
		t.Errorf("%v", err)
	}
}

// After an error that left the stream in the middle of a reply the connection is not used again: the next read would take the
// rest of that reply for the answer to the next command.
func TestAConnectionThatFailedInTheMiddleOfAReplyIsNotUsedAgainButOneThatGotAnErrorReplyIs(t *testing.T) {
	c := serveRaw(t, "$3\r\nabcXY", Options{})
	c.Do(context.Background(), "GET", "k")
	if _, err := c.Do(context.Background(), "PING"); !errors.Is(err, ErrClosed) {
		t.Errorf("a broken connection must refuse: %v", err)
	}
	s := redistest.New("", "")
	defer s.Close()
	c2, _ := dial(t, s, "", "")
	defer c2.Close()
	if _, err := c2.Do(context.Background(), "NOPE"); err == nil {
		t.Fatal("an unknown command is an error reply")
	}
	if _, err := c2.Do(context.Background(), "PING"); err != nil {
		t.Errorf("an error reply leaves the connection fine, and it must be usable: %v", err)
	}
}

func TestACancelledContextIsATimeoutAndSendsNothing(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, _ := dial(t, s, "", "")
	defer c.Close()
	before := len(s.Commands())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Do(ctx, "GET", "k"); !errors.Is(err, ErrTimeout) {
		t.Errorf("%v", err)
	}
	if len(s.Commands()) != before {
		t.Error("a command was sent on a cancelled context")
	}
}

// The context's deadline is honoured when it is sooner than the connection's own timeout.
func TestTheContextDeadlineBeatsTheConnectionTimeout(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, err := Open(context.Background(), s.Addr, Credentials{}, Options{AllowLocal: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.SetSlow(make(chan struct{}))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = c.Do(ctx, "GET", "k")
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 2*time.Second {
		t.Errorf("%v after %s", err, time.Since(start))
	}
}

func TestATimeoutOfTheConnectionAloneIsATimeoutToo(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, err := Open(context.Background(), s.Addr, Credentials{}, Options{AllowLocal: true, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.SetSlow(make(chan struct{}))
	if _, err := c.Do(context.Background(), "GET", "k"); !errors.Is(err, ErrTimeout) {
		t.Errorf("a silent server is a timeout, not an unreachable one: %v", err)
	}
}

// A message from a server is cut: it goes to a person and into a log, and a server that sends a megabyte of "error" must not.
func TestAnErrorMessageIsCutToALineOfSaneLength(t *testing.T) {
	c := serveRaw(t, "-ERR "+strings.Repeat("A", 5000)+"\r\n", Options{})
	_, err := c.Do(context.Background(), "GET", "k")
	var re *ReplyError
	if !errors.As(err, &re) || len(re.Message) != 200 {
		t.Fatalf("%v (%d)", err, func() int {
			if re != nil {
				return len(re.Message)
			}
			return -1
		}())
	}
}

// A cancelled context stops a call even when the server has not been slow yet: nothing is sent, and the connection stays usable.
func TestACancelledCallLeavesTheConnectionUsableAndSendsNothing(t *testing.T) {
	s := redistest.New("", "")
	defer s.Close()
	c, _ := dial(t, s, "", "")
	defer c.Close()
	n := len(s.Commands())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Do(ctx, "GET", "k")
	if len(s.Commands()) != n {
		t.Error("a command was sent on a cancelled context")
	}
	if _, err := c.Do(context.Background(), "PING"); err != nil {
		t.Errorf("declining a call is not damage to the connection: %v", err)
	}
}

// A line with no end is refused once it is longer than any real one, and the memory it would take is not kept.
func TestALineThatNeverEndsIsRefused(t *testing.T) {
	c := serveRaw(t, "+"+strings.Repeat("x", maxLine+10)+"\r\n", Options{MaxReply: 1 << 30})
	if _, err := c.Do(context.Background(), "GET", "k"); !errors.Is(err, ErrProtocol) {
		t.Errorf("%v", err)
	}
}

// An array can be as long as the budget allows and no longer, and a count that is only a lie is refused before the elements are read.
func TestAnArrayCountIsHeldToTheLimit(t *testing.T) {
	c := serveRaw(t, "*"+strconv.Itoa(maxArray+1)+"\r\n", Options{MaxReply: 1 << 30})
	if _, err := c.Do(context.Background(), "GET", "k"); !errors.Is(err, ErrProtocol) {
		t.Errorf("%v", err)
	}
}

// A write that fails (the server closed the connection) marks the connection broken, so the next call says so instead of writing
// into a socket nobody reads.
func TestAWriteThatFailsBreaksTheConnection(t *testing.T) {
	s := redistest.New("", "")
	c, _ := dial(t, s, "", "")
	defer c.Close()
	s.Close()
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 5; i++ { // the first write after a close can still succeed into the kernel's buffer
		c.Do(context.Background(), "GET", "k")
	}
	if _, err := c.Do(context.Background(), "GET", "k"); !errors.Is(err, ErrClosed) {
		t.Errorf("%v", err)
	}
}
