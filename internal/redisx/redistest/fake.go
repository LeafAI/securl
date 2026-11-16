// Package redistest is a fake Redis server for tests: it speaks RESP2 over TCP the way Redis does for the commands securl allows, and
// refuses what Redis refuses (a wrong password is -WRONGPASS, a command before AUTH is -NOAUTH, an unknown command is -ERR unknown
// command). It records every command it receives, in order, so that a test can prove what was and was not sent.
package redistest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

// Server is the fake. It keeps strings, hashes, lists, sets and sorted sets in memory.
type Server struct {
	Addr string

	mu       sync.Mutex
	ln       net.Listener
	password string
	user     string
	strs     map[string]string
	hashes   map[string]map[string]string
	lists    map[string][]string
	sets     map[string][]string
	zsets    map[string][]string // member, score pairs flattened: m1, s1, m2, s2
	ttl      map[string]int64
	cmds     [][]string
	closed   chan struct{}
	once     sync.Once
	conns    []net.Conn
	banner   string
	slow     chan struct{}
}

// SetBanner makes the fake answer every command with this simple string instead of working (a test of a server that lies).
func (s *Server) SetBanner(b string) { s.mu.Lock(); s.banner = b; s.mu.Unlock() }

// SetSlow makes every reply wait for this channel first, for timeout tests. A nil channel turns it off.
func (s *Server) SetSlow(c chan struct{}) { s.mu.Lock(); s.slow = c; s.mu.Unlock() }

// New starts the fake on a free loopback port. A password makes it demand AUTH (user may be empty: the legacy form).
func New(user, password string) *Server {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s := &Server{Addr: ln.Addr().String(), ln: ln, user: user, password: password, closed: make(chan struct{}),
		strs: map[string]string{}, hashes: map[string]map[string]string{}, lists: map[string][]string{}, sets: map[string][]string{},
		zsets: map[string][]string{}, ttl: map[string]int64{}}
	go s.accept()
	return s
}

// Close stops the server and drops every connection to it.
func (s *Server) Close() {
	s.once.Do(func() { close(s.closed) })
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

// SetString, SetHash, SetList, SetSet and SetZSet put data in.
func (s *Server) SetString(k, v string)          { s.mu.Lock(); s.strs[k] = v; s.mu.Unlock() }
func (s *Server) SetHash(k string, kv ...string) { s.mu.Lock(); s.hashes[k] = pairs(kv); s.mu.Unlock() }
func (s *Server) SetList(k string, v ...string)  { s.mu.Lock(); s.lists[k] = v; s.mu.Unlock() }
func (s *Server) SetSet(k string, v ...string)   { s.mu.Lock(); s.sets[k] = v; s.mu.Unlock() }
func (s *Server) SetZSet(k string, ms ...string) { s.mu.Lock(); s.zsets[k] = ms; s.mu.Unlock() }
func (s *Server) SetTTL(k string, seconds int64) { s.mu.Lock(); s.ttl[k] = seconds; s.mu.Unlock() }
func pairs(kv []string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// GetString reads a string the fake holds, for a test to see what a command did.
func (s *Server) GetString(k string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.strs[k]
	return v, ok
}

// Commands returns every command received, in order, with its arguments.
func (s *Server) Commands() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.cmds))
	for i, c := range s.cmds {
		out[i] = append([]string(nil), c...)
	}
	return out
}

// Names returns just the command names received (upper case), in order.
func (s *Server) Names() []string {
	var out []string
	for _, c := range s.Commands() {
		out = append(out, strings.ToUpper(c[0]))
	}
	return out
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
	r := bufio.NewReader(c)
	authed := s.password == ""
	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, args)
		slow, banner := s.slow, s.banner
		s.mu.Unlock()
		if slow != nil {
			select {
			case <-slow:
			case <-s.closed:
				return
			}
		}
		name := strings.ToUpper(args[0])
		var reply string
		switch {
		case banner != "":
			reply = "+" + banner + "\r\n"
		case name == "AUTH":
			reply, authed = s.auth(args[1:])
		case !authed:
			reply = "-NOAUTH Authentication required.\r\n"
		default:
			reply = s.run(name, args[1:])
		}
		if _, err := io.WriteString(c, reply); err != nil {
			return
		}
	}
}

func (s *Server) auth(a []string) (string, bool) {
	switch {
	case s.password == "":
		return "-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?\r\n", false
	case len(a) == 1 && s.user == "" && a[0] == s.password:
		return "+OK\r\n", true
	case len(a) == 2 && a[0] == s.user && a[1] == s.password:
		return "+OK\r\n", true
	}
	return "-WRONGPASS invalid username-password pair or user is disabled.\r\n", false
}

func readCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil // an inline command
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil || n < 0 || n > 1024 {
		return nil, fmt.Errorf("bad array")
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		h, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		h = strings.TrimRight(h, "\r\n")
		if !strings.HasPrefix(h, "$") {
			return nil, fmt.Errorf("bad bulk")
		}
		l, err := strconv.Atoi(h[1:])
		if err != nil || l < 0 || l > 64<<20 {
			return nil, fmt.Errorf("bad length")
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

func bulk(s string) string   { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }
func integer(n int64) string { return ":" + strconv.FormatInt(n, 10) + "\r\n" }
func nilBulk() string        { return "$-1\r\n" }
func array(items ...string) string {
	return "*" + strconv.Itoa(len(items)) + "\r\n" + strings.Join(items, "")
}
func bulks(v []string) string {
	items := make([]string, len(v))
	for i, x := range v {
		items[i] = bulk(x)
	}
	return array(items...)
}
func errReply(m string) string { return "-ERR " + m + "\r\n" }

func (s *Server) run(name string, a []string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch name {
	case "PING":
		return "+PONG\r\n"
	case "GET":
		if len(a) != 1 {
			return errReply("wrong number of arguments for 'get' command")
		}
		if v, ok := s.strs[a[0]]; ok {
			return bulk(v)
		}
		return nilBulk()
	case "MGET":
		items := make([]string, len(a))
		for i, k := range a {
			if v, ok := s.strs[k]; ok {
				items[i] = bulk(v)
			} else {
				items[i] = nilBulk()
			}
		}
		return array(items...)
	case "EXISTS":
		var n int64
		for _, k := range a {
			if s.has(k) {
				n++
			}
		}
		return integer(n)
	case "TYPE":
		if len(a) != 1 {
			return errReply("wrong number of arguments for 'type' command")
		}
		return "+" + s.kind(a[0]) + "\r\n"
	case "TTL":
		if !s.has(a[0]) {
			return integer(-2)
		}
		if t, ok := s.ttl[a[0]]; ok {
			return integer(t)
		}
		return integer(-1)
	case "STRLEN":
		return integer(int64(len(s.strs[a[0]])))
	case "HGET":
		if v, ok := s.hashes[a[0]][a[1]]; ok {
			return bulk(v)
		}
		return nilBulk()
	case "HGETALL":
		var flat []string
		for k, v := range s.hashes[a[0]] {
			flat = append(flat, k, v)
		}
		return bulks(flat)
	case "HLEN":
		return integer(int64(len(s.hashes[a[0]])))
	case "LRANGE":
		return bulks(slice(s.lists[a[0]], a[1], a[2]))
	case "LLEN":
		return integer(int64(len(s.lists[a[0]])))
	case "SMEMBERS":
		return bulks(s.sets[a[0]])
	case "SCARD":
		return integer(int64(len(s.sets[a[0]])))
	case "ZRANGE":
		return bulks(slice(s.zsets[a[0]], a[1], a[2]))
	case "ZCARD":
		return integer(int64(len(s.zsets[a[0]]) / 2))
	case "SCAN":
		var keys []string
		for k := range s.strs {
			keys = append(keys, k)
		}
		for k := range s.hashes {
			keys = append(keys, k)
		}
		return array(bulk("0"), bulks(keys))
	case "DBSIZE":
		return integer(int64(len(s.strs) + len(s.hashes) + len(s.lists) + len(s.sets) + len(s.zsets)))
	case "SET":
		if len(a) < 2 {
			return errReply("wrong number of arguments for 'set' command")
		}
		s.strs[a[0]] = a[1]
		return "+OK\r\n"
	case "DEL":
		var n int64
		for _, k := range a {
			if s.has(k) {
				n++
				delete(s.strs, k)
				delete(s.hashes, k)
				delete(s.lists, k)
				delete(s.sets, k)
				delete(s.zsets, k)
			}
		}
		return integer(n)
	case "INCR":
		n, _ := strconv.ParseInt(s.strs[a[0]], 10, 64)
		n++
		s.strs[a[0]] = strconv.FormatInt(n, 10)
		return integer(n)
	case "EXPIRE":
		if !s.has(a[0]) {
			return integer(0)
		}
		n, _ := strconv.ParseInt(a[1], 10, 64)
		s.ttl[a[0]] = n
		return integer(1)
	case "HSET":
		if s.hashes[a[0]] == nil {
			s.hashes[a[0]] = map[string]string{}
		}
		var n int64
		for i := 1; i+1 < len(a); i += 2 {
			if _, ok := s.hashes[a[0]][a[i]]; !ok {
				n++
			}
			s.hashes[a[0]][a[i]] = a[i+1]
		}
		return integer(n)
	case "FLUSHALL", "FLUSHDB":
		s.strs, s.hashes, s.lists, s.sets, s.zsets = map[string]string{}, map[string]map[string]string{}, map[string][]string{}, map[string][]string{}, map[string][]string{}
		return "+OK\r\n"
	case "CONFIG", "EVAL", "KEYS", "DEBUG", "SHUTDOWN", "SLAVEOF", "REPLICAOF", "MONITOR", "SCRIPT", "MODULE", "CLIENT", "SUBSCRIBE":
		return "+EXECUTED " + name + "\r\n" // a real Redis would do something; the fake says it ran, so a test can see it was let through
	}
	return "-ERR unknown command '" + name + "'\r\n"
}

func (s *Server) has(k string) bool {
	_, a := s.strs[k]
	_, b := s.hashes[k]
	_, c := s.lists[k]
	_, d := s.sets[k]
	_, e := s.zsets[k]
	return a || b || c || d || e
}

func (s *Server) kind(k string) string {
	switch {
	case func() bool { _, ok := s.strs[k]; return ok }():
		return "string"
	case func() bool { _, ok := s.hashes[k]; return ok }():
		return "hash"
	case func() bool { _, ok := s.lists[k]; return ok }():
		return "list"
	case func() bool { _, ok := s.sets[k]; return ok }():
		return "set"
	case func() bool { _, ok := s.zsets[k]; return ok }():
		return "zset"
	}
	return "none"
}

func slice(v []string, from, to string) []string {
	f, _ := strconv.Atoi(from)
	t, _ := strconv.Atoi(to)
	n := len(v)
	if f < 0 {
		f += n
	}
	if t < 0 {
		t += n
	}
	if f < 0 {
		f = 0
	}
	if t >= n {
		t = n - 1
	}
	if f > t || f >= n {
		return nil
	}
	return v[f : t+1]
}
