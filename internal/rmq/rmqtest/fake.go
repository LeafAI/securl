// Package rmqtest is a fake RocketMQ (a NameServer and one Broker, in one process) for tests. It speaks the part of the remoting
// protocol securl uses the way a real broker does, and checks the ACL signature the way a real broker does, with the algorithm read
// from the broker's own classes: the access key is an extension field, and the signature is the base64 of the HmacSHA1 of the secret
// over the sorted values of the extension fields (not the signature itself) followed by the body.
//
// What it refuses, it refuses with what the real broker answers: an ACL refusal is code 1 with the reason in the remark, a pull at the
// end of a queue is 19, one far past it or before the start is 21, a group that does not exist is 24, a topic that does not exist is 17.
package rmqtest

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Account is one ACL account of the fake.
type Account struct {
	AccessKey, SecretKey string
	Admin                bool
	// SubTopics may be subscribed to; Groups are the consumer groups the account may use. A missing permission is refused as the real
	// broker refuses it.
	SubTopics, Groups []string
}

// Message is one message in a queue.
type Message struct {
	Body   []byte
	Tags   string
	Keys   string
	Props  map[string]string
	Stored time.Time
	// Compressed stores the body compressed and says so in the system flag, as a producer that compresses does. Compression is the
	// type bits of the flag: 0 or 0x300 is zlib (the body is zlib-compressed), 0x100 is LZ4 and 0x200 ZSTD (the body is stored as it
	// is and the flag says what a client that cannot read them must say no to).
	Compressed  bool
	Compression int32
	// V2 writes the second magic code, whose topic length is two bytes instead of one.
	V2 bool
	// V6 writes the born host and the store host as 16-byte IPv6 addresses and says so in the system flag.
	V6 bool
}

// Request is what the fake received.
type Request struct {
	Code   int
	Ext    map[string]string
	Addr   string
	Signed bool
}

// Server is the fake. It is the NameServer and the Broker at once: the route it answers names its own address.
type Server struct {
	Addr string

	mu       sync.Mutex
	ln       net.Listener
	accounts map[string]*Account
	topics   map[string][][]Message // per topic, per queue
	groups   map[string]bool
	reqs     []Request
	closed   chan struct{}
	once     sync.Once
	// Slow makes every answer wait on this channel first, for timeout tests.
	slow chan struct{}
	// RouteAddr overrides the broker address the route names (a test of a route that points somewhere else).
	routeAddr string
	// failQueue makes a queue answer with this response code ("topic#queue"), the others as usual.
	failQueue map[string]int
	// perPull caps how many messages one pull returns (0: as many as asked), and delay is how long each answer takes.
	perPull int
	delay   time.Duration
	// answer, when set, replaces the broker's answer to a code with raw bytes, for a test of a server that lies.
	rawAnswer map[int][]byte
}

// New starts the fake on a free loopback port. With no account, ACL is off.
func New(accounts ...Account) *Server {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	s := &Server{Addr: ln.Addr().String(), ln: ln, accounts: map[string]*Account{}, topics: map[string][][]Message{}, groups: map[string]bool{}, closed: make(chan struct{}), rawAnswer: map[int][]byte{}}
	for i := range accounts {
		a := accounts[i]
		s.accounts[a.AccessKey] = &a
	}
	go s.accept()
	return s
}

// Close stops the server.
func (s *Server) Close() { s.once.Do(func() { close(s.closed) }); s.ln.Close() }

// AddTopic makes a topic with this many queues.
func (s *Server) AddTopic(name string, queues int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.topics[name] = make([][]Message, queues)
}

// Put adds a message to a queue.
func (s *Server) Put(topic string, queue int, m Message) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Stored.IsZero() {
		m.Stored = time.Unix(1_700_000_000, 0).Add(time.Duration(len(s.topics[topic][queue])) * time.Second)
	}
	s.topics[topic][queue] = append(s.topics[topic][queue], m)
}

// AddGroup makes a consumer group exist on the broker.
func (s *Server) AddGroup(name string) { s.mu.Lock(); s.groups[name] = true; s.mu.Unlock() }

// SetSlow makes every answer wait for this channel first. A nil channel turns it off.
func (s *Server) SetSlow(c chan struct{}) { s.mu.Lock(); s.slow = c; s.mu.Unlock() }

// SetRouteAddr makes the route name this broker address instead of the fake's own.
func (s *Server) SetRouteAddr(a string) { s.mu.Lock(); s.routeAddr = a; s.mu.Unlock() }

// FailQueue makes the offsets and pulls of one queue answer with a response code and nothing else.
func (s *Server) FailQueue(topic string, queue, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failQueue == nil {
		s.failQueue = map[string]int{}
	}
	s.failQueue[fmt.Sprintf("%s#%d", topic, queue)] = code
}

// SetPerPull caps how many messages one pull returns, as a broker with a small batch size does.
func (s *Server) SetPerPull(n int) { s.mu.Lock(); s.perPull = n; s.mu.Unlock() }

// SetDelay makes every answer take this long.
func (s *Server) SetDelay(d time.Duration) { s.mu.Lock(); s.delay = d; s.mu.Unlock() }

// SetRaw makes the answer to a request code these exact bytes (after the frame's length), for a test of a server that lies.
func (s *Server) SetRaw(code int, b []byte) { s.mu.Lock(); s.rawAnswer[code] = b; s.mu.Unlock() }

// Requests returns every request received, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// Codes returns the request codes received, in order.
func (s *Server) Codes() []int {
	var out []int
	for _, r := range s.Requests() {
		out = append(out, r.Code)
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

type frame struct {
	Code      int               `json:"code"`
	Language  string            `json:"language"`
	Version   int               `json:"version"`
	Opaque    int               `json:"opaque"`
	Flag      int               `json:"flag"`
	Remark    string            `json:"remark,omitempty"`
	ExtFields map[string]string `json:"extFields,omitempty"`
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		var lb [4]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		total := binary.BigEndian.Uint32(lb[:])
		if total < 4 || total > 8<<20 {
			return
		}
		b := make([]byte, total)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		hl := binary.BigEndian.Uint32(b[:4])
		if hl>>24 != 0 { // only JSON
			return
		}
		hlen := int(hl & 0xFFFFFF)
		if 4+hlen > len(b) {
			return
		}
		var f frame
		if err := json.Unmarshal(b[4:4+hlen], &f); err != nil {
			return
		}
		body := b[4+hlen:]
		s.mu.Lock()
		slow, raw, delay := s.slow, s.rawAnswer[f.Code], s.delay
		s.mu.Unlock()
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-s.closed:
				return
			}
		}
		if slow != nil {
			select {
			case <-slow:
			case <-s.closed:
				return
			}
		}
		if raw != nil {
			c.Write(raw)
			continue
		}
		resp, rbody := s.handle(c, f, body)
		resp.Opaque, resp.Flag, resp.Language, resp.Version = f.Opaque, 1, "JAVA", 475
		if _, err := c.Write(encode(resp, rbody)); err != nil {
			return
		}
	}
}

func encode(f frame, body []byte) []byte {
	h, _ := json.Marshal(f)
	total := 4 + len(h) + len(body)
	out := make([]byte, 4+total)
	binary.BigEndian.PutUint32(out, uint32(total))
	binary.BigEndian.PutUint32(out[4:], uint32(len(h)))
	copy(out[8:], h)
	copy(out[8+len(h):], body)
	return out
}

// Sign is the signature the real broker expects.
func Sign(ext map[string]string, body []byte, secret string) string {
	keys := make([]string, 0, len(ext))
	for k := range ext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if k != "Signature" {
			b.WriteString(ext[k])
		}
	}
	m := hmac.New(sha1.New, []byte(secret))
	m.Write(append([]byte(b.String()), body...))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) handle(c net.Conn, f frame, body []byte) (frame, []byte) {
	ext := f.ExtFields
	if ext == nil {
		ext = map[string]string{}
	}
	signed := ext["Signature"] != ""
	s.mu.Lock()
	s.reqs = append(s.reqs, Request{Code: f.Code, Ext: cloneMap(ext), Addr: c.RemoteAddr().String(), Signed: signed})
	acl := len(s.accounts) > 0
	s.mu.Unlock()
	if f.Code != 105 && acl { // a NameServer does not check ACL; the broker does
		if why := s.check(f, ext, body); why != "" {
			return frame{Code: 1, Remark: "org.apache.rocketmq.acl.common.AclException: " + why + ", org.apache.rocketmq.acl.plain.PlainAccessValidator.validate"}, nil
		}
	}
	switch f.Code {
	case 105:
		return s.route(ext["topic"])
	case 30, 31:
		return s.offsets(f.Code, ext)
	case 11:
		return s.pull(ext)
	}
	return frame{Code: 1, Remark: fmt.Sprintf("request code %d not supported", f.Code)}, nil
}

func cloneMap(m map[string]string) map[string]string {
	o := make(map[string]string, len(m))
	for k, v := range m {
		o[k] = v
	}
	return o
}

// check returns why the ACL refuses, or "" when it allows.
func (s *Server) check(f frame, ext map[string]string, body []byte) string {
	ak := ext["AccessKey"]
	if ak == "" {
		return "No accessKey is configured"
	}
	s.mu.Lock()
	a := s.accounts[ak]
	s.mu.Unlock()
	if a == nil {
		return "No acl config for " + ak
	}
	if Sign(ext, body, a.SecretKey) != ext["Signature"] {
		return "Check signature failed for accessKey=" + ak
	}
	if a.Admin {
		return ""
	}
	topic := ext["topic"]
	if !contains(a.SubTopics, topic) {
		if topicHas(a, topic) {
			return "No permission for topic:" + topic
		}
		return "No default permission for topic:" + topic
	}
	if f.Code == 11 {
		if g := ext["consumerGroup"]; !contains(a.Groups, g) {
			return "No default permission for group:" + g
		}
	}
	return ""
}

func topicHas(a *Account, topic string) bool { return false }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (s *Server) route(topic string) (frame, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	qs, ok := s.topics[topic]
	if !ok {
		return frame{Code: 17, Remark: "No topic route info in name server for the topic: " + topic}, nil
	}
	addr := s.routeAddr
	if addr == "" {
		addr = s.Addr
	}
	// The real NameServer's JSON has integer keys that are not quoted ({0:"127.0.0.1:30911"}), which is not valid JSON.
	body := fmt.Sprintf(`{"brokerDatas":[{"brokerAddrs":{0:%q},"brokerName":"broker-a","cluster":"DefaultCluster","enableActingMaster":false}],"filterServerTable":{},"queueDatas":[{"brokerName":"broker-a","perm":6,"readQueueNums":%d,"topicSysFlag":0,"writeQueueNums":%d}]}`, addr, len(qs), len(qs))
	return frame{Code: 0}, []byte(body)
}

func (s *Server) queue(topic, qid string) ([]Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	qs, ok := s.topics[topic]
	n, err := strconv.Atoi(qid)
	if !ok || err != nil || n < 0 || n >= len(qs) {
		return nil, false
	}
	return append([]Message(nil), qs[n]...), true
}

func (s *Server) failed(ext map[string]string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.failQueue[ext["topic"]+"#"+ext["queueId"]]
	return c, ok
}

func (s *Server) offsets(code int, ext map[string]string) (frame, []byte) {
	if c, bad := s.failed(ext); bad {
		return frame{Code: c, Remark: "failed on purpose"}, nil
	}
	q, ok := s.queue(ext["topic"], ext["queueId"])
	if !ok {
		return frame{Code: 1, Remark: "queueId[" + ext["queueId"] + "] is illegal"}, nil
	}
	n := 0
	if code == 30 {
		n = len(q)
	}
	return frame{Code: 0, ExtFields: map[string]string{"offset": strconv.Itoa(n)}}, nil
}

func (s *Server) pull(ext map[string]string) (frame, []byte) {
	topic := ext["topic"]
	if c, bad := s.failed(ext); bad {
		return frame{Code: c, Remark: "failed on purpose"}, nil
	}
	q, ok := s.queue(topic, ext["queueId"])
	if !ok {
		return frame{Code: 1, Remark: "queueId[" + ext["queueId"] + "] is illegal, topic:[" + topic + "]"}, nil
	}
	s.mu.Lock()
	known := s.groups[ext["consumerGroup"]]
	s.mu.Unlock()
	sysFlag, _ := strconv.Atoi(ext["sysFlag"])
	if !known && sysFlag&4 == 0 {
		return frame{Code: 24, Remark: "the consumer's group info not exist"}, nil
	}
	if !known && ext["subscription"] == "" {
		return frame{Code: 24, Remark: "the consumer's group info not exist"}, nil
	}
	off, err := strconv.ParseInt(ext["queueOffset"], 10, 64)
	if err != nil {
		return frame{Code: 1, Remark: "bad queueOffset"}, nil
	}
	max, _ := strconv.Atoi(ext["maxMsgNums"])
	s.mu.Lock()
	if s.perPull > 0 && s.perPull < max {
		max = s.perPull
	}
	s.mu.Unlock()
	hdr := func(next int64) map[string]string {
		return map[string]string{"nextBeginOffset": strconv.FormatInt(next, 10), "minOffset": "0", "maxOffset": strconv.Itoa(len(q)), "suggestWhichBrokerId": "0", "groupSysFlag": "0", "topicSysFlag": "0"}
	}
	switch {
	case off < 0:
		return frame{Code: 21, Remark: "OFFSET_TOO_SMALL", ExtFields: hdr(0)}, nil
	case off > int64(len(q)):
		return frame{Code: 21, Remark: "OFFSET_OVERFLOW_BADLY", ExtFields: hdr(int64(len(q)))}, nil
	case off == int64(len(q)):
		return frame{Code: 19, Remark: "OFFSET_OVERFLOW_ONE", ExtFields: hdr(off)}, nil
	}
	var out []byte
	end := off
	for i := off; i < int64(len(q)) && int(i-off) < max; i++ {
		out = append(out, EncodeMessage(topic, atoi(ext["queueId"]), i, q[i])...)
		end = i + 1
	}
	return frame{Code: 0, Remark: "FOUND", ExtFields: hdr(end)}, out
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// EncodeMessage writes one message the way a broker stores it and hands it to a consumer: the layout read from the broker's own
// decoder (MessageDecoder), and checked against messages a real broker returned.
func EncodeMessage(topic string, queue int, offset int64, m Message) []byte {
	body := m.Body
	var sys int32
	if m.Compressed {
		if m.Compression == 0 || m.Compression == 0x300 {
			body = Deflate(body)
		}
		sys |= 0x1 | m.Compression
	}
	if m.V6 {
		sys |= 0x10 | 0x20
	}
	props := ""
	for k, v := range m.Props {
		props += k + "\x01" + v + "\x02"
	}
	if m.Tags != "" {
		props += "TAGS\x01" + m.Tags + "\x02"
	}
	if m.Keys != "" {
		props += "KEYS\x01" + m.Keys + "\x02"
	}
	host := func() []byte {
		if m.V6 {
			return net.ParseIP("::1").To16()
		}
		return []byte{127, 0, 0, 1}
	}
	b := make([]byte, 0, 128+len(body)+len(props))
	u32 := func(v int32) { b = binary.BigEndian.AppendUint32(b, uint32(v)) }
	u64 := func(v int64) { b = binary.BigEndian.AppendUint64(b, uint64(v)) }
	u32(0) // the total length, filled in at the end
	if m.V2 {
		u32(-626843477) // magic 0xdaa320ab: version 2, whose topic length is a short
	} else {
		u32(-626843481) // magic 0xdaa320a7: version 1, whose topic length is a byte
	}
	u32(0)                         // body crc
	u32(int32(queue))              // queue id
	u32(0)                         // flag
	u64(offset)                    // queue offset
	u64(offset * 100)              // physical offset
	u32(sys)                       // system flag
	u64(m.Stored.UnixMilli())      // born timestamp
	b = append(b, host()...)       // born host
	u32(41286)                     // born port
	u64(m.Stored.UnixMilli() + 11) // store timestamp
	b = append(b, host()...)       // store host
	u32(10911)                     // store port
	u32(0)                         // reconsume times
	u64(0)                         // prepared transaction offset
	u32(int32(len(body)))          // body length
	b = append(b, body...)
	if m.V2 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(topic)))
	} else {
		b = append(b, byte(len(topic)))
	}
	b = append(b, topic...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(props)))
	b = append(b, props...)
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	return b
}
