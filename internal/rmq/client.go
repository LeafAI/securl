// Package rmq is the part of the Apache RocketMQ remoting protocol securl needs to READ messages: ask a NameServer where a topic is,
// ask a broker how long a queue is, and pull messages from it. It cannot send a message, create a topic or touch an offset, because
// none of that is written here: what is not in the package cannot be done with it.
//
// It is written for this and not taken from a library: the frames are a length, a JSON header and a body, the ACL signature is one
// HMAC, and every byte that comes back is read by a parser whose limits are known. The layout of a stored message, the request codes
// and the signature were read from the broker's own classes and checked against a real 5.3.1 broker (ACL on), not remembered.
//
// Reading never consumes: a pull is made with no commit flag and no commit offset, and it does not wait on the broker, so the
// consumers of a topic lose nothing and the group's position does not move.
//
// The AccessKey and the SecretKey are never part of an error: every error here is made of this package's own words.
package rmq

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/LeafAI/securl/internal/netguard"
)

// Errors the callers act on.
var (
	ErrBadCredentials   = errors.New("the broker refused the access key or the secret key")
	ErrNoPermission     = errors.New("the key has no permission for that topic or group")
	ErrTopicNotFound    = errors.New("the topic does not exist")
	ErrGroupNotFound    = errors.New("the consumer group does not exist on the broker")
	ErrUnreachable      = errors.New("RocketMQ could not be reached")
	ErrTimeout          = errors.New("RocketMQ did not answer in time")
	ErrLocalAddress     = errors.New("that address is on this machine, which is not allowed here")
	ErrTooLarge         = errors.New("the reply is larger than the limit")
	ErrProtocol         = errors.New("the server did not answer in the RocketMQ protocol")
	ErrOffsetOutOfRange = errors.New("the offset is outside the queue")
)

// Request codes, read from the broker's RequestCode class.
const (
	codeGetMaxOffset = 30
	codePull         = 11
	codeRoute        = 105
)

// Response codes, read from ResponseCode.
const (
	respSuccess        = 0
	respSystemError    = 1
	respNoPermission   = 16
	respTopicNotExist  = 17
	respPullNotFound   = 19
	respPullRetry      = 20
	respOffsetMoved    = 21
	respSubNotExist    = 24
	respGroupNotExist  = 26
	pullSysFlagSubscr  = 4 // PullSysFlag.FLAG_SUBSCRIPTION: send the subscription; no commit flag (1), no suspend flag (2)
	magicV1            = -626843481
	magicV2            = -626843477
	flagCompressed     = 1
	flagBornHostV6     = 16
	flagStoreHostV6    = 32
	compressionTypeMsk = 0x700
)

// Limits on what a server can make this package do.
const (
	maxFrame           = 16 << 20
	maxHeader          = 64 << 10
	maxMessagesPerPull = 64
	maxQueuesPerTopic  = 1024
	maxPropsLen        = 32 << 10
	maxPropValue       = 256
)

// Credentials are the access key and the secret key of an ACL account. Both empty: no ACL.
type Credentials struct{ AccessKey, SecretKey string }

// Options tune a client.
type Options struct {
	AllowLocal bool
	Timeout    time.Duration
	// Group is the consumer group the pulls are made as. It must exist on the broker (or be created by a pull, if the broker allows),
	// and the key must be allowed to use it.
	Group string
	// MaxReply bounds the bytes of one frame (default 4 MiB); MaxBody bounds one message body, inflated included (default 1 MiB).
	MaxReply, MaxBody int
	TLS               func(net.Conn, string) (net.Conn, error)
}

// Client reads from one cluster.
type Client struct {
	ns   []string
	cred Credentials
	opt  Options
}

// New makes a client for the NameServers (host:port).
func New(nameServers []string, cred Credentials, o Options) *Client {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.MaxReply <= 0 {
		o.MaxReply = 4 << 20
	}
	if o.MaxBody <= 0 {
		o.MaxBody = 1 << 20
	}
	return &Client{ns: nameServers, cred: cred, opt: o}
}

// Queue is one queue of a topic on one broker.
type Queue struct {
	Topic, Broker, Addr string
	ID                  int
}

// Route says where a topic's queues are.
type Route struct {
	Topic  string
	Queues []Queue
}

// Message is one message as a broker stores it.
type Message struct {
	Topic       string
	Queue       int
	QueueOffset int64
	Tags, Keys  string
	Props       map[string]string
	Body        []byte
	// BodyUnreadable says why Body is empty or cut: a compression this client cannot read, or a body over the limit.
	BodyUnreadable string
	BornTime       time.Time
	StoreTime      time.Time
	Reconsume      int32
}

// PullResult is what a pull found.
type PullResult struct {
	Messages             []Message
	NextOffset           int64
	MinOffset, MaxOffset int64
}

// ---- the wire ----

type header struct {
	Code      int               `json:"code"`
	Language  string            `json:"language"`
	Version   int               `json:"version"`
	Opaque    int               `json:"opaque"`
	Flag      int               `json:"flag"`
	Remark    string            `json:"remark,omitempty"`
	ExtFields map[string]string `json:"extFields,omitempty"`
}

// sign is the signature of RocketMQ's AclClientRPCHook: the base64 of the HmacSHA1 of the secret over the values of the extension
// fields, in the order of their names, without the signature itself, followed by the body.
func sign(ext map[string]string, body []byte, secret string) string {
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

func (c *Client) dial(ctx context.Context, addr string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()
	nc, err := netguard.DialContext(c.opt.AllowLocal)(dctx, "tcp", addr)
	if err != nil {
		switch {
		case errors.Is(err, netguard.ErrBlocked):
			return nil, ErrLocalAddress
		case errors.Is(dctx.Err(), context.DeadlineExceeded):
			return nil, fmt.Errorf("%w: connecting", ErrTimeout)
		}
		return nil, ErrUnreachable
	}
	if c.opt.TLS != nil {
		host, _, _ := net.SplitHostPort(addr)
		tc, err := c.opt.TLS(nc, host)
		if err != nil {
			nc.Close()
			return nil, fmt.Errorf("%w: TLS", ErrUnreachable)
		}
		nc = tc
	}
	return nc, nil
}

// call sends one request and reads one answer on a connection of its own. signed adds the access key and the signature.
func (c *Client) call(ctx context.Context, addr string, code int, ext map[string]string, signed bool) (header, []byte, error) {
	if err := ctx.Err(); err != nil {
		return header{}, nil, ErrTimeout
	}
	nc, err := c.dial(ctx, addr)
	if err != nil {
		return header{}, nil, err
	}
	defer nc.Close()
	deadline := time.Now().Add(c.opt.Timeout)
	nc.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { nc.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	ext = cloneExt(ext)
	if signed && c.cred.AccessKey != "" {
		ext["AccessKey"] = c.cred.AccessKey
		ext["Signature"] = sign(ext, nil, c.cred.SecretKey)
	}
	h, err := json.Marshal(header{Code: code, Language: "GO", Version: 0, Opaque: 1, ExtFields: ext})
	if err != nil {
		return header{}, nil, ErrProtocol
	}
	if len(h) > maxHeader {
		return header{}, nil, ErrProtocol // a request is a few fields: one this large is a bug, and it is not sized from
	}
	frame := make([]byte, 8, 8+len(h))
	binary.BigEndian.PutUint32(frame, uint32(4+len(h)))
	binary.BigEndian.PutUint32(frame[4:], uint32(len(h))) // serialization type 0: JSON
	frame = append(frame, h...)
	if _, err := nc.Write(frame); err != nil {
		return header{}, nil, c.netErr(ctx, err)
	}
	return c.read(ctx, nc)
}

func cloneExt(m map[string]string) map[string]string {
	o := make(map[string]string, len(m)+2)
	for k, v := range m {
		o[k] = v
	}
	return o
}

func (c *Client) read(ctx context.Context, nc net.Conn) (header, []byte, error) {
	var lb [4]byte
	if _, err := io.ReadFull(nc, lb[:]); err != nil {
		return header{}, nil, c.netErr(ctx, err)
	}
	total := binary.BigEndian.Uint32(lb[:])
	if total < 4 {
		return header{}, nil, ErrProtocol
	}
	if int64(total) > int64(c.opt.MaxReply) || total > maxFrame {
		return header{}, nil, ErrTooLarge // judged on the length it announces, before a byte of it is read
	}
	b := make([]byte, total)
	if _, err := io.ReadFull(nc, b); err != nil {
		return header{}, nil, c.netErr(ctx, err)
	}
	hl := binary.BigEndian.Uint32(b[:4])
	if hl>>24 != 0 {
		return header{}, nil, ErrProtocol // only JSON is spoken here
	}
	hlen := int(hl & 0xFFFFFF)
	if hlen > maxHeader || 4+hlen > len(b) {
		return header{}, nil, ErrProtocol
	}
	var h header
	if err := json.Unmarshal(b[4:4+hlen], &h); err != nil {
		return header{}, nil, ErrProtocol
	}
	return h, b[4+hlen:], nil
}

func (c *Client) netErr(ctx context.Context, err error) error {
	switch {
	case ctx.Err() != nil:
		return ErrTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ErrTimeout
	}
	return ErrUnreachable
}

// refusal turns what a broker answers into this package's errors. The remark is the broker's own text and is matched, never repeated:
// it can name the key, and a broker that is not one can put anything in it.
func refusal(h header) error {
	r := strings.ToLower(h.Remark)
	switch h.Code {
	case respSuccess:
		return nil
	case respNoPermission:
		return ErrNoPermission
	case respTopicNotExist:
		return ErrTopicNotFound
	case respSubNotExist, respGroupNotExist:
		return ErrGroupNotFound
	case respSystemError:
		switch {
		case strings.Contains(r, "check signature failed"), strings.Contains(r, "no acl config for"), strings.Contains(r, "no accesskey is configured"),
			strings.Contains(r, "accesskey"):
			return ErrBadCredentials
		case strings.Contains(r, "no permission"), strings.Contains(r, "no default permission"):
			return ErrNoPermission
		case strings.Contains(r, "group") && strings.Contains(r, "not exist"):
			return ErrGroupNotFound
		}
	}
	return fmt.Errorf("%w: the broker refused the request (%d)", ErrProtocol, h.Code)
}

// ---- route ----

type routeJSON struct {
	BrokerDatas []struct {
		Name  string            `json:"brokerName"`
		Addrs map[string]string `json:"brokerAddrs"`
	} `json:"brokerDatas"`
	QueueDatas []struct {
		Name string `json:"brokerName"`
		Read int    `json:"readQueueNums"`
		Perm int    `json:"perm"`
	} `json:"queueDatas"`
}

// A NameServer's route is not valid JSON: the keys of brokerAddrs are integers and are not quoted ({0:"10.0.0.1:10911"}). They are
// quoted here, and only there, before the document is read.
var unquotedKey = regexp.MustCompile(`([{,])\s*(\d+)\s*:`)

func parseRoute(b []byte) (*Route, error) {
	var r routeJSON
	if err := json.Unmarshal(unquotedKey.ReplaceAll(b, []byte(`$1"$2":`)), &r); err != nil {
		return nil, ErrProtocol
	}
	master := map[string]string{}
	for _, d := range r.BrokerDatas {
		addr, ok := d.Addrs["0"]
		if !ok {
			continue // a broker with no master is not read from: a replica may lag
		}
		if err := validAddr(addr); err != nil {
			return nil, err
		}
		master[d.Name] = addr
	}
	out := &Route{}
	for _, q := range r.QueueDatas {
		addr, ok := master[q.Name]
		if !ok {
			continue
		}
		if q.Read < 0 || q.Read > maxQueuesPerTopic || len(out.Queues)+q.Read > maxQueuesPerTopic {
			return nil, ErrProtocol
		}
		if q.Perm&4 == 0 { // the topic is not readable on this broker
			continue
		}
		for i := 0; i < q.Read; i++ {
			out.Queues = append(out.Queues, Queue{Broker: q.Name, Addr: addr, ID: i})
		}
	}
	if len(out.Queues) == 0 {
		return nil, ErrProtocol
	}
	return out, nil
}

// validAddr accepts host:port and nothing else: a route is somebody else's server speaking, and it must not be able to name a URL, a
// user or a path as an address.
func validAddr(a string) error {
	h, p, err := net.SplitHostPort(a)
	if err != nil || h == "" {
		return ErrProtocol
	}
	if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
		return ErrProtocol
	}
	if net.ParseIP(h) == nil && !regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$`).MatchString(h) {
		return ErrProtocol
	}
	return nil
}

// Route asks the NameServers where a topic is, one after another until one answers. A NameServer that says the topic does not exist
// has answered, and the others are not asked. The request is not signed: a NameServer is not given the key.
func (c *Client) Route(ctx context.Context, topic string) (*Route, error) {
	return c.routeWith(ctx, topic, c.opt.AllowLocal)
}

// routeWith is Route with the rule for the broker's address given: the NameServer's own address is held to Options.AllowLocal in dial.
func (c *Client) routeWith(ctx context.Context, topic string, allowLocalBroker bool) (*Route, error) {
	var last error = ErrUnreachable
	for _, ns := range c.ns {
		h, body, err := c.call(ctx, ns, codeRoute, map[string]string{"topic": topic}, false)
		if err != nil {
			if errors.Is(err, ErrLocalAddress) {
				return nil, err
			}
			last = err
			continue
		}
		if h.Code == respTopicNotExist {
			return nil, ErrTopicNotFound
		}
		if err := refusal(h); err != nil {
			last = err
			continue
		}
		r, err := parseRoute(body)
		if err != nil {
			last = err
			continue
		}
		r.Topic = topic
		for i := range r.Queues {
			r.Queues[i].Topic = topic
		}
		if !allowLocalBroker {
			for _, q := range r.Queues {
				if netguard.LocalHost(hostOf(q.Addr)) {
					return nil, ErrLocalAddress
				}
			}
		}
		return r, nil
	}
	return nil, last
}

func hostOf(addr string) string {
	h, _, _ := net.SplitHostPort(addr)
	return h
}

// ---- offsets and pulls ----

// MaxOffset is how many messages a queue has had: the offset the next one will get.
func (c *Client) MaxOffset(ctx context.Context, q Queue) (int64, error) {
	h, _, err := c.call(ctx, q.Addr, codeGetMaxOffset, map[string]string{"topic": q.Topic, "queueId": strconv.Itoa(q.ID), "committed": "true"}, true)
	if err != nil {
		return 0, err
	}
	if err := refusal(h); err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(h.ExtFields["offset"], 10, 64)
	if err != nil || n < 0 {
		return 0, ErrProtocol
	}
	return n, nil
}

// Pull reads up to max messages of a queue from an offset. It commits nothing and does not wait: see the package comment.
func (c *Client) Pull(ctx context.Context, q Queue, offset int64, max int) (*PullResult, error) {
	if max < 1 {
		max = 1
	}
	if max > maxMessagesPerPull {
		max = maxMessagesPerPull
	}
	h, body, err := c.call(ctx, q.Addr, codePull, map[string]string{
		"consumerGroup": c.opt.Group, "topic": q.Topic, "queueId": strconv.Itoa(q.ID), "queueOffset": strconv.FormatInt(offset, 10),
		"maxMsgNums": strconv.Itoa(max), "sysFlag": strconv.Itoa(pullSysFlagSubscr), "commitOffset": "0", "suspendTimeoutMillis": "0",
		"subscription": "*", "subVersion": "0", "expressionType": "TAG",
	}, true)
	if err != nil {
		return nil, err
	}
	res := &PullResult{NextOffset: extInt(h, "nextBeginOffset"), MinOffset: extInt(h, "minOffset"), MaxOffset: extInt(h, "maxOffset")}
	switch h.Code {
	case respSuccess:
		msgs, err := decodeMessages(body, c.opt.MaxBody, true)
		if err != nil {
			return nil, err
		}
		res.Messages = msgs
		return res, nil
	case respPullNotFound, respPullRetry:
		return res, nil // nothing new
	case respOffsetMoved:
		return res, ErrOffsetOutOfRange
	}
	return nil, refusal(h)
}

func extInt(h header, k string) int64 {
	n, _ := strconv.ParseInt(h.ExtFields[k], 10, 64)
	return n
}

// ---- messages ----

// decodeMessages reads the messages a pull answers with, one after another. Every length in a message is checked against what is left
// of it: bytes a server sent are never trusted to say how much of them there is.
func decodeMessages(b []byte, maxBody int, inflate bool) ([]Message, error) {
	var out []Message
	for off := 0; off < len(b); {
		if len(out) >= maxMessagesPerPull {
			return nil, fmt.Errorf("%w: more messages than a pull may hold", ErrProtocol)
		}
		if len(b)-off < 4 {
			return nil, ErrProtocol
		}
		total := int(binary.BigEndian.Uint32(b[off:]))
		if total < 4+4+4+4+4+8+8+4+8+4+4+8+4+4+8+4+1+2 || off+total > len(b) || total < 0 {
			return nil, ErrProtocol
		}
		m, err := decodeOne(b[off+4:off+total], maxBody, inflate)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
		off += total
	}
	return out, nil
}

type reader struct {
	b   []byte
	i   int
	bad bool
}

func (r *reader) take(n int) []byte {
	if n < 0 || r.i+n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v
}
func (r *reader) u32() int32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return int32(binary.BigEndian.Uint32(v))
}
func (r *reader) u64() int64 {
	v := r.take(8)
	if v == nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(v))
}
func (r *reader) u16() int {
	v := r.take(2)
	if v == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(v))
}

func decodeOne(b []byte, maxBody int, inflate bool) (Message, error) {
	r := &reader{b: b}
	magic := r.u32()
	if magic != magicV1 && magic != magicV2 {
		return Message{}, fmt.Errorf("%w: a message with a magic code that is not RocketMQ's", ErrProtocol)
	}
	r.u32() // body crc: not checked, a message is read, not stored
	var m Message
	m.Queue = int(r.u32())
	r.u32() // flag
	m.QueueOffset = r.u64()
	r.u64() // physical offset
	sys := r.u32()
	m.BornTime = time.UnixMilli(r.u64())
	hostLen := 4
	if sys&flagBornHostV6 != 0 {
		hostLen = 16
	}
	r.take(hostLen)
	r.u32() // born port
	m.StoreTime = time.UnixMilli(r.u64())
	hostLen = 4
	if sys&flagStoreHostV6 != 0 {
		hostLen = 16
	}
	r.take(hostLen)
	r.u32() // store port
	m.Reconsume = r.u32()
	r.u64() // prepared transaction offset
	bodyLen := int(r.u32())
	if bodyLen < 0 || r.i+bodyLen > len(b) {
		return Message{}, ErrProtocol
	}
	body := r.take(bodyLen)
	topicLen := 1
	if magic == magicV2 {
		topicLen = 2
	}
	var tl int
	if topicLen == 1 {
		if v := r.take(1); v != nil {
			tl = int(v[0])
		}
	} else {
		tl = r.u16()
	}
	m.Topic = cleanText(string(r.take(tl)), 128)
	pl := r.u16()
	if pl > maxPropsLen {
		return Message{}, ErrProtocol
	}
	props := r.take(pl)
	if r.bad {
		return Message{}, ErrProtocol
	}
	m.Props = parseProps(string(props))
	m.Tags, m.Keys = m.Props["TAGS"], m.Props["KEYS"]
	delete(m.Props, "TAGS")
	delete(m.Props, "KEYS")
	m.Body, m.BodyUnreadable = readBody(body, sys, maxBody, inflate)
	return m, nil
}

// readBody returns a message's body: as it is, or inflated when it was compressed with zlib, and never more than max bytes. A
// compression that is not zlib is said, and the bytes are not handed over as if they were the body.
func readBody(b []byte, sys int32, max int, inflate bool) ([]byte, string) {
	if sys&flagCompressed == 0 {
		if len(b) > max {
			return b[:max], fmt.Sprintf("the body is %d bytes and is cut at %d", len(b), max)
		}
		return b, ""
	}
	switch (sys & compressionTypeMsk) >> 8 {
	case 0, 3: // zlib: no type bits is the old way of saying so
		if !inflate {
			return nil, "compressed body"
		}
		z, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, "a body that says it is compressed and is not"
		}
		defer z.Close()
		out, err := io.ReadAll(io.LimitReader(z, int64(max)+1))
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, "a body that says it is compressed and is not"
		}
		if len(out) > max {
			return out[:max], fmt.Sprintf("the body is larger than %d bytes once inflated and is cut there", max)
		}
		return out, ""
	case 1:
		return nil, "the body is compressed with LZ4, which this client does not read"
	case 2:
		return nil, "the body is compressed with ZSTD, which this client does not read"
	}
	return nil, "the body is compressed in a way this client does not know"
}

func parseProps(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, "\x02") {
		k, v, ok := strings.Cut(kv, "\x01")
		if !ok || k == "" {
			continue
		}
		out[cleanText(k, 64)] = cleanText(v, maxPropValue)
	}
	return out
}

// cleanText is s as one line of at most max characters: a producer chooses what a property says, and it goes to a person and a model.
func cleanText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return s
}

var _ = tls.VersionTLS12
