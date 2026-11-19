// Package zulipfake is a fake Zulip server for tests. It speaks the part of the REST API securl uses (GET and POST /api/v1/messages and
// GET /api/v1/users/me) the way the real one does, including what the real one refuses: a wrong key is 401, a channel the bot is not
// subscribed to is an error and has no history for it, a message over the length limit is an error, and a flood is 429 with a
// retry-after in seconds.
package zulipfake

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Message is something said in a channel.
type Message struct {
	ID       int64
	Channel  string
	Topic    string
	Sender   string // full name
	SenderID int64
	Email    string
	Content  string
	At       time.Time
	Bot      bool
}

// Bot is one bot of the fake: who it is, its key, and which channels it is subscribed to.
type Bot struct {
	Email string
	Key   string
	ID    int64
	Name  string
	// Channels the bot is subscribed to. A channel it is not subscribed to cannot be read or written, and has no history for it.
	Channels map[string]bool
}

// Sent is a message the bot was asked to send, as the API received it.
type Sent struct {
	Channel string
	Topic   string
	Content string
	Type    string
	To      string
}

// Server is the fake.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	bots     map[string]*Bot // by email
	messages []Message
	next     int64
	sent     []Sent
	queries  []map[string]string
	auths    []string
	// MaxLength is the longest message the fake accepts, in characters (default 10000, Zulip's own).
	MaxLength int
	// FailNext makes the next call of a path answer this status, once. A key is "GET /api/v1/messages" and so on.
	FailNext map[string]Failure
	// Calls counts calls by "METHOD path".
	Calls map[string]int
}

// Failure is an answer the fake gives instead of working.
type Failure struct {
	Status     int
	Code       string
	Msg        string
	RetryAfter float64
}

// New starts the fake. The caller closes it.
func New(bots ...Bot) *Server {
	s := &Server{bots: map[string]*Bot{}, next: 1000, MaxLength: 10000, FailNext: map[string]Failure{}, Calls: map[string]int{}}
	for i := range bots {
		b := bots[i]
		if b.Channels == nil {
			b.Channels = map[string]bool{}
		}
		s.bots[b.Email] = &b
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

// Say puts a message from a person into a channel. Only a bot subscribed to it can read it.
func (s *Server) Say(channel, topic, sender string, senderID int64, content string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.say(Message{Channel: channel, Topic: topic, Sender: sender, SenderID: senderID, Email: "user" + strconv.FormatInt(senderID, 10) + "@example.invalid", Content: content})
}

func (s *Server) say(m Message) int64 {
	s.next++
	m.ID, m.At = s.next, time.Now()
	s.messages = append(s.messages, m)
	return m.ID
}

// Sent returns what the bots were asked to send, oldest first.
func (s *Server) Sent() []Sent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sent(nil), s.sent...)
}

// Queries returns the parameters of each GET /messages, as the fake received them.
func (s *Server) Queries() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.queries...)
}

// Auths returns the Authorization header of each call.
func (s *Server) Auths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auths...)
}

// Revoke is the owner regenerating or deleting a bot's key: the next call with it is 401.
func (s *Server) Revoke(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bots, email)
}

func (s *Server) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, f Failure) {
	if f.Code == "" {
		f.Code = "BAD_REQUEST"
	}
	body := map[string]any{"result": "error", "msg": f.Msg, "code": f.Code}
	if f.RetryAfter > 0 {
		body["retry-after"] = f.RetryAfter
	}
	s.reply(w, f.Status, body)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	s.Calls[key]++
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	if f, ok := s.FailNext[key]; ok {
		delete(s.FailNext, key)
		s.fail(w, f)
		return
	}
	email, pass, ok := r.BasicAuth()
	b := s.bots[email]
	if !ok || b == nil || b.Key != pass {
		s.fail(w, Failure{Status: 401, Code: "UNAUTHORIZED", Msg: "Invalid API key"})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/users/me":
		s.reply(w, 200, map[string]any{"result": "success", "msg": "", "user_id": b.ID, "email": b.Email, "full_name": b.Name, "is_bot": true})
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/messages":
		s.getMessages(w, r, b)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/messages":
		s.postMessage(w, r, b)
	default:
		s.fail(w, Failure{Status: 404, Code: "BAD_REQUEST", Msg: "no such endpoint"})
	}
}

type narrowTerm struct {
	Operator string `json:"operator"`
	Operand  string `json:"operand"`
	Negated  bool   `json:"negated"`
}

func (s *Server) getMessages(w http.ResponseWriter, r *http.Request, b *Bot) {
	q := r.URL.Query()
	rec := map[string]string{}
	for k := range q {
		rec[k] = q.Get(k)
	}
	s.queries = append(s.queries, rec)
	var narrow []narrowTerm
	if raw := q.Get("narrow"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &narrow); err != nil {
			s.fail(w, Failure{Status: 400, Msg: "Bad value for 'narrow'"})
			return
		}
	}
	channel, topic := "", ""
	for _, t := range narrow {
		switch t.Operator {
		case "channel", "stream":
			channel = t.Operand
		case "topic":
			topic = t.Operand
		}
	}
	if channel != "" && !b.Channels[channel] {
		s.fail(w, Failure{Status: 400, Msg: "Invalid channel name '" + channel + "'"})
		return
	}
	before, _ := strconv.Atoi(q.Get("num_before"))
	after, _ := strconv.Atoi(q.Get("num_after"))
	var matched []Message
	for _, m := range s.messages {
		if !b.Channels[m.Channel] || (channel != "" && m.Channel != channel) || (topic != "" && !strings.EqualFold(m.Topic, topic)) {
			continue
		}
		matched = append(matched, m)
	}
	anchor := q.Get("anchor")
	var out []Message
	switch anchor {
	case "newest", "":
		if before > len(matched) {
			before = len(matched)
		}
		out = matched[len(matched)-before:]
	default:
		id, _ := strconv.ParseInt(anchor, 10, 64)
		include := q.Get("include_anchor") != "false"
		var older, newer []Message
		for _, m := range matched {
			switch {
			case m.ID < id:
				older = append(older, m)
			case m.ID > id:
				newer = append(newer, m)
			case include:
				newer = append([]Message{m}, newer...)
			}
		}
		if before > len(older) {
			before = len(older)
		}
		if after > len(newer) {
			after = len(newer)
		}
		out = append(append([]Message(nil), older[len(older)-before:]...), newer[:after]...)
	}
	msgs := make([]map[string]any, 0, len(out))
	for _, m := range out {
		msgs = append(msgs, map[string]any{"id": m.ID, "sender_full_name": m.Sender, "sender_id": m.SenderID, "sender_email": m.Email, "content": m.Content,
			"timestamp": m.At.Unix(), "type": "stream", "display_recipient": m.Channel, "subject": m.Topic, "content_type": "text/x-markdown"})
	}
	s.reply(w, 200, map[string]any{"result": "success", "msg": "", "messages": msgs, "found_newest": true, "found_oldest": len(out) == len(matched)})
}

func (s *Server) postMessage(w http.ResponseWriter, r *http.Request, b *Bot) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, Failure{Status: 400, Msg: "bad form"})
		return
	}
	typ, to, topic, content := r.PostForm.Get("type"), r.PostForm.Get("to"), r.PostForm.Get("topic"), r.PostForm.Get("content")
	s.sent = append(s.sent, Sent{Channel: to, Topic: topic, Content: content, Type: typ, To: to})
	switch {
	case typ != "stream" && typ != "channel":
		s.fail(w, Failure{Status: 400, Msg: "Invalid type"})
	case !b.Channels[to]:
		s.fail(w, Failure{Status: 400, Msg: "Channel '" + to + "' does not exist"})
	case topic == "":
		s.fail(w, Failure{Status: 400, Msg: "Missing topic"})
	case len([]rune(content)) > s.MaxLength:
		s.fail(w, Failure{Status: 400, Msg: "Message length shouldn't exceed " + strconv.Itoa(s.MaxLength) + " characters."})
	default:
		id := s.say(Message{Channel: to, Topic: topic, Sender: b.Name, SenderID: b.ID, Email: b.Email, Content: content, Bot: true})
		s.reply(w, 200, map[string]any{"result": "success", "msg": "", "id": id})
	}
}
