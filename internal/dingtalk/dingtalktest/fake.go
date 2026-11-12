// Package dingtalktest is a fake DingTalk custom-robot endpoint for tests. It answers the way the real one does, including what the
// real one refuses: an unknown access_token is 300005 "token is not exist", a missing one is 40035, a robot that has a signing
// secret refuses a request whose timestamp or sign is wrong (310000), a robot with a keyword refuses text without it (310000), a
// flood is 410100, and a message type or content it does not take is refused. The status is 200 for all of them, as the real
// one's is.
package dingtalktest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Robot is one custom robot of the fake: the group it is in is the robot's whole identity.
type Robot struct {
	Token string
	// Secret, when set, makes the robot require a fresh timestamp and a matching sign (the "加签" security setting).
	Secret string
	// Keyword, when set, makes the robot refuse text that does not contain it.
	Keyword string
}

// Sent is a message the robot was asked to send, as the endpoint received it.
type Sent struct {
	Token   string
	Type    string
	Text    string
	Title   string
	AtAll   bool
	Mobiles []string
	UserIDs []string
	Uuid    string
}

// Failure is an answer the fake gives instead of working.
type Failure struct {
	Status  int // the HTTP status; 0 is 200
	Code    int
	Message string
}

// API is the fake server.
type API struct {
	*httptest.Server

	mu     sync.Mutex
	robots map[string]*Robot
	sent   []Sent
	paths  []string
	uuids  map[string]bool
	// FailNext makes the next send answer this, once.
	FailNext *Failure
	// Now is the clock the signature's timestamp is checked against.
	Now func() time.Time
	// Throttle makes the robot answer 410100 after this many messages (0: never), as the real one does after 20 in a minute.
	Throttle int
}

// New starts the fake over TLS (the real endpoint is https) and returns it. The caller closes it.
func New(robots ...Robot) *API {
	a := &API{robots: map[string]*Robot{}, uuids: map[string]bool{}, Now: time.Now}
	for i := range robots {
		r := robots[i]
		a.robots[r.Token] = &r
	}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(a.serve))
	return a
}

// Sign is the signature the real endpoint expects for a millisecond timestamp.
func Sign(secret string, tsMillis int64) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "%d\n%s", tsMillis, secret)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Sent returns what was sent, oldest first.
func (a *API) Sent() []Sent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Sent(nil), a.sent...)
}

// Requests returns every request URI (path and query) the fake received. They carry the access_token, as the real ones do.
func (a *API) Requests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths...)
}

func (a *API) reply(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"errcode": code, "errmsg": msg})
}

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.paths = append(a.paths, r.URL.RequestURI())
	if r.URL.Path != "/robot/send" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if f := a.FailNext; f != nil {
		a.FailNext = nil
		a.reply(w, f.Status, f.Code, f.Message)
		return
	}
	q := r.URL.Query()
	tok := q.Get("access_token")
	if tok == "" {
		a.reply(w, 0, 40035, "缺少参数 access_token")
		return
	}
	rb, ok := a.robots[tok]
	if !ok {
		a.reply(w, 0, 300005, "token is not exist")
		return
	}
	if rb.Secret != "" && !a.signed(rb, q) {
		a.reply(w, 0, 310000, "sign not match")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var m struct {
		Type string `json:"msgtype"`
		Uuid string `json:"msgUuid"`
		Text struct {
			Content string `json:"content"`
		} `json:"text"`
		Markdown struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		} `json:"markdown"`
		At struct {
			Mobiles []string `json:"atMobiles"`
			UserIDs []string `json:"atUserIds"`
			All     bool     `json:"isAtAll"`
		} `json:"at"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		a.reply(w, 0, 40035, "缺少参数 json")
		return
	}
	if m.Type != "text" && m.Type != "markdown" {
		a.reply(w, 0, 400105, "不支持的消息类型")
		return
	}
	text := m.Text.Content
	if m.Type == "markdown" {
		text = m.Markdown.Text
	}
	if strings.TrimSpace(text) == "" {
		a.reply(w, 0, 40035, "content is empty")
		return
	}
	if rb.Keyword != "" && !strings.Contains(text+m.Markdown.Title, rb.Keyword) {
		a.reply(w, 0, 310000, "keywords not in content")
		return
	}
	if m.Uuid != "" && a.uuids[tok+"/"+m.Uuid] {
		a.reply(w, 0, 0, "ok") // an idempotent retry: accepted, and not sent twice
		return
	}
	if a.Throttle > 0 && len(a.sent) >= a.Throttle {
		a.reply(w, 0, 410100, "send too fast")
		return
	}
	if m.Uuid != "" {
		a.uuids[tok+"/"+m.Uuid] = true
	}
	a.sent = append(a.sent, Sent{Token: tok, Type: m.Type, Text: text, Title: m.Markdown.Title, AtAll: m.At.All, Mobiles: m.At.Mobiles, UserIDs: m.At.UserIDs, Uuid: m.Uuid})
	a.reply(w, 0, 0, "ok")
}

// signed checks the timestamp is within an hour of now (the real endpoint's window) and the sign matches.
func (a *API) signed(rb *Robot, q map[string][]string) bool {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	ts, err := strconv.ParseInt(get("timestamp"), 10, 64)
	if err != nil {
		return false
	}
	if d := a.Now().Sub(time.UnixMilli(ts)); d > time.Hour || d < -time.Hour {
		return false
	}
	return hmac.Equal([]byte(get("sign")), []byte(Sign(rb.Secret, ts)))
}
