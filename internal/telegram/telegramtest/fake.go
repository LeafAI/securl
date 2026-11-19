// Package telegramtest is a fake Telegram Bot API for tests. It speaks the part of the protocol securl uses (getMe, sendMessage,
// getUpdates) the way the real one does, including what the real one refuses: a wrong token is 401, a chat the bot is not in
// is 400/403, a message over 4096 characters is 400, a flood is 429 with retry_after, and updates are handed out once and are
// forgotten when an offset confirms them.
package telegramtest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Message is something said in a chat, by a person or by the bot.
type Message struct {
	ID     int64
	ChatID int64
	From   string // the sender's name
	FromID int64
	Text   string
	Bot    bool
	// Channel is a post in a channel: Telegram sends it as a channel_post update with no sender user, and the channel itself (its
	// title is From) as the sender chat. A post is delivered only to a bot that is in the channel and only when the bot asked for
	// channel_post updates.
	Channel bool
	// Caption makes the text a photo's caption: the message then has a caption and no text, as a post of a picture does.
	Caption bool
	// SenderTitle, for a channel post, is the title of the sender chat when it is not the channel's own (a post made on behalf of a
	// linked chat). Empty: the channel itself.
	SenderTitle string
	At          time.Time
	// ReplyTo is the id of the message this one answers, if any.
	ReplyTo int64
}

// Sent is a message the bot was asked to send, as the API received it.
type Sent struct {
	ChatID    int64
	Text      string
	ParseMode string
	ReplyTo   int64
}

// Bot is one bot of the fake: its token, who it is, and which chats it is in.
type Bot struct {
	Token    string
	ID       int64
	Username string
	// Privacy true means the bot sees only what is addressed to it; false means it sees every message of a group.
	Privacy bool
	// Chats the bot is a member of; sending anywhere else is refused as the real API refuses it.
	Chats map[int64]bool
}

// API is the fake server.
type API struct {
	*httptest.Server

	mu      sync.Mutex
	bots    map[string]*Bot
	updates map[string][]update // per token, in order, not yet confirmed
	next    int64               // update ids and message ids
	allowed map[string][]string // per token, the allowed_updates of its last getUpdates
	sent    []Sent
	paths   []string
	// FailNext makes the next call of a method answer this status, once. A key is a method name ("sendMessage").
	FailNext map[string]Failure
	// Calls counts calls by method.
	Calls map[string]int
	// Webhook set to a token makes getUpdates of that bot answer 409, as the real API does while a webhook is set.
	Webhook map[string]bool
}

// Failure is an answer the fake gives instead of working.
type Failure struct {
	Status      int
	Description string
	RetryAfter  int
}

type update struct {
	ID  int64
	Msg Message
}

// New starts the fake. The caller closes it.
func New(bots ...Bot) *API {
	a := &API{bots: map[string]*Bot{}, updates: map[string][]update{}, allowed: map[string][]string{}, next: 1000,
		FailNext: map[string]Failure{}, Calls: map[string]int{}, Webhook: map[string]bool{}}
	for i := range bots {
		b := bots[i]
		if b.Chats == nil {
			b.Chats = map[int64]bool{}
		}
		a.bots[b.Token] = &b
	}
	a.Server = httptest.NewServer(http.HandlerFunc(a.serve))
	return a
}

// Say puts a message from a person into a chat. Every bot that is in the chat gets it as an update, if its privacy mode lets it
// see it: a bot with privacy on sees only messages that mention it (@username) or reply to it.
func (a *API) Say(chatID int64, from string, fromID int64, text string, replyTo int64) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.say(chatID, from, fromID, text, replyTo, false)
}

func (a *API) say(chatID int64, from string, fromID int64, text string, replyTo int64, bot bool) int64 {
	a.next++
	m := Message{ID: a.next, ChatID: chatID, From: from, FromID: fromID, Text: text, Bot: bot, At: time.Now(), ReplyTo: replyTo}
	for tok, b := range a.bots {
		if !b.Chats[chatID] {
			continue
		}
		if b.Privacy && !bot && !strings.Contains(text, "@"+b.Username) && replyTo == 0 && !strings.HasPrefix(text, "/") {
			continue
		}
		a.next++
		a.updates[tok] = append(a.updates[tok], update{ID: a.next, Msg: m})
	}
	return m.ID
}

// Post puts a post into a channel, as its administrators write it: no person is the sender, the channel is. Only a bot that is in the
// channel gets it (the fake takes being in a channel to mean being an administrator, which is what the real API needs of a bot to
// deliver one), and only if it asked for channel_post updates.
func (a *API) Post(chatID int64, title, text string) int64 {
	return a.post(chatID, Message{From: title, Text: text})
}

// PostAs is Post for a post whose sender chat has a title of its own, and PostPhoto one that is a picture with a caption.
func (a *API) PostAs(chatID int64, title, senderTitle, text string) int64 {
	return a.post(chatID, Message{From: title, SenderTitle: senderTitle, Text: text})
}

func (a *API) PostPhoto(chatID int64, title, caption string) int64 {
	return a.post(chatID, Message{From: title, Text: caption, Caption: true})
}

func (a *API) post(chatID int64, m Message) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	m.ID, m.ChatID, m.FromID, m.Channel, m.At = a.next, chatID, chatID, true, time.Now()
	for tok, b := range a.bots {
		if !b.Chats[chatID] {
			continue
		}
		a.next++
		a.updates[tok] = append(a.updates[tok], update{ID: a.next, Msg: m})
	}
	return m.ID
}

// Sent returns what the bots were asked to send, oldest first.
func (a *API) Sent() []Sent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Sent(nil), a.sent...)
}

// Paths returns every request path the fake received (they carry the token, as the real API's do).
func (a *API) Paths() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.paths...)
}

// LastAllowed is the allowed_updates of the last getUpdates of a bot, as the fake read it (nil if there was none).
func (a *API) LastAllowed(token string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.allowed[token]...)
}

// Pending is how many updates of a bot nobody has confirmed yet.
func (a *API) Pending(token string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.updates[token])
}

func (a *API) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (a *API) fail(w http.ResponseWriter, status int, desc string, retry int) {
	body := map[string]any{"ok": false, "error_code": status, "description": desc}
	if retry > 0 {
		body["parameters"] = map[string]any{"retry_after": retry}
	}
	a.reply(w, status, body)
}

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.paths = append(a.paths, r.URL.Path)
	// /bot<token>/<method>
	rest := strings.TrimPrefix(r.URL.Path, "/bot")
	token, method, ok := strings.Cut(rest, "/")
	if !ok || !strings.HasPrefix(r.URL.Path, "/bot") {
		a.fail(w, 404, "Not Found", 0)
		return
	}
	a.Calls[method]++
	b, known := a.bots[token]
	if !known {
		a.fail(w, 401, "Unauthorized", 0)
		return
	}
	if f, has := a.FailNext[method]; has {
		delete(a.FailNext, method)
		a.fail(w, f.Status, f.Description, f.RetryAfter)
		return
	}
	args := map[string]any{}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if len(body) > 0 {
		json.Unmarshal(body, &args)
	}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			args[k] = v[0]
		}
	}
	switch method {
	case "getMe":
		a.reply(w, 200, map[string]any{"ok": true, "result": map[string]any{
			"id": b.ID, "is_bot": true, "first_name": "securl test", "username": b.Username,
			"can_join_groups": true, "can_read_all_group_messages": !b.Privacy}})
	case "sendMessage":
		a.sendMessage(w, b, args)
	case "getUpdates":
		a.getUpdates(w, token, args)
	default:
		a.fail(w, 404, "Not Found", 0)
	}
}

func num(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	}
	return 0
}

// clampLimit is the number of updates a getUpdates call may return: 1 to 100, and 100 for anything else (none given, negative, or
// out of range), as the real API does. The bound is applied to the 64-bit number before it is made an int, so that a huge value is
// never cut down to a small one by the conversion.
func clampLimit(n int64) int {
	if n <= 0 || n > 100 {
		return 100
	}
	return int(n)
}

func (a *API) sendMessage(w http.ResponseWriter, b *Bot, args map[string]any) {
	chat := num(args["chat_id"])
	text, _ := args["text"].(string)
	mode, _ := args["parse_mode"].(string)
	switch {
	case chat == 0:
		a.fail(w, 400, "Bad Request: chat_id is empty", 0)
		return
	case text == "":
		a.fail(w, 400, "Bad Request: message text is empty", 0)
		return
	case len([]rune(text)) > 4096:
		a.fail(w, 400, "Bad Request: message is too long", 0)
		return
	case !b.Chats[chat]:
		a.fail(w, 403, "Forbidden: bot is not a member of the group chat", 0)
		return
	}
	a.sent = append(a.sent, Sent{ChatID: chat, Text: text, ParseMode: mode, ReplyTo: num(args["reply_to_message_id"])})
	id := a.say(chat, b.Username, b.ID, text, 0, true)
	a.reply(w, 200, map[string]any{"ok": true, "result": map[string]any{
		"message_id": id, "date": time.Now().Unix(), "chat": map[string]any{"id": chat}, "text": text}})
}

func (a *API) getUpdates(w http.ResponseWriter, token string, args map[string]any) {
	if a.Webhook[token] {
		a.fail(w, 409, "Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete the webhook first", 0)
		return
	}
	// An offset confirms every update below it: they are forgotten, as the real API forgets them.
	if off := num(args["offset"]); off != 0 {
		keep := a.updates[token][:0:0]
		for _, u := range a.updates[token] {
			if u.ID >= off {
				keep = append(keep, u)
			}
		}
		a.updates[token] = keep
	}
	limit := clampLimit(num(args["limit"]))
	// allowed_updates: a type the caller did not ask for is not delivered, and is dropped when the call is made, so asking for it
	// later does not bring it back (the real API's rule). Without the argument the fake delivers every type; securl always says.
	if allowed, said := allowedTypes(args["allowed_updates"]); said {
		a.allowed[token] = a.allowed[token][:0:0]
		for t := range allowed {
			a.allowed[token] = append(a.allowed[token], t)
		}
		keep := a.updates[token][:0:0]
		for _, u := range a.updates[token] {
			if allowed[u.Msg.updateType()] {
				keep = append(keep, u)
			}
		}
		a.updates[token] = keep
	}
	out := []map[string]any{}
	for _, u := range a.updates[token] {
		if len(out) == limit {
			break
		}
		m := map[string]any{"message_id": u.Msg.ID, "date": u.Msg.At.Unix(), "chat": map[string]any{"id": u.Msg.ChatID}}
		if u.Msg.Caption {
			m["caption"] = u.Msg.Text
		} else {
			m["text"] = u.Msg.Text
		}
		if u.Msg.Channel {
			sender := u.Msg.From
			if u.Msg.SenderTitle != "" {
				sender = u.Msg.SenderTitle
			}
			m["chat"] = map[string]any{"id": u.Msg.ChatID, "title": u.Msg.From, "type": "channel"}
			m["sender_chat"] = map[string]any{"id": u.Msg.ChatID, "title": sender, "type": "channel"}
		} else {
			m["from"] = map[string]any{"id": u.Msg.FromID, "is_bot": u.Msg.Bot, "first_name": u.Msg.From}
		}
		if u.Msg.ReplyTo != 0 {
			m["reply_to_message"] = map[string]any{"message_id": u.Msg.ReplyTo}
		}
		out = append(out, map[string]any{"update_id": u.ID, u.Msg.updateType(): m})
	}
	a.reply(w, 200, map[string]any{"ok": true, "result": out})
}

// Tokens is the set of tokens the fake knows. Deleting one is the owner revoking it in BotFather: the next call with it is 401.
// The map is the fake's own, so a caller must not use it while a request is being served.
func (a *API) Tokens() map[string]*Bot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.bots
}

// updateType is the name of the key under which Telegram delivers a message: a post in a channel is a channel_post, anything said in
// a group or a private chat is a message.
func (m Message) updateType() string {
	if m.Channel {
		return "channel_post"
	}
	return "message"
}

// allowedTypes reads allowed_updates. said is false when the caller gave none.
func allowedTypes(v any) (set map[string]bool, said bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	set = map[string]bool{}
	for _, x := range list {
		if t, ok := x.(string); ok {
			set[t] = true
		}
	}
	return set, true
}
