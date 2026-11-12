package telegram

import (
	"context"
	"sync"
	"time"
)

// Inbox is what a bot has been told, kept so that it can be read one chat at a time.
//
// A bot has one queue of updates for all of its chats, and Telegram forgets an update as soon as a getUpdates with a higher offset
// confirms it. Reading one chat by asking Telegram for it would therefore lose the messages of every other chat the bot is in. So
// the inbox takes everything the bot is sent, keeps it, and hands out a chat's messages from what it keeps. It confirms an offset
// only for updates it has stored, so a read that fails loses nothing.
//
// What is kept is in memory only, bounded, and gone when the process ends: it holds what other people wrote, which is not
// securl's to store.
type Inbox struct {
	c    *Client
	keep int

	mu      sync.Mutex
	msgs    []Message // oldest first, every chat, not yet returned by a Read
	offset  int64     // the next update to ask Telegram for (the highest update id seen, plus one)
	polling sync.Mutex
}

// InboxOptions tunes an Inbox.
type InboxOptions struct {
	// Keep is how many messages the inbox holds in all; when it is full the oldest go. Default 500.
	Keep int
}

// NewInbox makes an inbox for the bot behind c.
func NewInbox(c *Client, o InboxOptions) *Inbox {
	if o.Keep <= 0 {
		o.Keep = 500
	}
	return &Inbox{c: c, keep: o.Keep}
}

// fill takes what Telegram has for the bot and stores it. Only one fill runs at a time: two would ask for the same offset and
// store the same updates twice.
func (in *Inbox) fill(ctx context.Context, wait time.Duration) error {
	in.polling.Lock()
	defer in.polling.Unlock()
	in.mu.Lock()
	offset := in.offset
	in.mu.Unlock()
	ups, err := in.c.Updates(ctx, offset, 100, wait)
	if err != nil {
		return err
	}
	if len(ups) == 0 {
		return nil
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, m := range ups {
		in.msgs = append(in.msgs, m)
		if m.UpdateID >= in.offset {
			in.offset = m.UpdateID + 1
		}
	}
	if over := len(in.msgs) - in.keep; over > 0 {
		in.msgs = append([]Message(nil), in.msgs[over:]...)
	}
	return nil
}

// take returns up to limit messages of a chat, oldest first, and removes them from the inbox when consume is true.
func (in *Inbox) take(chatID int64, limit int, consume bool) []Message {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []Message
	rest := in.msgs[:0:0]
	for _, m := range in.msgs {
		if m.ChatID == chatID && len(out) < limit {
			out = append(out, m)
			if !consume {
				rest = append(rest, m)
			}
			continue
		}
		rest = append(rest, m)
	}
	in.msgs = rest
	return out
}

// Read returns the new messages of a chat, up to limit, oldest first, and does not return them again.
func (in *Inbox) Read(ctx context.Context, chatID int64, limit int) ([]Message, error) {
	if err := in.fill(ctx, 0); err != nil {
		return nil, err
	}
	return in.take(chatID, limit, true), nil
}

// Return puts messages that were read but not used back at the front, in their order, so that the next read returns them first. The
// inbox keeps its bound: when what is put back and what is already there are more than it holds, the oldest go.
func (in *Inbox) Return(ms []Message) {
	if len(ms) == 0 {
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	all := append(append([]Message(nil), ms...), in.msgs...)
	if over := len(all) - in.keep; over > 0 {
		all = all[over:]
	}
	in.msgs = all
}

// Peek is Read that leaves the messages where they are.
func (in *Inbox) Peek(ctx context.Context, chatID int64, limit int) ([]Message, error) {
	if err := in.fill(ctx, 0); err != nil {
		return nil, err
	}
	return in.take(chatID, limit, false), nil
}

// Wait is Read that, when there is nothing yet, waits up to wait for something to be said in the chat.
func (in *Inbox) Wait(ctx context.Context, chatID int64, limit int, wait time.Duration) ([]Message, error) {
	deadline := time.Now().Add(wait)
	for {
		left := time.Until(deadline)
		if left < 0 {
			left = 0
		}
		// Telegram holds the request open for up to a whole number of seconds; the fill is cut off by the deadline too.
		hold := left
		if hold > 25*time.Second {
			hold = 25 * time.Second
		}
		fctx, cancel := context.WithTimeout(ctx, left+2*time.Second)
		err := in.fill(fctx, hold)
		cancel()
		if err != nil {
			return nil, err
		}
		if got := in.take(chatID, limit, true); len(got) > 0 {
			return got, nil
		}
		if time.Until(deadline) <= 0 || ctx.Err() != nil {
			return nil, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}
