package telegram

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/telegram/telegramtest"
)

// One bot has one queue of updates, for all of its chats, and Telegram forgets an update the moment an offset confirms it. So
// what is read for one chat must be kept for the others, or reading one chat would lose the messages of the rest; and what is
// returned to a reader must not be returned again.

func inbox(t *testing.T, privacy bool) (*telegramtest.API, *Inbox) {
	t.Helper()
	api, c := fake(t, privacy)
	return api, NewInbox(c, InboxOptions{Keep: 200})
}

func texts(ms []Message) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Text)
	}
	return out
}

func TestReadingOneChatKeepsWhatWasSaidInTheOthers(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatA, "ann", 1, "a1", 0)
	api.Say(chatB, "bob", 2, "b1", 0)
	api.Say(chatA, "ann", 1, "a2", 0)
	got, err := in.Read(context.Background(), chatA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(texts(got)) != "[a1 a2]" {
		t.Fatalf("chat A: %v", texts(got))
	}
	// An offset confirms what came before it only when the NEXT getUpdates carries it, so Telegram still holds the three updates
	// until then; what matters is that the inbox holds b1 too, and that after the next fill Telegram has forgotten them all.
	got, err = in.Read(context.Background(), chatB, 10)
	if err != nil || fmt.Sprint(texts(got)) != "[b1]" {
		t.Fatalf("chat B lost its message: %v %v", texts(got), err)
	}
	if api.Pending(tok) != 0 {
		t.Errorf("the second fill carried the offset, so Telegram has forgotten what the inbox kept: %d pending", api.Pending(tok))
	}
}

func TestAMessageIsReturnedOnceAndNotAgain(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatA, "ann", 1, "one", 0)
	first, _ := in.Read(context.Background(), chatA, 10)
	second, _ := in.Read(context.Background(), chatA, 10)
	if len(first) != 1 || len(second) != 0 {
		t.Errorf("first %v, then %v: a message read is not read again", texts(first), texts(second))
	}
	api.Say(chatA, "ann", 1, "two", 0)
	third, _ := in.Read(context.Background(), chatA, 10)
	if fmt.Sprint(texts(third)) != "[two]" {
		t.Errorf("only what is new: %v", texts(third))
	}
}

func TestThePeekDoesNotConsume(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatA, "ann", 1, "x", 0)
	peeked, _ := in.Peek(context.Background(), chatA, 10)
	again, _ := in.Peek(context.Background(), chatA, 10)
	read, _ := in.Read(context.Background(), chatA, 10)
	if len(peeked) != 1 || len(again) != 1 || len(read) != 1 {
		t.Errorf("%d %d %d", len(peeked), len(again), len(read))
	}
}

func TestTheLimitReturnsTheOldestFirstAndKeepsTheRestForTheNextRead(t *testing.T) {
	api, in := inbox(t, false)
	for i := 1; i <= 5; i++ {
		api.Say(chatA, "ann", 1, fmt.Sprintf("m%d", i), 0)
	}
	got, _ := in.Read(context.Background(), chatA, 2)
	if fmt.Sprint(texts(got)) != "[m1 m2]" {
		t.Errorf("the oldest first, so that nothing is skipped: %v", texts(got))
	}
	rest, _ := in.Read(context.Background(), chatA, 10)
	if fmt.Sprint(texts(rest)) != "[m3 m4 m5]" {
		t.Errorf("what was not returned is still there: %v", texts(rest))
	}
}

func TestOnlyTheChatNamedIsReturned(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatB, "bob", 2, "elsewhere", 0)
	got, _ := in.Read(context.Background(), chatA, 10)
	if len(got) != 0 {
		t.Errorf("a message of another chat came back: %v", texts(got))
	}
}

// The bot's own messages are in the stream; they are not "what was said to it".
func TestTheBotsOwnMessagesAreMarkedSoTheyCanBeToldApart(t *testing.T) {
	api, in := inbox(t, false)
	c := in.c
	if _, err := c.Send(context.Background(), chatA, "from the bot", 0); err != nil {
		t.Fatal(err)
	}
	api.Say(chatA, "ann", 1, "from ann", 0)
	got, _ := in.Read(context.Background(), chatA, 10)
	var bots, people int
	for _, m := range got {
		if m.FromBot {
			bots++
		} else {
			people++
		}
	}
	if bots != 1 || people != 1 {
		t.Errorf("%d bot, %d people: %v", bots, people, texts(got))
	}
}

func TestTheInboxKeepsAtMostWhatItWasToldAndDropsTheOldest(t *testing.T) {
	api, c := fake(t, false)
	in := NewInbox(c, InboxOptions{Keep: 3})
	for i := 1; i <= 6; i++ {
		api.Say(chatA, "ann", 1, fmt.Sprintf("m%d", i), 0)
	}
	got, _ := in.Read(context.Background(), chatA, 10)
	if fmt.Sprint(texts(got)) != "[m4 m5 m6]" {
		t.Errorf("memory is bounded; the oldest go first: %v", texts(got))
	}
}

func TestAWebhookThatIsSetIsSaidNotHidden(t *testing.T) {
	api, in := inbox(t, false)
	api.Webhook[tok] = true
	_, err := in.Read(context.Background(), chatA, 10)
	if !errors.Is(err, ErrWebhookSet) {
		t.Errorf("a bot with a webhook cannot be polled, and the reader must be told why: %v", err)
	}
}

func TestAReadThatFailsLosesNothing(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatA, "ann", 1, "keep me", 0)
	api.FailNext["getUpdates"] = telegramtest.Failure{Status: 502, Description: "Bad Gateway"}
	if _, err := in.Read(context.Background(), chatA, 10); err == nil {
		t.Fatal("a 502 is an error")
	}
	got, err := in.Read(context.Background(), chatA, 10)
	if err != nil || fmt.Sprint(texts(got)) != "[keep me]" {
		t.Errorf("an update that was not received is not confirmed: %v %v", texts(got), err)
	}
}

// Telegram confirms an update when an offset above it is sent. The inbox must send the offset only for updates it has stored.
func TestTheOffsetConfirmsOnlyWhatTheInboxHasKept(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatA, "ann", 1, "x", 0)
	if _, err := in.Peek(context.Background(), chatA, 10); err != nil {
		t.Fatal(err)
	}
	// stored, but Telegram is not told yet: the confirmation rides on the next request
	if got := api.Pending(tok); got != 1 {
		t.Errorf("Telegram must still hold the update the inbox has just stored (a crash now must not lose it): %d", got)
	}
	got, _ := in.Peek(context.Background(), chatA, 10)
	if len(got) != 1 {
		t.Errorf("%d", len(got))
	}
	if got := api.Pending(tok); got != 0 {
		t.Errorf("the next request confirmed it: %d", got)
	}
}

func TestSeveralReadersAtOnceNeitherLoseNorDuplicateAMessage(t *testing.T) {
	api, in := inbox(t, false)
	const n = 40
	for i := 0; i < n; i++ {
		api.Say(chatA, "ann", 1, fmt.Sprintf("m%02d", i), 0)
	}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 8; k++ {
				got, err := in.Read(context.Background(), chatA, 7)
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				for _, m := range got {
					seen[m.Text]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Errorf("%d of %d messages were read", len(seen), n)
	}
	for text, c := range seen {
		if c != 1 {
			t.Errorf("%s was returned %d times", text, c)
		}
	}
}

func TestAMessageWithNoTextIsKeptAsEmptyNotDropped(t *testing.T) {
	api, in := inbox(t, false)
	api.Say(chatA, "ann", 1, "", 0)
	got, _ := in.Read(context.Background(), chatA, 10)
	if len(got) != 1 || got[0].Text != "" {
		t.Errorf("a photo or a sticker has no text; it is still something that was said: %+v", got)
	}
}

func TestWaitForAMessageReturnsAsSoonAsOneArrives(t *testing.T) {
	api, in := inbox(t, false)
	go func() { time.Sleep(80 * time.Millisecond); api.Say(chatA, "ann", 1, "late", 0) }()
	start := time.Now()
	got, err := in.Wait(context.Background(), chatA, 10, 3*time.Second)
	if err != nil || fmt.Sprint(texts(got)) != "[late]" {
		t.Fatalf("%v %v", texts(got), err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("it waited for the whole time: %s", time.Since(start))
	}
}

func TestWaitGivesUpWhenNothingComesAndReturnsNothing(t *testing.T) {
	_, in := inbox(t, false)
	got, err := in.Wait(context.Background(), chatA, 10, 250*time.Millisecond)
	if err != nil || len(got) != 0 {
		t.Errorf("%v %v", texts(got), err)
	}
}

// To know whether there is more than a read asked for, one extra message is taken; it goes back at the front, in order, and is the
// first thing the next read returns.
func TestWhatWasTakenBeyondTheLimitGoesBackInOrderAtTheFront(t *testing.T) {
	api, in := inbox(t, false)
	for i := 1; i <= 4; i++ {
		api.Say(chatA, "ann", 1, fmt.Sprintf("m%d", i), 0)
	}
	got, _ := in.Read(context.Background(), chatA, 3)
	if fmt.Sprint(texts(got)) != "[m1 m2 m3]" {
		t.Fatalf("%v", texts(got))
	}
	in.Return(got[2:]) // m3 goes back
	api.Say(chatA, "ann", 1, "m5", 0)
	rest, _ := in.Read(context.Background(), chatA, 10)
	if fmt.Sprint(texts(rest)) != "[m3 m4 m5]" {
		t.Errorf("returned messages come first, in their order: %v", texts(rest))
	}
}

func TestReturningNothingDoesNothingAndReturnRespectsTheBound(t *testing.T) {
	api, c := fake(t, false)
	in := NewInbox(c, InboxOptions{Keep: 3})
	in.Return(nil)
	for i := 1; i <= 3; i++ {
		api.Say(chatA, "ann", 1, fmt.Sprintf("m%d", i), 0)
	}
	got, _ := in.Read(context.Background(), chatA, 3)
	api.Say(chatA, "ann", 1, "m4", 0)
	api.Say(chatA, "ann", 1, "m5", 0)
	in.Peek(context.Background(), chatA, 1)
	in.Return(got) // the buffer holds two now; three more would pass the bound of three
	rest, _ := in.Read(context.Background(), chatA, 10)
	if len(rest) > 3 {
		t.Errorf("the bound holds: %v", texts(rest))
	}
}
