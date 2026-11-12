package slidewindow

import (
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newClock() *clock { return &clock{t: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)} }

func TestItAllowsUpToTheLimitInTheWindowAndThenSaysWhenToTryAgain(t *testing.T) {
	c := newClock()
	w := New(3, time.Minute, c.now)
	for i := 0; i < 3; i++ {
		if ok, _ := w.Take(); !ok {
			t.Fatalf("take %d", i)
		}
		c.add(10 * time.Second)
	}
	ok, retry := w.Take()
	if ok {
		t.Fatal("the fourth is over the limit")
	}
	// the oldest was at t+0, the window is a minute, and 30 s have passed
	if retry != 30*time.Second {
		t.Errorf("retry in %s, want 30s", retry)
	}
}

func TestTheWindowSlidesOneOldTakeFallsOutAtATime(t *testing.T) {
	c := newClock()
	w := New(2, time.Minute, c.now)
	w.Take()
	c.add(40 * time.Second)
	w.Take()
	c.add(30 * time.Second) // the first is 70 s old, the second 30 s
	if ok, _ := w.Take(); !ok {
		t.Error("one fell out, so one is free")
	}
	if ok, _ := w.Take(); ok {
		t.Error("only one was free")
	}
}

func TestARefusedTakeIsNotCounted(t *testing.T) {
	c := newClock()
	w := New(1, time.Minute, c.now)
	w.Take()
	for i := 0; i < 50; i++ {
		if ok, _ := w.Take(); ok {
			t.Fatal("over the limit")
		}
	}
	c.add(61 * time.Second)
	if ok, _ := w.Take(); !ok {
		t.Error("refused takes pushed the end of the window further away")
	}
}

func TestGiveBackFreesATakeThatWasNotUsed(t *testing.T) {
	c := newClock()
	w := New(1, time.Minute, c.now)
	w.Take()
	w.GiveBack()
	if ok, _ := w.Take(); !ok {
		t.Error("a message that was not sent used up the limit")
	}
	w.GiveBack()
	w.GiveBack() // more than was taken is harmless
	w.GiveBack()
	if ok, _ := w.Take(); !ok {
		t.Error("the window is empty")
	}
	if ok, _ := w.Take(); ok {
		t.Error("but giving back more than was taken did not raise the limit")
	}
}

func TestBlockHoldsEveryTakeUntilTheTimeGivenAndThenLetsGo(t *testing.T) {
	c := newClock()
	w := New(10, time.Minute, c.now)
	w.Block(30 * time.Second)
	ok, retry := w.Take()
	if ok || retry != 30*time.Second {
		t.Errorf("%v %s", ok, retry)
	}
	c.add(31 * time.Second)
	if ok, _ := w.Take(); !ok {
		t.Error("the block ended")
	}
}

func TestABlockThatIsShorterThanOneAlreadyThereDoesNotShortenIt(t *testing.T) {
	c := newClock()
	w := New(10, time.Minute, c.now)
	w.Block(60 * time.Second)
	w.Block(5 * time.Second)
	if _, retry := w.Take(); retry != 60*time.Second {
		t.Errorf("%s", retry)
	}
}

func TestSeveralAtOnceNeverGoPastTheLimit(t *testing.T) {
	w := New(7, time.Minute, time.Now)
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := w.Take(); ok {
				mu.Lock()
				n++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n != 7 {
		t.Errorf("%d", n)
	}
}

func TestANonPositiveLimitOrWindowTakesNothingAndNeverPanics(t *testing.T) {
	for _, w := range []*Window{New(0, time.Minute, nil), New(-1, time.Minute, nil), New(1, 0, nil)} {
		if ok, _ := w.Take(); ok {
			t.Error("an unusable limit allows nothing")
		}
	}
}

// Two takes are in flight and the first one is given back: it is the first one's slot that is freed, not the latest. If the latest
// were freed, the second send (which did happen) would stop counting and the limit could be passed.
func TestGivingBackFreesTheSlotThatWasGivenBackNotTheLatest(t *testing.T) {
	c := newClock()
	w := New(2, time.Minute, c.now)
	_, a := w.TakeSlot()
	c.add(time.Second)
	_, b := w.TakeSlot()
	_ = b
	w.GiveBackSlot(a) // the first one did not happen
	if ok, _ := w.Take(); !ok {
		t.Fatal("one slot is free")
	}
	// now two are counted: b (a message that was sent) and the new one; a third must be refused
	if ok, _ := w.Take(); ok {
		t.Error("the sent message b was forgotten when a was given back")
	}
}

func TestAGivenBackSlotIsNotGivenBackTwice(t *testing.T) {
	c := newClock()
	w := New(1, time.Minute, c.now)
	_, a := w.TakeSlot()
	w.GiveBackSlot(a)
	w.GiveBackSlot(a)
	if ok, _ := w.Take(); !ok {
		t.Fatal("free")
	}
	if ok, _ := w.Take(); ok {
		t.Error("giving the same slot back twice made room for two")
	}
}
