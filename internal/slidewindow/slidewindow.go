// Package slidewindow is a limit on how many things happen in any stretch of time: at most n in the last d, counted from each one's
// own moment, so a burst cannot straddle two fixed windows and double the rate.
package slidewindow

import (
	"sync"
	"time"
)

// Window counts takes. It is safe for concurrent use.
type Window struct {
	n     int
	d     time.Duration
	now   func() time.Time
	mu    sync.Mutex
	slots []entry
	next  uint64
	until time.Time // nothing is allowed before this moment (a server that asked to be left alone)
}

type entry struct {
	id uint64
	at time.Time
}

// New makes a window of n takes in d. now is the clock (time.Now when nil). A limit or a window that is not positive allows nothing.
func New(n int, d time.Duration, now func() time.Time) *Window {
	if now == nil {
		now = time.Now
	}
	return &Window{n: n, d: d, now: now}
}

// Slot identifies one take, so that it can be given back.
type Slot struct{ id uint64 }

// Take records one use and says true, or says false, and how long until one is free, and records nothing.
func (w *Window) Take() (bool, time.Duration) {
	ok, retry, _ := w.take()
	return ok, retry
}

// TakeSlot is Take that also returns the slot, for GiveBackSlot. A refused take has the zero slot, which gives back nothing.
func (w *Window) TakeSlot() (time.Duration, Slot) {
	ok, retry, s := w.take()
	if !ok {
		return retry, Slot{}
	}
	return 0, s
}

func (w *Window) take() (bool, time.Duration, Slot) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n <= 0 || w.d <= 0 {
		return false, w.d, Slot{}
	}
	now := w.now()
	if now.Before(w.until) {
		return false, w.until.Sub(now), Slot{}
	}
	cutoff := now.Add(-w.d)
	keep := w.slots[:0:0]
	for _, e := range w.slots {
		if e.at.After(cutoff) {
			keep = append(keep, e)
		}
	}
	w.slots = keep
	if len(w.slots) >= w.n {
		return false, w.slots[0].at.Add(w.d).Sub(now), Slot{}
	}
	w.next++
	w.slots = append(w.slots, entry{id: w.next, at: now})
	return true, 0, Slot{id: w.next}
}

// GiveBackSlot undoes one take: the thing it was for did not happen. A slot that was already given back, that has slid out of the
// window, or that is the zero slot, does nothing.
func (w *Window) GiveBackSlot(s Slot) {
	if s.id == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, e := range w.slots {
		if e.id == s.id {
			w.slots = append(w.slots[:i:i], w.slots[i+1:]...)
			return
		}
	}
}

// GiveBack undoes the latest take. Prefer GiveBackSlot where two takes can be in flight at once.
func (w *Window) GiveBack() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.slots) > 0 {
		w.slots = w.slots[:len(w.slots)-1]
	}
}

// Block refuses every take for d from now, or for what is left of an earlier block if that is longer.
func (w *Window) Block(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if until := w.now().Add(d); until.After(w.until) {
		w.until = until
	}
}
