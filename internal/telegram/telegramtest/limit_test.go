package telegramtest

import (
	"math"
	"testing"
)

// A limit is a number the caller chose, and it is bounded before it is made an int: a 64-bit value that is only cut to the width of
// an int could come out as a small, valid-looking limit.
func TestLimitIsBoundedBeforeItIsNarrowed(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want int
	}{
		{0, 100}, {-1, 100}, {1, 1}, {50, 50}, {100, 100}, {101, 100},
		{1 << 32, 100},   // would narrow to 0 on a 32-bit int
		{1<<32 + 7, 100}, // would narrow to 7
		{math.MaxInt64, 100}, {math.MinInt64, 100},
	} {
		if got := clampLimit(tc.in); got != tc.want {
			t.Errorf("clampLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
