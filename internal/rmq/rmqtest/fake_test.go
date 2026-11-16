package rmqtest

import (
	"math"
	"strings"
	"testing"
)

// A queue id is an int in a test and an int32 on the wire: one that does not fit is not narrowed into a different queue's id.
func TestAQueueIdThatDoesNotFitAnInt32IsNotNarrowedIntoAnotherId(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want int32
	}{{0, 0}, {7, 7}, {math.MaxInt32, math.MaxInt32}, {-1, 0}, {math.MaxInt32 + 1, 0}, {1 << 40, 0}} {
		if got := clampQueue(tc.in); got != tc.want {
			t.Errorf("clampQueue(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestAFrameTooLargeToBuildIsNotBuilt(t *testing.T) {
	if got := encode(frame{Code: 1}, make([]byte, maxFake+1)); got != nil {
		t.Errorf("a body over the bound was built: %d bytes", len(got))
	}
	if got := encode(frame{Code: 1, Remark: strings.Repeat("r", maxFake+1)}, []byte("ok")); got != nil {
		t.Errorf("a header over the bound was built: %d bytes", len(got))
	}
	if got := encode(frame{Code: 1}, []byte("ok")); len(got) < 8 {
		t.Errorf("an ordinary frame was refused")
	}
}
