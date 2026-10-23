package mcpserver

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// The page cuts a label at 60 characters. What goes must be what the person reads, so the label lists names in full and then
// counts the rest, and never ends in the middle of a name.
func TestTheLabelNamesWhatFitsAndCountsTheRest(t *testing.T) {
	keys := []string{"https://gitlab.91aql.com", "db://mysql-test", "https://kibana.91aql.com", "db://postgres", "https://jenkins.91aql.com"}
	got := closeLabel(keys)
	if utf8.RuneCountInString(got) > closeLabelMax {
		t.Errorf("%d characters, the page shows %d: %q", utf8.RuneCountInString(got), closeLabelMax, got)
	}
	if !strings.HasPrefix(got, "Type DELETE to close: ") {
		t.Errorf("%q", got)
	}
	shown, rest := 0, 0
	for _, k := range keys {
		if strings.Contains(got, strings.TrimPrefix(k, "https://")) {
			shown++
		}
	}
	fmt.Sscanf(got[strings.LastIndex(got, "(+")+2:], "%d more)", &rest)
	if shown+rest != len(keys) {
		t.Errorf("every session is either named or counted: %d named + %d more != %d: %q", shown, rest, len(keys), got)
	}
	if shown == 0 {
		t.Errorf("at least the first name is shown: %q", got)
	}
}

func TestTheLabelOfAFewShortNamesNamesAllOfThem(t *testing.T) {
	got := closeLabel([]string{"db://b", "https://a.example"})
	if got != "Type DELETE to close: a.example, db://b" {
		t.Errorf("sorted, complete, with no count: %q", got)
	}
}

func TestANameTooLongForTheLabelFallsBackToACount(t *testing.T) {
	long := "https://" + strings.Repeat("x", 80) + ".example"
	if got := closeLabel([]string{long}); got != "Type DELETE to close 1 session" {
		t.Errorf("%q", got)
	}
	got := closeLabel([]string{long, "db://a"}) // sorted: the short one fits, the long one is counted, never shown cut
	if got != "Type DELETE to close: db://a (+1 more)" || strings.Contains(got, "xxxx") {
		t.Errorf("%q", got)
	}
}

func TestTheDetailNamesEverySessionNotJustTheOnesInTheLabel(t *testing.T) {
	var keys []string
	for i := 0; i < 12; i++ {
		keys = append(keys, fmt.Sprintf("https://site%02d.example", i))
	}
	d := closeDetail(keys)
	for _, k := range keys {
		if !strings.Contains(d, strings.TrimPrefix(k, "https://")) {
			t.Errorf("the message must name %s: %s", k, d)
		}
	}
	if strings.Contains(d, "database") {
		t.Errorf("no database is closed, so nothing is said about accounts: %s", d)
	}
}
