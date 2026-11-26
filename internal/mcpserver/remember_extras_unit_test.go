package mcpserver

import (
	"context"
	"errors"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/web"
)

// A human that answers one round with what it is given, and says which fields it was asked for.
type scripted struct {
	answer site.Credentials
	asked  []site.Field
	mode   string
}

func (s *scripted) Ask(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	s.mode, s.asked = mode, fields
	return s.answer, nil
}

var saltOnly = []site.Field{{Name: "salt", Label: "Salt", Secret: true}}

func loginFields() []site.Field {
	return []site.Field{{Name: "username"}, {Name: "password", Secret: true}, {Name: "salt", Secret: true}}
}

// The page is the one that says nothing may be empty, and a page that is an old copy, or a hand-made submission, may leave a field
// out: an empty salt is a login that is bound to fail, and to count against the account, so the round stops here.
func TestAnEmptyOrMissingExtraStopsTheRoundBeforeTheDriverUsesIt(t *testing.T) {
	for name, answer := range map[string]site.Credentials{
		"missing": {"username": "alice", "password": "pw", "remember": "yes"},
		"empty":   {"username": "alice", "password": "pw", "remember": "yes", "salt": ""},
	} {
		a := &setupAsker{human: &scripted{answer: answer}, mode: web.ModeSetupExtras, extras: saltOnly}
		out, err := a.Ask(context.Background(), "custom", loginFields())
		if !errors.Is(err, site.ErrBadCredentials) || out != nil {
			t.Errorf("%s: %v %v", name, out, err)
		}
		if len(a.record.Extras) != 0 || a.record.Username != "" || a.record.Password != "" {
			t.Errorf("%s: something was kept from a round that was refused: %+v", name, a.record)
		}
	}
}

func TestTheSetupRoundAsksTheHumanForTheDriversFieldsAfterTheOnesTheStepHas(t *testing.T) {
	h := &scripted{answer: site.Credentials{"username": "alice", "password": "pw", "remember": "yes", "salt": "S"}}
	a := &setupAsker{human: h, mode: web.ModeSetupExtras, extras: saltOnly}
	out, err := a.Ask(context.Background(), "custom", loginFields())
	if err != nil || out["salt"] != "S" || out["username"] != "alice" || out["password"] != "pw" {
		t.Fatalf("%v %v", out, err)
	}
	var names []string
	for _, f := range h.asked {
		names = append(names, f.Name)
	}
	if got := names; len(got) != 6 || got[0] != "username" || got[1] != "password" || got[5] != "salt" {
		t.Errorf("%v", names)
	}
	if h.mode != web.ModeSetupExtras {
		t.Errorf("the person is asked on the step that has the salt, not %q", h.mode)
	}
	if a.record.Extras["salt"] != "S" || !a.consent {
		t.Errorf("%+v consent=%v", a.record, a.consent)
	}
}

// Replacing saved credentials is already the choice to save them: the replace step has no "remember" tick, with the salt or without.
func TestTheReplaceStepsSaveWithoutARememberTick(t *testing.T) {
	for _, mode := range []string{"credential_replace", web.ModeReplaceExtras} {
		a := &setupAsker{human: &scripted{answer: site.Credentials{"username": "alice", "password": "pw", "salt": "S"}}, mode: mode, extras: saltOnly}
		if _, err := a.Ask(context.Background(), "custom", loginFields()); err != nil || !a.consent {
			t.Errorf("%s: consent=%v %v", mode, a.consent, err)
		}
	}
	for _, mode := range []string{"credential_setup", web.ModeSetupExtras} {
		a := &setupAsker{human: &scripted{answer: site.Credentials{"username": "alice", "password": "pw", "salt": "S"}}, mode: mode, extras: saltOnly}
		if _, err := a.Ask(context.Background(), "custom", loginFields()); err != nil || a.consent {
			t.Errorf("%s: nothing is saved without the tick: consent=%v %v", mode, a.consent, err)
		}
	}
}

func TestADriverWithNoExtrasIsAskedExactlyWhatItAlwaysWas(t *testing.T) {
	h := &scripted{answer: site.Credentials{"username": "alice", "password": "pw", "remember": "yes"}}
	a := &setupAsker{human: h, mode: "credential_setup"}
	if _, err := a.Ask(context.Background(), "login", site.LoginFields); err != nil {
		t.Fatal(err)
	}
	if len(h.asked) != 5 || h.mode != "credential_setup" || len(a.record.Extras) != 0 {
		t.Errorf("%v %q %+v", h.asked, h.mode, a.record.Extras)
	}
}
