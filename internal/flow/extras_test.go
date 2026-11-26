package flow

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/web"
)

func extrasFlow() *Flow {
	u, _ := url.Parse("https://site.example")
	return &Flow{Base: u}
}

// The two steps that add a driver's fields to the sign-in are told to the person in words, like the steps they extend.
func TestTheMessageSaysWhatEachExtrasStepAsks(t *testing.T) {
	f := extrasFlow()
	for mode, want := range map[string]string{
		web.ModeSetupExtras:   "sign in",
		web.ModeReplaceExtras: "replace saved credentials",
	} {
		msg := message(f, mode, 1, "https://page.example/#v=2", "ABCDEF0123456789ABCDEF", time.Now(), "", false, false)
		if !strings.Contains(strings.ToLower(msg), want) {
			t.Errorf("%s: the message does not say %q:\n%s", mode, want, msg)
		}
		if strings.Contains(msg, mode) {
			t.Errorf("%s: the message shows the step's internal name instead of words:\n%s", mode, msg)
		}
		if !strings.Contains(msg, "24h0m0s") {
			t.Errorf("%s: the message does not say how long the grant lasts:\n%s", mode, msg)
		}
	}
}

func TestTheExtrasStepsAreManagedStepsSoTheyShowTheGrant(t *testing.T) {
	for _, mode := range []string{"daily_approval", "credential_setup", "credential_replace", "credential_totp", web.ModeSetupExtras, web.ModeReplaceExtras} {
		if !managedStep(mode) {
			t.Errorf("%s shows no grant: a step that saves credentials must say for how long it authorizes", mode)
		}
	}
	for _, mode := range []string{"login", "totp", "custom", "vault", ""} {
		if managedStep(mode) {
			t.Errorf("%s is not a managed step", mode)
		}
	}
}

func TestTheExtrasOfARoundAreTheLinkFieldsOfTheStepsThatTakeThemAndNoOthers(t *testing.T) {
	fs := []site.Field{{Name: "salt", Label: "Salt", Secret: true, Image: "data:image/png;base64,AAAA"}, {Name: "x", Label: "X"}}
	for _, mode := range []string{"custom", web.ModeSetupExtras, web.ModeReplaceExtras} {
		got := linkFields(mode, fs)
		if len(got) != 2 || got[0].Name != "salt" || got[1].Name != "x" {
			t.Errorf("%s: %+v", mode, got)
		}
	}
	for _, mode := range []string{"login", "totp", "credential_setup", "credential_replace", "credential_totp", "daily_approval", "vault"} {
		if got := linkFields(mode, fs); got != nil {
			t.Errorf("%s: the link of a step with a form of its own carries no list: %+v", mode, got)
		}
	}
}

// The extras are always secret on the page, whatever the driver said, and never carry an image there: the page refuses the link
// otherwise, and it must not be this side that builds one it will refuse.
func TestAnExtrasStepSendsEveryFieldAsASecretAndWithNoImage(t *testing.T) {
	fs := []site.Field{{Name: "salt", Label: "Salt", Secret: false, Image: "data:image/png;base64,AAAA"}}
	for _, mode := range []string{web.ModeSetupExtras, web.ModeReplaceExtras} {
		got := linkFields(mode, fs)
		if len(got) != 1 || !got[0].Secret || got[0].Image != "" {
			t.Errorf("%s: %+v", mode, got)
		}
	}
	if got := linkFields("custom", fs); len(got) != 1 || got[0].Secret || got[0].Image == "" {
		t.Errorf("custom is passed as the driver gave it: %+v", got)
	}
}

// The sign-in page has the username, the password and the remember choices of its own. What the round asks for beside the driver's
// extras is therefore left out of the link: the page refuses a link that names one of its own fields.
func TestTheLinkOfAnExtrasStepCarriesTheDriversFieldsAndNotThePagesOwn(t *testing.T) {
	fs := []site.Field{{Name: "username"}, {Name: "password", Secret: true}, {Name: "remember"}, {Name: "remember_totp"}, {Name: "totp_secret", Secret: true},
		{Name: "salt", Label: "Salt"}, {Name: "pepper", Label: "Pepper"}}
	for _, mode := range []string{web.ModeSetupExtras, web.ModeReplaceExtras} {
		got := linkFields(mode, fs)
		if len(got) != 2 || got[0].Name != "salt" || got[1].Name != "pepper" {
			t.Errorf("%s: %+v", mode, got)
		}
	}
	got := linkFields("custom", []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}})
	if len(got) != 3 {
		t.Errorf("custom carries what the driver gave, whatever the names: %+v", got)
	}
	if got := linkFields(web.ModeSetupExtras, []site.Field{{Name: "username"}, {Name: "password"}}); len(got) != 0 {
		t.Errorf("an extras step with no extras carries none: %+v", got)
	}
}
