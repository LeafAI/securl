package telegramsite

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/telegram"
	"github.com/LeafAI/securl/internal/telegram/telegramtest"
)

const (
	tok   = "123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv"
	chatA = int64(-1001111111111)
)

// asker answers the one round of the login with the token it is given, as the page does. It keeps the map it handed over, so that
// a test can see what the driver did to it afterwards.
type asker struct {
	token string
	err   error
	got   []site.Field
	mode  string
	given site.Credentials
}

func (a *asker) Ask(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	a.mode, a.got = mode, fields
	if a.err != nil {
		return nil, a.err
	}
	a.given = site.Credentials{"bot_token": a.token}
	return a.given, nil
}

func setup(t *testing.T, privacy bool) (*Driver, *telegramtest.API) {
	t.Helper()
	api := telegramtest.New(telegramtest.Bot{Token: tok, ID: 123456789, Username: "securl_test_bot", Privacy: privacy,
		Chats: map[int64]bool{chatA: true}})
	t.Cleanup(api.Close)
	cfg := &config.Config{}
	cfg.Telegram.Bots = []config.TelegramBot{{Name: "ops", Chats: []config.TelegramChat{{Name: "alerts", ChatID: chatA}}}}
	d := New(cfg.TelegramBot, Options{BaseURL: api.URL, HTTP: api.Client()})
	return d, api
}

func TestTheKeyOfABotIsTelegramColonSlashSlashItsName(t *testing.T) {
	if got := BaseURL("ops").String(); got != "telegram://ops" {
		t.Errorf("%s", got)
	}
	if Key("ops") != "telegram://ops" {
		t.Errorf("%s", Key("ops"))
	}
}

func TestTheDriverIsNeverMatchedFromAURLSoNoToolReachesABotByAccident(t *testing.T) {
	d, _ := setup(t, false)
	for _, raw := range []string{"telegram://ops", "https://api.telegram.org/bot123:ABC/getMe", "https://t.me/x", "http://ops"} {
		u, _ := url.Parse(raw)
		if d.Match(u) {
			t.Errorf("%s is matched: a bot is chosen by name, never recognised from a URL", raw)
		}
	}
	if !d.NeedsLogin() {
		t.Error("the token is the whole point")
	}
	if d.Name() != "telegram" {
		t.Errorf("%q", d.Name())
	}
}

func TestLoginAsksForTheTokenAloneOnASecretFieldAndKeepsItInTheSession(t *testing.T) {
	d, _ := setup(t, false)
	a := &asker{token: tok}
	s, err := d.Login(context.Background(), BaseURL("ops"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.got) != 1 || a.got[0].Name != "bot_token" || !a.got[0].Secret {
		t.Errorf("one secret field, the token: %+v", a.got)
	}
	if a.mode != "custom" {
		t.Errorf("a field that is not a username and a password is a custom round: %q", a.mode)
	}
	if s.Tokens[TokenBot] != tok {
		t.Errorf("the session holds the token for the tools to use")
	}
	if s.Tokens[TokenUsername] != "securl_test_bot" {
		t.Errorf("and who the bot is, which is not a secret: %v", s.Tokens)
	}
}

// The decrypted copy of what the person typed is the page's, handed over for one use; the driver clears it when it has used it.
func TestTheDecryptedTokenIsClearedFromWhatThePageHandedOver(t *testing.T) {
	d, _ := setup(t, false)
	a := &asker{token: tok}
	if _, err := d.Login(context.Background(), BaseURL("ops"), a, nil); err != nil {
		t.Fatal(err)
	}
	if a.given["bot_token"] != "" {
		t.Error("the plaintext token is still in the map the page handed over")
	}
	a2 := &asker{token: "not a token"}
	d.Login(context.Background(), BaseURL("ops"), a2, nil)
	if a2.given["bot_token"] != "" {
		t.Error("and a refused one is cleared too")
	}
}

func TestTheLabelOfTheFieldNamesTheBotAndHowToGetATokenWithoutEchoingAnything(t *testing.T) {
	d, _ := setup(t, false)
	a := &asker{token: tok}
	if _, err := d.Login(context.Background(), BaseURL("ops"), a, nil); err != nil {
		t.Fatal(err)
	}
	l := a.got[0].Label
	if l != "Bot token for ops" {
		t.Errorf("the label says what is asked for and which bot, and nothing that the page would cut: %q", l)
	}
	if len([]rune(l)) > 60 {
		t.Errorf("the page cuts a label at 60 characters: %d", len([]rune(l)))
	}
}

// A bot with a long name must still say what is asked for: the page shows 60 characters, so the name is what gives way.
func TestALongBotNameNeverPushesTheQuestionOffTheLabel(t *testing.T) {
	long := strings.Repeat("n", 64)
	api := telegramtest.New(telegramtest.Bot{Token: tok, ID: 123456789, Username: "b", Chats: map[int64]bool{chatA: true}})
	defer api.Close()
	cfg := &config.Config{}
	cfg.Telegram.Bots = []config.TelegramBot{{Name: long, Chats: []config.TelegramChat{{Name: "a", ChatID: chatA}}}}
	d := New(cfg.TelegramBot, Options{BaseURL: api.URL, HTTP: api.Client()})
	a := &asker{token: tok}
	if _, err := d.Login(context.Background(), BaseURL(long), a, nil); err != nil {
		t.Fatal(err)
	}
	l := a.got[0].Label
	if len([]rune(l)) > 60 || !strings.HasPrefix(l, "Bot token for ") {
		t.Errorf("%q (%d)", l, len([]rune(l)))
	}
}

func TestAWrongTokenIsBadCredentialsAndTheTokenIsNotInTheError(t *testing.T) {
	d, _ := setup(t, false)
	a := &asker{token: "999:WRONG-TOKEN-abcdefghijklmnopqrstuvwxyz0123"}
	_, err := d.Login(context.Background(), BaseURL("ops"), a, nil)
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "WRONG-TOKEN") || strings.Contains(err.Error(), "999:") {
		t.Errorf("the error repeats what was typed: %v", err)
	}
}

func TestATokenThatIsNotEvenShapedLikeOneIsRefusedWithoutCallingTelegram(t *testing.T) {
	d, api := setup(t, false)
	for _, bad := range []string{"", "   ", "not a token", "123456789", "abc:def", "123456789:short", "123456789:AAH SECRET TOKEN WITH SPACES abcdef", "https://api.telegram.org/bot123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv/getMe"} {
		_, err := d.Login(context.Background(), BaseURL("ops"), &asker{token: bad}, nil)
		if !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%q: %v", bad, err)
		}
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("%q: the error repeats what was typed", bad)
		}
	}
	if n := api.Calls["getMe"]; n != 0 {
		t.Errorf("%d calls to Telegram for tokens that cannot be one", n)
	}
}

// A token pasted with a newline or spaces around it (copied from BotFather's message) is the commonest slip; it is trimmed.
func TestATokenWithSurroundingSpaceIsTrimmed(t *testing.T) {
	d, _ := setup(t, false)
	s, err := d.Login(context.Background(), BaseURL("ops"), &asker{token: "  " + tok + "\n"}, nil)
	if err != nil || s.Tokens[TokenBot] != tok {
		t.Fatalf("%v", err)
	}
}

func TestTheSessionRecordsWhetherTheBotSeesEveryMessageOfAGroup(t *testing.T) {
	d, _ := setup(t, false)
	s, _ := d.Login(context.Background(), BaseURL("ops"), &asker{token: tok}, nil)
	if s.Tokens[TokenReadsAll] != "true" {
		t.Errorf("privacy off: %v", s.Tokens)
	}
	d2, _ := setup(t, true)
	s2, _ := d2.Login(context.Background(), BaseURL("ops"), &asker{token: tok}, nil)
	if s2.Tokens[TokenReadsAll] != "false" {
		t.Errorf("privacy on: %v", s2.Tokens)
	}
}

func TestAnUnreachableTelegramIsNotAWrongToken(t *testing.T) {
	d, api := setup(t, false)
	api.Close()
	_, err := d.Login(context.Background(), BaseURL("ops"), &asker{token: tok}, nil)
	if !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a person who typed a good token while the network was down must not be told it was wrong: %v", err)
	}
	if errors.Is(err, site.ErrBadCredentials) {
		t.Error("and must not be counted as a wrong credential")
	}
	if strings.Contains(err.Error(), "AAH-SECRET") {
		t.Errorf("%v", err)
	}
}

func TestACancelledLoginPassesTheAskersErrorThrough(t *testing.T) {
	d, _ := setup(t, false)
	want := errors.New("the person rejected")
	_, err := d.Login(context.Background(), BaseURL("ops"), &asker{err: want}, nil)
	if !errors.Is(err, want) {
		t.Errorf("%v", err)
	}
}

func TestAKeyThatNamesNoConfiguredBotIsRefusedBeforeAnyoneIsAsked(t *testing.T) {
	d, _ := setup(t, false)
	a := &asker{token: tok}
	for _, u := range []*url.URL{BaseURL("nope"), {Scheme: "db", Host: "ops"}, nil} {
		_, err := d.Login(context.Background(), u, a, nil)
		if err == nil {
			t.Errorf("%v: a person must not be asked for a token for a bot that is not configured", u)
		}
	}
	if a.got != nil {
		t.Error("somebody was asked")
	}
}

func TestProbeIsTrueWhileTheTokenWorksAndEndsTheSessionWhenTelegramRefusesIt(t *testing.T) {
	d, api := setup(t, false)
	s, _ := d.Login(context.Background(), BaseURL("ops"), &asker{token: tok}, nil)
	if err := d.Probe(context.Background(), BaseURL("ops"), s, nil); err != nil {
		t.Fatalf("%v", err)
	}
	// the owner revoked the token in BotFather
	delete(api.Tokens(), tok)
	err := d.Probe(context.Background(), BaseURL("ops"), s, nil)
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a revoked token ends the session, as a cookie the site no longer knows would: %v", err)
	}
}

func TestProbeKeepsTheSessionWhenTelegramCannotBeReached(t *testing.T) {
	d, api := setup(t, false)
	s, _ := d.Login(context.Background(), BaseURL("ops"), &asker{token: tok}, nil)
	api.Close()
	err := d.Probe(context.Background(), BaseURL("ops"), s, nil)
	if !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a network that is down says nothing about the token, so the session is kept: %v", err)
	}
}

func TestProbeOfASessionWithNoTokenIsBadCredentialsAndAsksTelegramNothing(t *testing.T) {
	d, api := setup(t, false)
	for _, s := range []*site.Session{nil, {}, {Tokens: map[string]string{}}, {Tokens: map[string]string{TokenBot: ""}}} {
		err := d.Probe(context.Background(), BaseURL("ops"), s, nil)
		if !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%v", err)
		}
	}
	if n := api.Calls["getMe"]; n != 0 {
		t.Errorf("%d requests were made for a session that holds no token", n)
	}
}

func TestClientBuildsATelegramClientFromTheSessionAndTheConfiguredProxy(t *testing.T) {
	d, api := setup(t, false)
	s, _ := d.Login(context.Background(), BaseURL("ops"), &asker{token: tok}, nil)
	c, err := d.Client(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), chatA, "hi", 0); err != nil {
		t.Fatal(err)
	}
	if len(api.Sent()) != 1 {
		t.Error("the client sent through the session's token")
	}
	if _, err := d.Client(&site.Session{}); err == nil {
		t.Error("a session with no token has no client")
	}
}

var _ = http.StatusOK
var _ = telegram.ErrBadToken
