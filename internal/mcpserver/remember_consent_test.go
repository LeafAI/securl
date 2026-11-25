package mcpserver

import (
	"github.com/LeafAI/securl/internal/site"
	"testing"
)

func TestRememberTOTPRequiresSeparateConsent(t *testing.T) {
	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, tc := range []struct {
		name, flag, secret        string
		credentials, fail, stored bool
	}{
		{"password only", "", "", true, false, false},
		{"explicit no", "no", "", true, false, false},
		{"no storage", "", "", false, false, false},
		{"old page seed", "", seed, true, true, false},
		{"unchecked with seed", "no", seed, true, true, false},
		{"seed only", "yes", seed, false, true, false},
		{"missing seed", "yes", "", true, true, false},
		{"invalid seed", "yes", "!", true, true, false},
		{"unknown consent", "true", seed, true, true, false},
		{"explicit consent", "yes", seed, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := rememberedTOTP(site.Credentials{"remember_totp": tc.flag, "totp_secret": tc.secret}, tc.credentials)
			if (err != nil) != tc.fail || (len(got) > 0) != tc.stored {
				t.Fatalf("unexpected consent result: seed present=%v, error=%v", len(got) > 0, err)
			}
		})
	}
}
