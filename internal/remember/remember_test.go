package remember

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/vault"
)

func TestGrantLifecycle(t *testing.T) {
	dir := t.TempDir()
	v := vault.NewWithCost(dir, 1, 8, 1)
	const pass = "correct horse battery staple"
	if err := v.Init(pass); err != nil {
		t.Fatal(err)
	}
	key := "https://gitlab.example"
	if err := Enroll(v, key, Record{Site: "gitlab", Username: "secret-user", Password: "secret-password", Secret: []byte("12345678901234567890")}); err != nil {
		t.Fatal(err)
	}
	r, err := Load(v, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if r.Valid(now) {
		t.Fatal("enrollment must not authorize")
	}
	r, err = Approve(v, key, r, now, Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid(now) || !r.Valid(now.Add(Lifetime-time.Nanosecond)) || r.Valid(now.Add(Lifetime)) || r.Valid(now.Add(-time.Second)) {
		t.Fatal("incorrect authorization boundaries")
	}
	other := vault.NewWithCost(dir, 1, 8, 1)
	if err = other.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	copy, err := Load(other, key)
	if err != nil || copy.Revision != r.Revision || !copy.Valid(now) {
		t.Fatal("grant did not persist", err)
	}
	if _, err = Load(other, "https://other.example"); !errors.Is(err, vault.ErrNoEntry) {
		t.Fatal("cross-site credential access", err)
	}
	if err = Revoke(other, key); err != nil {
		t.Fatal(err)
	}
	revoked, err := Load(v, key)
	if err != nil || revoked.Valid(now) || revoked.Revision == r.Revision {
		t.Fatal("revocation did not propagate", err)
	}
	if _, err = Approve(v, key, r, now, Lifetime); err == nil {
		t.Fatal("stale approval resurrected")
	}
	if err = Revoke(other, key); err != nil {
		t.Fatal(err)
	}
	if _, err = Approve(v, key, revoked, now, Lifetime); err == nil {
		t.Fatal("pending approval survived revocation")
	}
	if err = Remove(other, key); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(v, key); !errors.Is(err, ErrRemoved) {
		t.Fatal("removed record still available", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "data.enc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"secret-user", "secret-password", "12345678901234567890"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatal("plaintext credential")
		}
	}
}

func TestConfiguredGrantDuration(t *testing.T) {
	v := vault.NewWithCost(t.TempDir(), 1, 8, 1)
	if err := v.Init("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	const key = "https://archery.example"
	const ttl = 2 * time.Hour
	now := time.Now().UTC()
	r, err := EnrollApproved(v, key, Record{Site: "archery", Username: "example-user", Password: "example-value", Secret: make([]byte, 20)}, nil, false, now, ttl)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Valid(now.Add(ttl-time.Nanosecond)) || r.Valid(now.Add(ttl)) {
		t.Fatal("custom deadline incorrect")
	}
	r, err = Load(v, key)
	if err != nil || r.Duration != ttl {
		t.Fatal("duration did not persist", err)
	}
	renewed, err := Approve(v, key, r, now, 8*time.Hour)
	if err != nil || !renewed.Valid(now.Add(7*time.Hour)) || renewed.Valid(now.Add(8*time.Hour)) {
		t.Fatal("new grant did not use new duration", err)
	}
	if _, err = EnrollApproved(v, key, *r, r, false, now, ttl); err == nil {
		t.Fatal("stale replacement succeeded")
	}
	if err = RemoveExpected(v, key, r); err == nil {
		t.Fatal("stale removal succeeded")
	}
	if err = RemoveExpected(v, key, renewed); err != nil {
		t.Fatal(err)
	}
	if _, err = EnrollApproved(v, key, *r, nil, true, now, ttl); err != nil {
		t.Fatal("re-enrollment failed", err)
	}
}
