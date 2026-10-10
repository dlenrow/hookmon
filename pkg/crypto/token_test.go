package crypto_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	hcrypto "github.com/dlenrow/hookmon/pkg/crypto"
)

const (
	enrSecretA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	enrSecretB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestNewTokenSet_Validation(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cases := map[string][]hcrypto.EnrollmentToken{
		"missing name":     {{Secret: enrSecretA, Expires: future}},
		"duplicate name":   {{Name: "a", Secret: enrSecretA, Expires: future}, {Name: "a", Secret: enrSecretB, Expires: future}},
		"short secret":     {{Name: "a", Secret: strings.Repeat("x", hcrypto.MinTokenLength-1), Expires: future}},
		"empty secret":     {{Name: "a", Expires: future}},
		"no expiry":        {{Name: "a", Secret: enrSecretA}},
		"duplicate secret": {{Name: "a", Secret: enrSecretA, Expires: future}, {Name: "b", Secret: enrSecretA, Expires: future}},
	}
	for name, tokens := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := hcrypto.NewTokenSet(tokens); err == nil {
				t.Fatal("NewTokenSet accepted an invalid token list")
			}
		})
	}

	ts, err := hcrypto.NewTokenSet(nil)
	if err != nil || ts.Len() != 0 {
		t.Errorf("empty token list: got (%v, %v)", ts.Len(), err)
	}
}

func TestTokenSet_Validate(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	ts, err := hcrypto.NewTokenSet([]hcrypto.EnrollmentToken{
		{Name: "rollout", Secret: enrSecretA, Expires: now.Add(time.Hour)},
		{Name: "one-shot", Secret: enrSecretB, Expires: now.Add(time.Hour), SingleUse: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	m, err := ts.Validate(enrSecretA, now)
	if err != nil || m.Name != "rollout" || m.SingleUse {
		t.Errorf("valid token: got (%+v, %v)", m, err)
	}
	if m.Fingerprint != hcrypto.TokenFingerprint(enrSecretA) || strings.Contains(m.Fingerprint, enrSecretA) {
		t.Errorf("fingerprint: got %q", m.Fingerprint)
	}

	m, err = ts.Validate(enrSecretB, now)
	if err != nil || m.Name != "one-shot" || !m.SingleUse {
		t.Errorf("single-use token: got (%+v, %v)", m, err)
	}

	for name, presented := range map[string]string{
		"empty":           "",
		"wrong":           strings.Repeat("c", 64),
		"prefix":          enrSecretA[:40],
		"extra character": enrSecretA + "a",
		"case changed":    strings.ToUpper(enrSecretA),
	} {
		if _, err := ts.Validate(presented, now); !errors.Is(err, hcrypto.ErrTokenInvalid) {
			t.Errorf("%s: got %v, want ErrTokenInvalid", name, err)
		}
	}

	// Expiry: valid until, not at, the expiry time.
	if _, err := ts.Validate(enrSecretA, now.Add(time.Hour-time.Nanosecond)); err != nil {
		t.Errorf("just before expiry: %v", err)
	}
	if _, err := ts.Validate(enrSecretA, now.Add(time.Hour)); !errors.Is(err, hcrypto.ErrTokenExpired) {
		t.Errorf("at expiry: got %v, want ErrTokenExpired", err)
	}
	if _, err := ts.Validate(enrSecretB, now.Add(48*time.Hour)); !errors.Is(err, hcrypto.ErrTokenExpired) {
		t.Errorf("after expiry: got %v, want ErrTokenExpired", err)
	}

	var nilSet *hcrypto.TokenSet
	if _, err := nilSet.Validate(enrSecretA, now); !errors.Is(err, hcrypto.ErrTokenInvalid) {
		t.Errorf("nil set: got %v, want ErrTokenInvalid", err)
	}
}
