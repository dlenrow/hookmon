package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// MinTokenLength is the shortest enrollment secret the server accepts in
// its config. `openssl rand -hex 32` gives 64 characters.
const MinTokenLength = 32

// Enrollment token errors.
var (
	ErrTokenInvalid = errors.New("invalid enrollment token")
	ErrTokenExpired = errors.New("enrollment token expired")
	ErrTokenUsed    = errors.New("enrollment token already used")
)

// EnrollmentToken is one enrollment secret from the server config.
type EnrollmentToken struct {
	// Name identifies the token in logs; it is not secret.
	Name string `yaml:"name"`
	// Secret is what a bus presents with --enroll-token.
	Secret string `yaml:"secret"`
	// Expires is when the token stops working. Required.
	Expires time.Time `yaml:"expires"`
	// SingleUse tokens enroll one host. The server records each use in its
	// database, so a restart does not make the token usable again.
	SingleUse bool `yaml:"single_use"`
}

// TokenMatch describes the configured token a presented secret matched.
type TokenMatch struct {
	Name      string
	SingleUse bool
	// Fingerprint is the hex SHA-256 of the secret. The server stores it,
	// never the secret, to record single-use tokens as used.
	Fingerprint string
}

// TokenSet holds the configured enrollment tokens.
type TokenSet struct {
	tokens []tokenEntry
}

type tokenEntry struct {
	EnrollmentToken
	digest [sha256.Size]byte
}

// NewTokenSet checks the configured tokens and returns a set to validate
// presented secrets against. Every token needs a unique name, a unique
// secret of at least MinTokenLength characters, and an expiry.
func NewTokenSet(tokens []EnrollmentToken) (*TokenSet, error) {
	ts := &TokenSet{}
	names := make(map[string]bool)
	digests := make(map[[sha256.Size]byte]bool)
	for i, t := range tokens {
		if t.Name == "" {
			return nil, fmt.Errorf("enrollment token %d: name is required", i)
		}
		if names[t.Name] {
			return nil, fmt.Errorf("enrollment token %q: duplicate name", t.Name)
		}
		names[t.Name] = true
		if len(t.Secret) < MinTokenLength {
			return nil, fmt.Errorf("enrollment token %q: secret is %d characters, want at least %d",
				t.Name, len(t.Secret), MinTokenLength)
		}
		if t.Expires.IsZero() {
			return nil, fmt.Errorf("enrollment token %q: expires is required", t.Name)
		}
		d := sha256.Sum256([]byte(t.Secret))
		if digests[d] {
			return nil, fmt.Errorf("enrollment token %q: same secret as another token", t.Name)
		}
		digests[d] = true
		ts.tokens = append(ts.tokens, tokenEntry{EnrollmentToken: t, digest: d})
	}
	return ts, nil
}

// Len returns the number of configured tokens.
func (ts *TokenSet) Len() int {
	if ts == nil {
		return 0
	}
	return len(ts.tokens)
}

// Validate checks a presented secret. It compares fixed-length SHA-256
// digests with subtle.ConstantTimeCompare against every configured token,
// without stopping at a match, so the time taken says nothing about which
// token or how much of it matched. It returns ErrTokenInvalid for no match
// and ErrTokenExpired for a match at or after its expiry. Whether a
// single-use token was already used is for the caller to check, with the
// returned fingerprint.
func (ts *TokenSet) Validate(presented string, now time.Time) (TokenMatch, error) {
	if ts == nil || presented == "" {
		return TokenMatch{}, ErrTokenInvalid
	}
	d := sha256.Sum256([]byte(presented))
	match := -1
	for i := range ts.tokens {
		if subtle.ConstantTimeCompare(d[:], ts.tokens[i].digest[:]) == 1 {
			match = i
		}
	}
	if match < 0 {
		return TokenMatch{}, ErrTokenInvalid
	}
	t := ts.tokens[match]
	if !now.Before(t.Expires) {
		return TokenMatch{}, ErrTokenExpired
	}
	return TokenMatch{
		Name:        t.Name,
		SingleUse:   t.SingleUse,
		Fingerprint: hex.EncodeToString(t.digest[:]),
	}, nil
}

// TokenFingerprint returns the hex SHA-256 of an enrollment secret.
func TokenFingerprint(secret string) string {
	d := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(d[:])
}
