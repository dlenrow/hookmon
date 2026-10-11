package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthMiddleware validates API tokens in the Authorization header.
type AuthMiddleware struct {
	tokens map[string]bool
}

// NewAuthMiddleware creates middleware that accepts the given API tokens.
// An empty or whitespace-only token is dropped: it would let in a request
// whose bearer token is empty. Config validation refuses such tokens
// first; this is the second line.
func NewAuthMiddleware(tokens []string) *AuthMiddleware {
	m := &AuthMiddleware{tokens: make(map[string]bool)}
	for _, t := range tokens {
		if strings.TrimSpace(t) == "" {
			continue
		}
		m.tokens[t] = true
	}
	return m
}

// Handler wraps an http.Handler with token authentication.
func (a *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			writeError(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		if !a.validateToken(bearerToken(auth)) {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// bearerToken returns the token in an Authorization header value.
func bearerToken(header string) string {
	return strings.TrimPrefix(header, "Bearer ")
}

// validateToken reports whether token is one of the API tokens. REST and
// the WebSocket both use it. An empty or whitespace-only token is never
// valid, whatever the configuration.
func (a *AuthMiddleware) validateToken(token string) bool {
	if strings.TrimSpace(token) == "" {
		return false
	}
	for t := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(t)) == 1 {
			return true
		}
	}
	return false
}
