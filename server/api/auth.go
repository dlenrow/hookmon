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
func NewAuthMiddleware(tokens []string) *AuthMiddleware {
	m := &AuthMiddleware{tokens: make(map[string]bool)}
	for _, t := range tokens {
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
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		if !a.validateToken(token) {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *AuthMiddleware) validateToken(token string) bool {
	for t := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(t)) == 1 {
			return true
		}
	}
	return false
}
