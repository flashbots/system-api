package systemapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
)

// BasicAuth implements a simple middleware handler for adding basic http auth to a route.
func BasicAuth(realm string, getHashedCredentials func() map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Loading credentials dynamically because they can be updated at runtime
			hashedCredentials := getHashedCredentials()

			// If no credentials are set, just pass through (unauthenticated)
			if len(hashedCredentials) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Load credentials from request
			user, pass, ok := r.BasicAuth()
			if !ok {
				basicAuthFailed(w, realm)
				return
			}

			// Hash the password and see if credentials are allowed
			h := sha256.New()
			h.Write([]byte(pass))
			userPassHash := hex.EncodeToString(h.Sum(nil))

			// Compare to allowed credentials
			credPassHash, credUserOk := hashedCredentials[user]
			if !credUserOk || subtle.ConstantTimeCompare([]byte(userPassHash), []byte(credPassHash)) != 1 {
				basicAuthFailed(w, realm)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func basicAuthFailed(w http.ResponseWriter, realm string) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}
