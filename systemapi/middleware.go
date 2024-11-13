package systemapi

import (
	"crypto/subtle"
	"fmt"
	"net/http"
)

// BasicAuth implements a simple middleware handler for adding basic http auth to a route.
func BasicAuth(realm string, getCreds func() map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Loading credentials dynamically because they can be updated at runtime
			creds := getCreds()

			// If no credentials are set, just pass through (unauthenticated)
			if len(creds) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Load credentials from request
			user, pass, ok := r.BasicAuth()
			if !ok {
				basicAuthFailed(w, realm)
				return
			}

			// Compare to allowed credentials
			credPass, credUserOk := creds[user]
			if !credUserOk || subtle.ConstantTimeCompare([]byte(pass), []byte(credPass)) != 1 {
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
