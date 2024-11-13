package systemapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/flashbots/system-api/common"
	"github.com/go-chi/httplog/v2"
	"github.com/stretchr/testify/require"
)

func getTestLogger() *httplog.Logger {
	return common.SetupLogger(&common.LoggingOpts{
		Debug: true,
		JSON:  false,
	})
}

func getTestConfig() *HTTPServerConfig {
	return &HTTPServerConfig{
		Log:    getTestLogger(),
		Config: NewSystemAPIConfig(),
	}
}

func execRequest(t *testing.T, router http.Handler, method, url string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestGeneralHandlers(t *testing.T) {
	// Instantiate the server
	srv, err := NewServer(getTestConfig())
	require.NoError(t, err)
	router := srv.getRouter()

	// Test /livez
	rr := execRequest(t, router, http.MethodGet, "/livez", nil)
	require.Equal(t, http.StatusOK, rr.Code)

	// Test /api/v1/events
	rr = execRequest(t, router, http.MethodGet, "/api/v1/events", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	body, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	require.Equal(t, "[]\n", string(body))

	// Add an event
	rr = execRequest(t, router, http.MethodGet, "/api/v1/new_event?message=foo", nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Len(t, srv.events, 1)
}

func TestBasicAuth(t *testing.T) {
	basicAuthSecret := []byte("secret")
	tempDir := t.TempDir()

	// Create the config
	cfg := getTestConfig()
	cfg.Config.General.BasicAuthSecretPath = tempDir + "/basic_auth_secret"

	// Create the temporary file to store the basic auth secret
	err := os.WriteFile(cfg.Config.General.BasicAuthSecretPath, []byte{}, 0o600)
	require.NoError(t, err)

	// Instantiate the server
	srv, err := NewServer(cfg)
	require.NoError(t, err)
	router := srv.getRouter()

	// Helper to get /livez with and without basic auth
	getLiveZ := func(basicAuthUser, basicAuthPass string) int {
		req, err := http.NewRequest(http.MethodGet, "/livez", nil)
		if basicAuthUser != "" {
			req.SetBasicAuth(basicAuthUser, basicAuthPass)
		}
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr.Code
	}

	// Initially, /livez should work without basic auth
	require.Equal(t, http.StatusOK, getLiveZ("", ""))

	// Set a basic auth secret
	rr := execRequest(t, router, http.MethodPost, "/api/v1/set-basic-auth", bytes.NewReader(basicAuthSecret))
	require.Equal(t, http.StatusOK, rr.Code)

	// Ensure secretFromFile was written to file
	secretFromFile, err := os.ReadFile(cfg.Config.General.BasicAuthSecretPath)
	require.NoError(t, err)
	require.Equal(t, basicAuthSecret, secretFromFile)

	// From here on, /livez shoud fail without basic auth
	require.Equal(t, http.StatusUnauthorized, getLiveZ("", ""))

	// /livez should work with basic auth
	require.Equal(t, http.StatusOK, getLiveZ("admin", string(basicAuthSecret)))

	// /livez should now work with invalid basic auth credentials
	require.Equal(t, http.StatusUnauthorized, getLiveZ("admin1", string(basicAuthSecret)))
}
