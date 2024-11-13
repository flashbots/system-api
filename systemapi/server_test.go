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

func TestGeneralHandlers(t *testing.T) {
	// Create the config
	cfg := getTestConfig()

	// Instantiate the server
	srv, err := NewServer(cfg)
	require.NoError(t, err)
	router := srv.getRouter()

	// Test /livez
	req, err := http.NewRequest(http.MethodGet, "/livez", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Test /api/v1/events
	req, err = http.NewRequest(http.MethodGet, "/api/v1/events", nil)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	body, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	require.Equal(t, "[]\n", string(body))

	// Add an event
	req, err = http.NewRequest(http.MethodGet, "/api/v1/new_event?message=foo", nil)
	require.NoError(t, err)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
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
	req, err := http.NewRequest(http.MethodPost, "/api/v1/set-basic-auth", bytes.NewReader(basicAuthSecret))
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Verify secretFromFile was written to file
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
