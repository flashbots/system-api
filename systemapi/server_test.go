package systemapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// Helper to execute an API request with optional basic auth
func execRequestAuth(t *testing.T, router http.Handler, method, url string, requestBody io.Reader, basicAuthUser, basicAuthPass string) (statusCode int, responsePayload []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, requestBody)
	require.NoError(t, err)
	if basicAuthUser != "" {
		req.SetBasicAuth(basicAuthUser, basicAuthPass)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	responseBody, err := io.ReadAll(rr.Body)
	require.NoError(t, err)
	return rr.Code, responseBody
}

// Helper to execute an API request without basic auth
func execRequest(t *testing.T, router http.Handler, method, url string, requestBody io.Reader) (statusCode int, responsePayload []byte) {
	t.Helper()
	return execRequestAuth(t, router, method, url, requestBody, "", "")
}

// Helper to create prepared test runners for specific API endpoints
func createRequestRunner(t *testing.T, router http.Handler, method, url string) func(basicAuthUser, basicAuthPass string, requestBody io.Reader) (statusCode int, responsePayload []byte) {
	t.Helper()
	return func(basicAuthUser, basicAuthPass string, requestBody io.Reader) (statusCode int, responsePayload []byte) {
		return execRequestAuth(t, router, method, url, requestBody, basicAuthUser, basicAuthPass)
	}
}

func TestGeneralHandlers(t *testing.T) {
	// Instantiate the server
	srv, err := NewServer(getTestConfig())
	require.NoError(t, err)
	router := srv.getRouter()

	// Test /livez
	code, _ := execRequest(t, router, http.MethodGet, "/livez", nil)
	require.Equal(t, http.StatusOK, code)

	// /api/v1/events is initially empty
	code, respBody := execRequest(t, router, http.MethodGet, "/api/v1/events", nil)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "[]\n", string(respBody))

	// Add an event
	code, _ = execRequest(t, router, http.MethodGet, "/api/v1/new_event?message=foo", nil)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, srv.events, 1)
	require.Equal(t, "foo", srv.events[0].Message)

	// /api/v1/events now has an entry
	code, respBody = execRequest(t, router, http.MethodGet, "/api/v1/events", nil)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, string(respBody), "foo")

	// /logs should also work
	code, respBody = execRequest(t, router, http.MethodGet, "/logs", nil)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, string(respBody), "foo\n")
}

func TestBasicAuth(t *testing.T) {
	tempDir := t.TempDir()
	basicAuthSecret := []byte("secret")

	// Create a hash of the basic auth secret
	h := sha256.New()
	h.Write(basicAuthSecret)
	basicAuthSecretHash := hex.EncodeToString(h.Sum(nil))

	// Create the config
	cfg := getTestConfig()
	cfg.Config.General.BasicAuthSecretPath = tempDir + "/basic_auth_secret"

	// Create the server instance
	_, err := NewServer(cfg)
	require.NoError(t, err)

	// Ensure the basic auth secret file was created
	_, err = os.Stat(cfg.Config.General.BasicAuthSecretPath)
	require.NoError(t, err)

	// Create the temporary file to store the basic auth secret
	err = os.WriteFile(cfg.Config.General.BasicAuthSecretPath, []byte{}, 0o600)
	require.NoError(t, err)

	// Server will work now
	srv, err := NewServer(cfg)
	require.NoError(t, err)
	router := srv.getRouter()

	// Prepare request helpers
	reqGetLiveZ := createRequestRunner(t, router, http.MethodGet, "/livez")
	reqSetBasicAuthSecret := createRequestRunner(t, router, http.MethodPost, "/api/v1/set-basic-auth")

	// Initially, /livez should work without basic auth
	code, _ := reqGetLiveZ("", "", nil)
	require.Equal(t, http.StatusOK, code)

	// should work even if invalid basic auth credentials are provided
	code, _ = reqGetLiveZ("admin", "foo", nil)
	require.Equal(t, http.StatusOK, code)

	// Set a basic auth secret
	code, _ = reqSetBasicAuthSecret("", "", bytes.NewReader(basicAuthSecret))
	require.Equal(t, http.StatusOK, code)

	// Ensure hash was written to file and is reproducible
	secretFromFile, err := os.ReadFile(cfg.Config.General.BasicAuthSecretPath)
	require.NoError(t, err)
	require.Equal(t, basicAuthSecretHash, string(secretFromFile))

	// From here on, /livez shoud fail without basic auth
	code, _ = reqGetLiveZ("", "", nil)
	require.Equal(t, http.StatusUnauthorized, code)

	// /livez should work with basic auth
	code, _ = reqGetLiveZ("admin", string(basicAuthSecret), nil)
	require.Equal(t, http.StatusOK, code)

	// /livez should not work with invalid basic auth credentials
	code, _ = reqGetLiveZ("admin1", string(basicAuthSecret), nil)
	require.Equal(t, http.StatusUnauthorized, code)
	code, _ = reqGetLiveZ("admin", "foo", nil)
	require.Equal(t, http.StatusUnauthorized, code)
}
