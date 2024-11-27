package systemapi

import (
	"os"

	"github.com/flashbots/system-api/common"
	toml "github.com/pelletier/go-toml/v2"
)

var DefaultLogMaxEntries = common.GetEnvInt("MAX_EVENTS", 1000)

type systemAPIConfigGeneral struct {
	ListenAddr    string `toml:"listen_addr"`     // Address (host and port) for server to listen on
	PipeFile      string `toml:"pipe_file"`       // Path for the named pipe file
	LogJSON       bool   `toml:"log_json"`        // Enables JSON logging
	LogDebug      bool   `toml:"log_debug"`       // Enables debug logging
	EnablePprof   bool   `toml:"pprof"`           // Enables pprof endpoints
	LogMaxEntries int    `toml:"log_max_entries"` // Maximum number of log entries

	BasicAuthSecretPath string `toml:"basic_auth_secret_path"` // Path to the file containing the basic auth secret hash
	BasicAuthSecretSalt string `toml:"basic_auth_secret_salt"` // Path to the file containing the basic auth secret salt

	HTTPReadTimeoutMillis  int `toml:"http_read_timeout_ms"`  // A zero or negative value means there will be no timeout.
	HTTPWriteTimeoutMillis int `toml:"http_write_timeout_ms"` // A zero or negative value means there will be no timeout.

	TLSEnabled         bool     `toml:"tls_enabled"`           // Enable TLS
	TLSCreateIfMissing bool     `toml:"tls_create_if_missing"` // Create TLS cert and key files if they do not exist
	TLSCertHosts       []string `toml:"tls_cert_hosts"`        // Hosts for the TLS cert
	TLSCertPath        string   `toml:"tls_cert_path"`         // Path to the TLS cert file
	TLSKeyPath         string   `toml:"tls_key_path"`          // Path to the TLS key file
}

type SystemAPIConfig struct {
	General systemAPIConfigGeneral

	Actions     map[string]string
	FileUploads map[string]string `toml:"file_uploads"`
}

func NewConfig() *SystemAPIConfig {
	return &SystemAPIConfig{
		General: systemAPIConfigGeneral{
			LogMaxEntries: DefaultLogMaxEntries,
		},
		Actions:     make(map[string]string),
		FileUploads: make(map[string]string),
	}
}

func NewConfigFromFile(path string) (*SystemAPIConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewConfigFromTOML(content)
}

func NewConfigFromTOML(content []byte) (*SystemAPIConfig, error) {
	cfg := &SystemAPIConfig{}
	err := toml.Unmarshal(content, cfg)
	if err != nil {
		return nil, err
	}
	cfg.loadDefaults()
	return cfg, nil
}

func (cfg *SystemAPIConfig) loadDefaults() {
	if cfg.General.LogMaxEntries == 0 {
		cfg.General.LogMaxEntries = DefaultLogMaxEntries
	}
}
