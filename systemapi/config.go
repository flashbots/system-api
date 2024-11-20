package systemapi

import (
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

type systemAPIConfigGeneral struct {
	ListenAddr    string `toml:"listen_addr"`
	PipeFile      string `toml:"pipe_file"`
	LogJSON       bool   `toml:"log_json"`
	LogDebug      bool   `toml:"log_debug"`
	EnablePprof   bool   `toml:"pprof"`           // Enables pprof endpoints
	LogMaxEntries int    `toml:"log_max_entries"` // Maximum number of log entries

	BasicAuthSecretPath string `toml:"basic_auth_secret_path"`
	BasicAuthSecretSalt string `toml:"basic_auth_secret_salt"`

	HTTPReadTimeoutMillis  int `toml:"http_read_timeout_ms"`
	HTTPWriteTimeoutMillis int `toml:"http_write_timeout_ms"`
}

type SystemAPIConfig struct {
	General systemAPIConfigGeneral

	Actions     map[string]string
	FileUploads map[string]string `toml:"file_uploads"`
}

func LoadConfigFromFile(path string) (*SystemAPIConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadConfig(content)
}

func LoadConfig(content []byte) (*SystemAPIConfig, error) {
	cfg := &SystemAPIConfig{}
	err := toml.Unmarshal(content, cfg)
	if err != nil {
		return nil, err
	}

	// Apply default
	if cfg.General.LogMaxEntries == 0 {
		cfg.General.LogMaxEntries = DefaultLogMaxEntries
	}

	return cfg, nil
}

func NewSystemAPIConfig() *SystemAPIConfig {
	return &SystemAPIConfig{
		General:     systemAPIConfigGeneral{},
		Actions:     make(map[string]string),
		FileUploads: make(map[string]string),
	}
}
