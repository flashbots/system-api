package systemapi

import (
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

type SystemAPIConfig struct {
	Actions map[string]string
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
	return cfg, nil
}
