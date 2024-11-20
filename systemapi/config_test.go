package systemapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	path := "../systemapi-config.toml"
	cfg, err := LoadConfigFromFile(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotEmpty(t, cfg.Actions)
	require.Equal(t, "echo test", cfg.Actions["echo_test"])
}

func TestEmptyConfig(t *testing.T) {
	cfg, err := LoadConfig([]byte{})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, DefaultLogMaxEntries, cfg.General.LogMaxEntries)
}
