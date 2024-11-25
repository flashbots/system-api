package systemapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	path := "../systemapi-config.toml"
	cfg, err := NewConfigFromFile(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotEmpty(t, cfg.Actions)
	require.Equal(t, "echo test", cfg.Actions["echo_test"])

	// check TLS config
	require.True(t, cfg.General.TLSEnabled)
	require.True(t, cfg.General.TLSCreateIfMissing)
	require.NotEmpty(t, cfg.General.TLSCertHosts)
	require.NotEmpty(t, cfg.General.TLSCertPath)
	require.NotEmpty(t, cfg.General.TLSKeyPath)
}

func TestEmptyConfig(t *testing.T) {
	cfg, err := NewConfigFromTOML([]byte{})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, DefaultLogMaxEntries, cfg.General.LogMaxEntries)
}
