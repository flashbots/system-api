package common

var (
	Version    = "dev"
	ShellToUse = GetEnv("SHELL_TO_USE", "/bin/ash")
)
