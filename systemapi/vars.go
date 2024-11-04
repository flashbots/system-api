package systemapi

import "github.com/flashbots/system-api/common"

var (
	MaxEvents  = common.GetEnvInt("MAX_EVENTS", 1000)
	ShellToUse = common.GetEnv("SHELL_TO_USE", "/bin/ash")
)
