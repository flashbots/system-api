package systemapi

import "github.com/flashbots/system-api/common"

var MaxEvents = common.GetEnvInt("MAX_EVENTS", 1000)
