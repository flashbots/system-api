package systemapi

import "github.com/flashbots/system-api/common"

var DefaultLogMaxEntries = common.GetEnvInt("MAX_EVENTS", 1000)
