// Package common contains common utilities and functions used by the service.
package common

import (
	"log/slog"

	httplog "github.com/go-chi/httplog/v2"
)

type LoggingOpts struct {
	ServiceName string

	// Whether to log in JSON format
	JSON bool

	// Whether to log debug messages
	Debug bool

	// Concise mode includes fewer log details during the request flow. For example excluding details like
	// request content length, user-agent and other details. This is useful if during development your console is too noisy.
	Concise bool

	// RequestHeaders enables logging of all request headers, however sensitive headers like authorization, cookie and set-cookie are hidden.
	RequestHeaders bool

	// Tags are additional fields included at the root level of all logs. These can be useful for example the commit hash of a build, or an environment name like prod/stg/dev
	Tags map[string]string
}

func SetupLogger(opts *LoggingOpts) (log *httplog.Logger) {
	logLevel := slog.LevelInfo
	if opts.Debug {
		logLevel = slog.LevelDebug
	}

	logger := httplog.NewLogger(opts.ServiceName, httplog.Options{
		JSON:           opts.JSON,
		LogLevel:       logLevel,
		Concise:        opts.Concise,
		RequestHeaders: opts.RequestHeaders,
		Tags:           opts.Tags,
	})
	return logger
}
