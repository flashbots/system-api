package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/flashbots/system-api/common"
	"github.com/flashbots/system-api/systemapi"
	cli "github.com/urfave/cli/v2" // imports as package "cli"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "listen-addr",
		Value: "0.0.0.0:3535",
		Usage: "address to serve certificate on",
	},
	&cli.StringFlag{
		Name:  "pipe-file",
		Value: "pipe.fifo",
		Usage: "filename for named pipe (for sending events into this service)",
	},
	&cli.BoolFlag{
		Name:  "log-json",
		Value: false,
		Usage: "log in JSON format",
	},
	&cli.BoolFlag{
		Name:  "log-debug",
		Value: true,
		Usage: "log debug messages",
	},
	&cli.StringFlag{
		Name:  "config",
		Value: "",
		Usage: "config file",
	},
}

func main() {
	app := &cli.App{
		Name:    "system-api",
		Usage:   "HTTP API for status events",
		Version: common.Version,
		Flags:   flags,
		Action:  runCli,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runCli(cCtx *cli.Context) (err error) {
	listenAddr := cCtx.String("listen-addr")
	pipeFile := cCtx.String("pipe-file")
	logJSON := cCtx.Bool("log-json")
	logDebug := cCtx.Bool("log-debug")

	logTags := map[string]string{
		"version": common.Version,
	}
	configFile := cCtx.String("config")

	log := common.SetupLogger(&common.LoggingOpts{
		JSON:           logJSON,
		Debug:          logDebug,
		Concise:        true,
		RequestHeaders: true,
		Tags:           logTags,
	})

	var config *systemapi.SystemAPIConfig
	if configFile != "" {
		config, err = systemapi.LoadConfigFromFile(configFile)
		if err != nil {
			log.Error("Error loading config", "err", err)
			return err
		}
		log.Info("Loaded config", "config-file", config)
	}

	// Setup and start the server (in the background)
	cfg := &systemapi.HTTPServerConfig{
		ListenAddr:   listenAddr,
		Log:          log,
		PipeFilename: pipeFile,
		Config:       config,
	}
	server, err := systemapi.NewServer(cfg)
	if err != nil {
		return err
	}
	go server.Start()

	// Wait for signal, then graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	<-exit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = server.Shutdown(ctx); err != nil {
		log.Error("HTTP shutdown error", "err", err)
		return err
	}
	return nil
}
