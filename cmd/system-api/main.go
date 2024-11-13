package main

import (
	"context"
	"fmt"
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
	configFile := cCtx.String("config")
	listenAddr := cCtx.String("listen-addr")
	pipeFile := cCtx.String("pipe-file")

	// Load configuration file
	config := systemapi.NewSystemAPIConfig()
	if configFile != "" {
		config, err = systemapi.LoadConfigFromFile(configFile)
		if err != nil {
			fmt.Println("Error loading config", err)
			return err
		}
	}

	// Override unset cli flags with config file values
	if listenAddr == "" {
		config.General.ListenAddr = listenAddr
	}
	if pipeFile == "" {
		config.General.PipeFile = pipeFile
	}

	// Setup logging
	logTags := map[string]string{
		"version": common.Version,
	}

	log := common.SetupLogger(&common.LoggingOpts{
		JSON:           config.General.LogJSON,
		Debug:          config.General.LogDebug,
		Concise:        true,
		RequestHeaders: true,
		Tags:           logTags,
	})

	// Print configuration
	log.Info("config:",
		"listenAddr", config.General.ListenAddr,
		"pipeFile", config.General.PipeFile,
		"logJSON", config.General.LogJSON,
		"logDebug", config.General.LogDebug,
	)

	// Setup and start the server (in the background)
	cfg := &systemapi.HTTPServerConfig{
		Log:    log,
		Config: config,
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
