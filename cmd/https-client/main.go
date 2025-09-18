package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/flashbots/system-api/common"
	cli "github.com/urfave/cli/v2"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "server-addr",
		Value: "https://0.0.0.0:8080",
		Usage: "address to serve certificate on",
	},
}

func main() {
	app := &cli.App{
		Name:   "https-client",
		Usage:  "Client to allow only specific self-signed server cert",
		Flags:  flags,
		Action: runCli,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func runCli(cCtx *cli.Context) error {
	log := common.SetupLogger(&common.LoggingOpts{})

	serverAddr := cCtx.String("server-addr")

	certFile := "cert.pem"

	certData, err := os.ReadFile(certFile)
	if err != nil {
		log.Error("could not read cert data", "err", err)
		return err
	}

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(certData)
	if !ok {
		log.Error("invalid certificate received", "cert", string(certData))
		return errors.New("invalid certificate")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	resp, err := client.Get(serverAddr)
	if err != nil {
		log.Error("http request error", "err", err)
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("could not read proxied service body", "err", err)
		return err
	}

	log.Info("Received", "resp", string(respBody))

	return nil
}
