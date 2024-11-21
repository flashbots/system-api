package systemapi

import (
	"time"

	"github.com/flashbots/go-utils/tls"
)

func (s *Server) loadOrCreateTLSCert() error {
	_, _, err := tls.GenerateTLS(time.Hour*24*365, []string{})
	return err
}
