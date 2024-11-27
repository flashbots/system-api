package systemapi

import (
	"errors"
	"os"
	"time"

	"github.com/flashbots/go-utils/tls"
)

// createTLSCertIfNotExists created a cert and key file if it doesn't exist yet
func (s *Server) createTLSCertIfNotExists() error {
	log := s.log.With("cert", s.cfg.General.TLSCertPath, "key", s.cfg.General.TLSKeyPath)
	_, err1 := os.Stat(s.cfg.General.TLSCertPath)
	if err1 != nil && !os.IsNotExist(err1) {
		return err1
	}

	_, err2 := os.Stat(s.cfg.General.TLSKeyPath)
	if err2 != nil && !os.IsNotExist(err2) {
		return err2
	}

	certFileExists := err1 == nil
	keyFileExists := err2 == nil
	if certFileExists && keyFileExists {
		// Files exist, use them
		log.Info("TLS cert and key found, using them")
		return nil
	} else if certFileExists || keyFileExists {
		// Only one of the files exist, should not happen
		return errors.New("both TLS cert and key files are required, but only one exists")
	}

	// Files do not exist, should create them
	if !s.cfg.General.TLSCreateIfMissing {
		return errors.New("TLS cert and key files do not exist, but config is set to not create them")
	}

	// Create them
	cert, key, err := tls.GenerateTLS(time.Hour*24*365, s.cfg.General.TLSCertHosts)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.cfg.General.TLSCertPath, cert, 0o600)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.cfg.General.TLSKeyPath, key, 0o600)
	if err != nil {
		return err
	}

	log.With("hosts", s.cfg.General.TLSCertHosts).Info("TLS cert and key files created")
	return nil
}
