// Package systemapi provides components for the System API service.
package systemapi

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/flashbots/system-api/common"
	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v2"
)

type Event struct {
	ReceivedAt time.Time `json:"received_at"`
	Message    string    `json:"message"`
}

type Server struct {
	cfg *SystemAPIConfig
	log *httplog.Logger
	srv *http.Server

	events     []Event
	eventsLock sync.RWMutex

	basicAuthHash string
}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewServer(log *httplog.Logger, cfg *SystemAPIConfig) (server *Server, err error) {
	server = &Server{
		cfg:    cfg,
		log:    log,
		srv:    nil,
		events: make([]Event, 0),
	}

	// Load (or create) file with basic auth secret hash
	err = server.loadBasicAuthSecretFromFile()
	if err != nil {
		return nil, err
	}

	// Setup the named pipe for receiving events
	if cfg.General.PipeFile != "" {
		// If the file does not exist, create it. If it exists, ensure it is a named pipe.
		stats, err := os.Stat(cfg.General.PipeFile)
		if err != nil {
			if os.IsNotExist(err) {
				err := syscall.Mknod(cfg.General.PipeFile, syscall.S_IFIFO|0o666, 0)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, err
			}
		} else {
			mode := stats.Mode()
			if mode&os.ModeNamedPipe == 0 {
				return nil, fmt.Errorf("file %s is not a named pipe", cfg.General.PipeFile)
			}
		}

		// Start reading the pipe in the background
		go server.readPipeInBackground()
	}

	// Load or create TLS certificate
	if cfg.General.TLSEnabled {
		err = server.createTLSCertIfNotExists()
		if err != nil {
			server.log.Error("Failed to create TLS certificate", "err", err)
			return nil, err
		}
	}

	// Create the HTTP server
	server.srv = &http.Server{
		Addr:         cfg.General.ListenAddr,
		Handler:      server.getRouter(),
		ReadTimeout:  time.Duration(cfg.General.HTTPReadTimeoutMillis) * time.Millisecond,
		WriteTimeout: time.Duration(cfg.General.HTTPWriteTimeoutMillis) * time.Millisecond,
	}

	return server, nil
}

func (s *Server) loadBasicAuthSecretFromFile() error {
	if s.cfg.General.BasicAuthSecretPath == "" {
		return nil
	}

	// Create if the file does not exist
	if _, err := os.Stat(s.cfg.General.BasicAuthSecretPath); os.IsNotExist(err) {
		err = os.WriteFile(s.cfg.General.BasicAuthSecretPath, []byte{}, 0o600)
		if err != nil {
			return fmt.Errorf("failed to create basic auth secret file: %w", err)
		}
		s.log.Info("Basic auth file created, auth disabled until secret is configured", "file", s.cfg.General.BasicAuthSecretPath)
		s.basicAuthHash = ""
		return nil
	}

	// Read the secret from the file
	secret, err := os.ReadFile(s.cfg.General.BasicAuthSecretPath)
	if err != nil {
		return fmt.Errorf("failed to read basic auth secret file: %w", err)
	}

	s.basicAuthHash = string(secret)
	if len(secret) == 0 {
		s.log.Info("Basic auth file without secret loaded, auth disabled until secret is configured", "file", s.cfg.General.BasicAuthSecretPath)
	} else {
		if len(s.basicAuthHash) != 64 {
			return fmt.Errorf("basic auth secret in %s does not look like a SHA256 hash (must be 64 characters)", s.cfg.General.BasicAuthSecretPath)
		}
		s.log.Info("Basic auth enabled", "file", s.cfg.General.BasicAuthSecretPath)
	}
	return nil
}

func (s *Server) getRouter() http.Handler {
	mux := chi.NewRouter()

	mux.Use(httplog.RequestLogger(s.log))
	mux.Use(middleware.Recoverer)

	// Enable a custom HTTP Basic Auth middleware
	mux.Use(BasicAuth("system-api", s.cfg.General.BasicAuthSecretSalt, s.getBasicAuthHashedCredentials))

	// Common APIs
	mux.Get("/", s.handleLivenessCheck)
	mux.Get("/livez", s.handleLivenessCheck)

	// Event (log) APIs
	mux.Get("/api/v1/new_event", s.handleNewEvent)
	mux.Get("/api/v1/events", s.handleGetEvents)
	mux.Get("/logs", s.handleGetLogs)

	// API to set the basic auth secret
	mux.Post("/api/v1/set-basic-auth", s.handleSetBasicAuthCreds)

	// API to trigger an action
	mux.Get("/api/v1/actions/{action}", s.handleAction)

	// API to upload a file
	mux.Post("/api/v1/file-upload/{file}", s.handleFileUpload)

	// Optionally, pprof
	if s.cfg.General.EnablePprof {
		mux.Mount("/debug", middleware.Profiler())
		s.log.Info("pprof API enabled: /debug/pprof/")
	}

	return mux
}

func (s *Server) readPipeInBackground() {
	file, err := os.OpenFile(s.cfg.General.PipeFile, os.O_CREATE, os.ModeNamedPipe)
	if err != nil {
		s.log.Error("Open named pipe file error:", "error", err)
		return
	}

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes('\n')
		if err == nil {
			msg := strings.Trim(string(line), "\n")

			s.log.Info("Received new event via pipe", "message", msg)
			s.addEvent(Event{
				ReceivedAt: time.Now().UTC(),
				Message:    msg,
			})
		}
	}
}

func (s *Server) Start() (err error) {
	s.log.Info("Starting HTTP server", "listenAddress", s.cfg.General.ListenAddr)

	if s.cfg.General.TLSEnabled {
		s.log.Info("TLS enabled", "cert", s.cfg.General.TLSCertPath, "key", s.cfg.General.TLSKeyPath)
		err = s.srv.ListenAndServeTLS(s.cfg.General.TLSCertPath, s.cfg.General.TLSKeyPath)
	} else {
		err = s.srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error("HTTP server failed", "err", err)
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("Shutting down HTTP server")

	if err := s.srv.Shutdown(ctx); err != nil {
		s.log.Error("HTTP server shutdown failed", "err", err)
	}

	s.log.Info("HTTP server shutdown")
	return nil
}

func (s *Server) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	s.respondOKJSON(w, map[string]string{
		"status": "ok",
	})
}

func (s *Server) addEvent(event Event) {
	// Add event to the list and prune if necessary
	s.eventsLock.Lock()
	s.events = append(s.events, event)
	if len(s.events) > s.cfg.General.LogMaxEntries {
		s.events = s.events[1:]
	}
	s.eventsLock.Unlock()
}

func (s *Server) addInternalEvent(msg string) {
	s.addEvent(Event{
		ReceivedAt: time.Now().UTC(),
		Message:    "[system-api] " + msg,
	})
}

func (s *Server) handleNewEvent(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("message")
	s.log.Info("Received new event", "message", msg)
	s.addEvent(Event{
		ReceivedAt: time.Now().UTC(),
		Message:    msg,
	})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) writeEventsAsText(w http.ResponseWriter) {
	s.eventsLock.RLock()
	defer s.eventsLock.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	for _, event := range s.events {
		_, err := w.Write([]byte(event.ReceivedAt.Format(time.RFC3339) + " \t " + event.Message + "\n"))
		if err != nil {
			s.log.Error("Failed to write event", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	// respond either as JSON or plain text
	if r.URL.Query().Get("format") == "text" {
		// write events as plain text response
		s.writeEventsAsText(w)
		return
	}

	// Send events as JSON response
	s.eventsLock.RLock()
	defer s.eventsLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(s.events)
	if err != nil {
		s.log.Error("Failed to encode events", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) respondErrorJSON(w http.ResponseWriter, code int, message string) {
	w.Header().Set(HeaderContentType, MediaTypeJSON)
	w.WriteHeader(code)
	resp := httpErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.With("response", resp, "error", err).Error("could not write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (s *Server) respondOKJSON(w http.ResponseWriter, response any) {
	w.Header().Set(HeaderContentType, MediaTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.log.With("response", response, "error", err).Error("could not write OK response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	s.writeEventsAsText(w)
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "action")
	s.log.Info("Received action", "action", action)

	if s.cfg == nil {
		s.respondErrorJSON(w, http.StatusNotImplemented, "Action not configured")
		return
	}

	cmd, ok := s.cfg.Actions[action]
	if !ok {
		s.respondErrorJSON(w, http.StatusBadRequest, "Specified action not configured")
		return
	}

	s.log.Info("Executing action", "action", action, "cmd", cmd)
	s.addInternalEvent("executing action: " + action + " = " + cmd)

	stdout, stderr, err := common.Shellout(cmd)
	if err != nil {
		s.log.Error("Failed to execute action", "action", action, "cmd", cmd, "err", err, "stderr", stderr)
		s.addInternalEvent("error executing action: " + action + " - error: " + err.Error() + " (stderr: " + stderr + ")")
		s.respondErrorJSON(w, http.StatusInternalServerError, "Failed to execute action: "+action+" - error: "+err.Error())
		return
	}

	s.log.Info("Action executed", "action", action, "cmd", cmd, "stdout", stdout, "stderr", stderr)
	s.addInternalEvent("executing action success: " + action + " = " + cmd)
	s.respondOKJSON(w, map[string]string{
		"message": "Action executed successfully",
	})
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	fileArg := chi.URLParam(r, "file")
	log := s.log.With("file", fileArg)
	log.Info("Receiving file upload")

	if s.cfg == nil {
		s.respondErrorJSON(w, http.StatusNotImplemented, "File upload not configured")
		return
	}

	filename, ok := s.cfg.FileUploads[fileArg]
	if !ok {
		s.respondErrorJSON(w, http.StatusBadRequest, "Specified file upload not configured")
		return
	}

	log = log.With("filename", filename)
	s.addInternalEvent("file upload: " + fileArg + " = " + filename)

	// 1. read content from payload r.Body
	content, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error("Failed to read content from payload", "err", err)
		s.addInternalEvent("file upload error (failed to read): " + fileArg + " = " + filename + " - error: " + err.Error())
		s.respondErrorJSON(w, http.StatusInternalServerError, "Failed to read content from payload")
		return
	}

	log.Debug("Content read from payload", "content", string(content))

	// 2. write content to file
	err = os.WriteFile(filename, content, 0o644) //nolint:gosec
	if err != nil {
		log.Error("Failed to write content to file", "err", err)
		s.addInternalEvent("file upload error (failed to write): " + fileArg + " = " + filename + " - error: " + err.Error())
		s.respondErrorJSON(w, http.StatusInternalServerError, "Failed to write content to file")
		return
	}

	log.Info("File uploaded")
	s.addInternalEvent(fmt.Sprintf("file upload success: %s = %s - content: %d bytes", fileArg, filename, len(content)))
	s.respondOKJSON(w, map[string]string{
		"message":    "File uploaded successfully",
		"file":       filename,
		"size_bytes": fmt.Sprint(len(content)), //nolint:perfsprint
	})
}

// getBasicAuthHashedCredentials returns the hashed credentials for the basic auth middleware (on every request).
// It is dynamic because the secret can be set/updated during runtime.
func (s *Server) getBasicAuthHashedCredentials() map[string]string {
	hashedCredentials := make(map[string]string)
	if s.basicAuthHash != "" {
		hashedCredentials["admin"] = s.basicAuthHash
	}
	return hashedCredentials
}

func (s *Server) handleSetBasicAuthCreds(w http.ResponseWriter, r *http.Request) {
	if s.cfg.General.BasicAuthSecretPath == "" {
		s.log.Warn("Basic auth secret path not set")
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	// read secret from payload
	secret, err := io.ReadAll(r.Body)
	if err != nil {
		s.log.Error("Failed to read secret from payload", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create hash of the secret
	h := sha256.New()
	h.Write(secret)
	h.Write([]byte(s.cfg.General.BasicAuthSecretSalt))
	secretHash := hex.EncodeToString(h.Sum(nil))

	// write secret to file
	err = os.WriteFile(s.cfg.General.BasicAuthSecretPath, []byte(secretHash), 0o600)
	if err != nil {
		s.log.Error("Failed to write secret to file", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.basicAuthHash = secretHash
	s.log.Info("Basic auth secret updated")
	s.addInternalEvent("basic auth secret updated. new hash: " + secretHash)
	s.respondOKJSON(w, map[string]string{
		"message": "Basic auth secret updated",
	})
}
