// Package systemapi provides components for the System API service.
package systemapi

import (
	"bufio"
	"context"
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

type HTTPServerConfig struct {
	ListenAddr   string
	Log          *httplog.Logger
	PipeFilename string
	EnablePprof  bool

	DrainDuration            time.Duration
	GracefulShutdownDuration time.Duration
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration

	Config *SystemAPIConfig
}

type Event struct {
	ReceivedAt time.Time `json:"received_at"`
	Message    string    `json:"message"`
}

type Server struct {
	cfg *HTTPServerConfig
	log *httplog.Logger

	srv *http.Server

	events     []Event
	eventsLock sync.RWMutex
}

func NewServer(cfg *HTTPServerConfig) (srv *Server, err error) {
	srv = &Server{
		cfg:    cfg,
		log:    cfg.Log,
		srv:    nil,
		events: make([]Event, 0),
	}

	if cfg.PipeFilename != "" {
		os.Remove(cfg.PipeFilename)
		err := syscall.Mknod(cfg.PipeFilename, syscall.S_IFIFO|0o666, 0)
		if err != nil {
			return nil, err
		}

		go srv.readPipeInBackground()
	}

	srv.srv = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.getRouter(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return srv, nil
}

func (s *Server) getRouter() http.Handler {
	mux := chi.NewRouter()

	mux.Use(httplog.RequestLogger(s.log))
	mux.Use(middleware.Recoverer)

	mux.Get("/", s.handleLivenessCheck)
	mux.Get("/livez", s.handleLivenessCheck)
	mux.Get("/api/v1/new_event", s.handleNewEvent)
	mux.Get("/api/v1/events", s.handleGetEvents)
	mux.Get("/logs", s.handleGetLogs)
	mux.Get("/api/v1/actions/{action}", s.handleAction)
	mux.Post("/api/v1/file-upload/{file}", s.handleFileUpload)

	if s.cfg.EnablePprof {
		s.log.Info("pprof API enabled")
		mux.Mount("/debug", middleware.Profiler())
	}

	return mux
}

func (s *Server) readPipeInBackground() {
	file, err := os.OpenFile(s.cfg.PipeFilename, os.O_CREATE, os.ModeNamedPipe)
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

func (s *Server) Start() {
	s.log.Info("Starting HTTP server", "listenAddress", s.cfg.ListenAddr)
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error("HTTP server failed", "err", err)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("Shutting down HTTP server")

	if err := s.srv.Shutdown(ctx); err != nil {
		s.log.Error("HTTP server shutdown failed", "err", err)
	}

	if s.cfg.PipeFilename != "" {
		os.Remove(s.cfg.PipeFilename)
	}

	s.log.Info("HTTP server shutdown")
	return nil
}

func (s *Server) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (s *Server) addEvent(event Event) {
	// Add event to the list and prune if necessary
	s.eventsLock.Lock()
	s.events = append(s.events, event)
	if len(s.events) > MaxEvents {
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
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	// respond either as JSON or plain text
	if r.URL.Query().Get("format") == "text" {
		// write events as plain text response
		s.writeEventsAsText(w)
		return
	}

	// write events as JSON response
	s.eventsLock.RLock()
	defer s.eventsLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(s.events)
	if err != nil {
		s.log.Error("Failed to encode events", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	s.writeEventsAsText(w)
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	action := chi.URLParam(r, "action")
	s.log.Info("Received action", "action", action)

	if s.cfg.Config == nil {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	cmd, ok := s.cfg.Config.Actions[action]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.log.Info("Executing action", "action", action, "cmd", cmd)
	s.addInternalEvent("executing action: " + action + " = " + cmd)

	stdout, stderr, err := common.Shellout(cmd)
	if err != nil {
		s.log.Error("Failed to execute action", "action", action, "cmd", cmd, "err", err, "stderr", stderr)
		s.addInternalEvent("error executing action: " + action + " - error: " + err.Error() + " (stderr: " + stderr + ")")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.log.Info("Action executed", "action", action, "cmd", cmd, "stdout", stdout, "stderr", stderr)
	s.addInternalEvent("executing action success: " + action + " = " + cmd)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	fileArg := chi.URLParam(r, "file")
	log := s.log.With("file", fileArg)
	log.Info("Receiving file upload")

	if s.cfg.Config == nil {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	filename, ok := s.cfg.Config.FileUploads[fileArg]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log = log.With("filename", filename)
	s.addInternalEvent("file upload: " + fileArg + " = " + filename)

	// 1. read content from payload r.Body
	content, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error("Failed to read content from payload", "err", err)
		s.addInternalEvent("file upload error (failed to read): " + fileArg + " = " + filename + " - error: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Debug("Content read from payload", "content", string(content))

	// 2. write content to file
	err = os.WriteFile(filename, content, 0o644) //nolint:gosec
	if err != nil {
		log.Error("Failed to write content to file", "err", err)
		s.addInternalEvent("file upload error (failed to write): " + fileArg + " = " + filename + " - error: " + err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Info("File uploaded")
	s.addInternalEvent(fmt.Sprintf("file upload success: %s = %s - content: %d bytes", fileArg, filename, len(content)))
	w.WriteHeader(http.StatusOK)
}
