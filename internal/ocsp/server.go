package ocsp

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"quantumca-platform/internal/utils"
)

type Server struct {
	db        *sql.DB
	config    *utils.Config
	responder *Responder
}

func NewServer(db *sql.DB, config *utils.Config) *Server {
	return &Server{
		db:        db,
		config:    config,
		responder: NewResponder(db, config),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleOCSPRequest)
	mux.HandleFunc("/ocsp", s.handleOCSPRequest)

	port := s.config.OCSPPort
	if port == 0 {
		port = 8081
	}

	server := &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: mux,
	}

	return server.ListenAndServe()
}

func (s *Server) handleOCSPRequest(w http.ResponseWriter, r *http.Request) {
	var requestBytes []byte
	var err error

	switch r.Method {
	case "GET":
		requestBytes, err = s.handleGETRequest(r)
	case "POST":
		requestBytes, err = s.handlePOSTRequest(r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	responseBytes, err := s.responder.HandleRequest(requestBytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to process OCSP request: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

func (s *Server) handleGETRequest(r *http.Request) ([]byte, error) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || path == "ocsp" {
		return nil, fmt.Errorf("missing OCSP request in URL path")
	}

	decoded, err := base64.URLEncoding.DecodeString(path)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 request: %v", err)
	}

	return decoded, nil
}

func (s *Server) handlePOSTRequest(r *http.Request) ([]byte, error) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		return nil, fmt.Errorf("invalid content type")
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %v", err)
	}
	defer r.Body.Close()

	return body, nil
}