// Package web is the embedded web server: a REST API giving the counters of
// what wolverine processed and the alerts raised (also streamed as they are
// raised), and a dashboard that displays them.
//
//	GET /api/v1/info                 sources and rules
//	GET /api/v1/stats                totals, since the start or of an interval
//	GET /api/v1/stats/series         counters by time bucket
//	GET /api/v1/alerts               alerts within the maximum lifetime
//	GET /api/v1/alerts/watch         new alerts, as server-sent events
//	GET /                            the dashboard
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"wolverine/internal/action"
	"wolverine/internal/config"
	"wolverine/internal/engine"
	"wolverine/internal/stats"
	"wolverine/internal/verbose"
)

//go:embed ui
var uiFiles embed.FS

// Backend is what the server reports on: the engine.
type Backend interface {
	Info() engine.Info
	Stats() *stats.Store
	AlertRecords() []engine.AlertRecord
	PendingUndos() []action.Pending
	Watch() (<-chan engine.Notice, func())
}

// maxWatchers is the number of /alerts/watch connections served at once.
const maxWatchers = 64

// Server is the web server.
type Server struct {
	backend Backend
	// token, if set, is required by the API.
	token    string
	srv      *http.Server
	listener net.Listener
	watchers atomic.Int64
	// heartbeat is how often a comment is sent to idle watchers, so that
	// proxies do not close the connection.
	heartbeat time.Duration
	// now gives the current time (time.Now in production).
	now func() time.Time
}

// New creates the server described by the configuration. It does not listen
// yet (see Start).
func New(b Backend, cfg config.HTTP) (*Server, error) {
	s := &Server{backend: b, heartbeat: 15 * time.Second, now: time.Now}
	if cfg.TokenEnv != "" {
		var ok bool
		if s.token, ok = os.LookupEnv(cfg.TokenEnv); !ok || s.token == "" {
			return nil, fmt.Errorf("http: environment variable %s (token_env) is not set", cfg.TokenEnv)
		}
	}
	s.srv = &http.Server{
		Addr:              cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: /alerts/watch streams; the other handlers set
		// their own deadline.
		ErrorLog: log.New(os.Stderr, "wolverine: http: ", 0),
	}
	return s, nil
}

// Start listens and serves in the background. Listening errors (address in
// use...) are returned.
func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	s.listener = l
	if s.token == "" && !loopback(l.Addr()) {
		log.Printf("warning: http: the API on %s has no token: anyone who can reach it sees the alerts (set http.token_env)", l.Addr())
	}
	verbose.Infof("http: dashboard and API on http://%s/", l.Addr())
	go func() {
		if err := s.srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("http: %v", err)
		}
	}()
	return nil
}

// Addr returns the address listened on, once started.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// Shutdown stops the server, waiting at most until ctx is done for the
// requests in progress.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

func loopback(a net.Addr) bool {
	tcp, ok := a.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// Handler returns the routes of the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/info", s.api(s.info))
	mux.Handle("GET /api/v1/stats", s.api(s.stats))
	mux.Handle("GET /api/v1/stats/series", s.api(s.series))
	mux.Handle("GET /api/v1/alerts", s.api(s.alerts))
	mux.Handle("GET /api/v1/alerts/watch", s.auth(http.HandlerFunc(s.watch)))
	mux.Handle("GET /api/v1/alerts/{id}", s.api(s.alert))
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "unknown API endpoint %s %s", r.Method, r.URL.Path)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	})
	ui, _ := fs.Sub(uiFiles, "ui")
	mux.Handle("GET /", http.FileServerFS(ui))
	return secure(mux)
}

// secure adds the security headers to every response.
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.ServeHTTP(w, r)
	})
}

// auth requires the token, if there is one.
func (s *Server) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token != "" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="wolverine"`)
				writeError(w, http.StatusUnauthorized, "a valid token is required (Authorization: Bearer <token>)")
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// api serves a JSON endpoint: f returns the value to encode, or an error
// (an *apiError for a client error).
func (s *Server) api(f func(*http.Request) (any, error)) http.Handler {
	return s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second))
		v, err := f(r)
		var ae *apiError
		switch {
		case errors.As(err, &ae):
			writeError(w, ae.status, "%s", ae.msg)
		case err != nil:
			log.Printf("http: %s: %v", r.URL.Path, err)
			writeError(w, http.StatusInternalServerError, "internal error")
		default:
			writeJSON(w, http.StatusOK, v)
		}
	}))
}
