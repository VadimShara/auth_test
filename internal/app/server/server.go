package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kuromii5/auth-part/internal/http/controllers"
	mwlog "github.com/kuromii5/auth-part/internal/http/middleware/mw_log"
	"github.com/kuromii5/auth-part/internal/repo"
	"github.com/kuromii5/auth-part/internal/service"
)

type Server struct {
	httpServer *http.Server
	logger     *slog.Logger
	db         *repo.DB
}

func NewServer(
	logger *slog.Logger,
	port int,
	reqTimeout, idleTimeout, accessTokenTTL, refreshTokenTTL time.Duration,
	tokenSecret, appEmail, appPassword, smtpHost string,
	db *repo.DB,
) *Server {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(mwlog.New(logger))
	r.Use(middleware.Recoverer)

	service := service.NewService(
		logger,
		accessTokenTTL,
		refreshTokenTTL,
		tokenSecret,
		appEmail,
		appPassword,
		smtpHost,
		db,
		db,
		db,
	)

	r.Get("/auth/tokens", controllers.IssueTokens(logger, service))
	r.Post("/auth/refresh", controllers.RefreshTokens(logger, service))

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      r,
		ReadTimeout:  reqTimeout,
		WriteTimeout: reqTimeout,
		IdleTimeout:  idleTimeout,
	}

	return &Server{
		logger:     logger,
		httpServer: httpServer,
		db:         db,
	}
}

func (s *Server) Run() error {
	s.logger.Info("Starting server...", "addr", s.httpServer.Addr)

	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down server...")

	return s.httpServer.Shutdown(ctx)
}
