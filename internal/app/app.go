package app

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kuromii5/auth-part/internal/app/logger"
	"github.com/kuromii5/auth-part/internal/app/server"
	"github.com/kuromii5/auth-part/internal/config"
	"github.com/kuromii5/auth-part/internal/repo"
	le "github.com/kuromii5/auth-part/pkg/logger/l_err"
)

type App struct {
	logger *slog.Logger
	server *server.Server
	db     *repo.DB
}

func NewApp() *App {
	config := config.Load()

	logger := logger.NewLogger(config.Env, config.LogLevel)

	logger.Debug("config settings", slog.Any("config", config))

	db := repo.NewDB(config.PGConfig)

	server := server.NewServer(
		logger,
		config.Port,
		config.ReqTimeout,
		config.IdleTimeout,
		config.TokenConfig.AccessTTL,
		config.TokenConfig.RefreshTTL,
		config.TokenConfig.Secret,
		config.AppEmail,
		config.AppPassword,
		config.SmtpHost,
		db,
	)

	return &App{
		logger: logger,
		server: server,
		db:     db,
	}
}

func (a *App) Run() error {
	go func() {
		if err := a.server.Run(); err != nil && err != http.ErrServerClosed {
			a.logger.Error("server failed", le.Err(err))
		}
	}()

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-done

	a.logger.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := a.Shutdown(ctx); err != nil {
		a.logger.Error("server shutdown error", le.Err(err))

		return err
	}

	a.logger.Info("server stopped")

	return nil
}

func (a *App) Shutdown(ctx context.Context) error {
	a.db.Close()
	return a.server.Shutdown(ctx)
}
