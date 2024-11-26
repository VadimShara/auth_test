package service

import (
	"log/slog"
	"time"
)

type Service struct {
	log *slog.Logger

	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	secret          string
	sessionSaver    SessionSaver
	sessionDeleter  SessionDeleter
	sessionGetter   SessionGetter

	// for sending email warning
	appEmail    string
	appPassword string
	smtpHost    string
}

func NewService(
	log *slog.Logger,
	accessTokenTTL, refreshTokenTTL time.Duration,
	secret, appEmail, appPassword, smtpHost string,
	sessionSaver SessionSaver,
	sessionDeleter SessionDeleter,
	sessionGetter SessionGetter,
) *Service {
	return &Service{
		log:             log,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		secret:          secret,
		sessionSaver:    sessionSaver,
		sessionDeleter:  sessionDeleter,
		sessionGetter:   sessionGetter,
		appEmail:        appEmail,
		appPassword:     appPassword,
		smtpHost:        smtpHost,
	}
}
