package service

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/golang-jwt/jwt"
	"github.com/kuromii5/auth-part/internal/models"
	"github.com/kuromii5/auth-part/internal/repo"
	"github.com/kuromii5/auth-part/pkg/email"
	le "github.com/kuromii5/auth-part/pkg/logger/l_err"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrWrongAccessToken  = errors.New("wrong access token")
	ErrWrongRefreshToken = errors.New("wrong refresh token")
)

type SessionDeleter interface {
	DeleteSession(sessionID int) error
}
type SessionGetter interface {
	GetSession(jti string) (models.Session, error)
}

func (s *Service) RefreshTokens(w http.ResponseWriter, accessToken, refreshToken, clientIP string) error {
	const f = "service.RefreshTokens"

	log := s.log.With(slog.String("fn", f))

	jti, err := validateAndGetJTI(accessToken, s.secret)
	if err != nil {
		log.Error("invalid access token", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	session, err := s.sessionGetter.GetSession(jti)
	if err != nil {
		if errors.Is(err, repo.ErrSessionNotFound) {
			log.Error("wrong access token")

			return ErrWrongAccessToken
		}
		log.Error("failed to get session", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	if session.ClientIP != clientIP {
		log.Warn("IP address mismatch during token refresh", slog.String("client_ip", clientIP))

		err := email.SendWarning("mockemail@gmail.com", s.appEmail, s.appPassword, s.smtpHost)
		if err != nil {
			log.Error("failed to send warning to email")
		}

		// no need to return here
	}

	if err := bcrypt.CompareHashAndPassword([]byte(session.RefreshToken), []byte(refreshToken)); err != nil {
		log.Error("refresh tokens don't match", le.Err(err))

		return fmt.Errorf("%s: %w", f, ErrWrongRefreshToken)
	}

	// Delete old session before creating new one
	err = s.sessionDeleter.DeleteSession(session.ID)
	if err != nil {
		log.Error("failed to delete old session", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	err = s.IssueTokens(w, session.UserID, clientIP)
	if err != nil {
		log.Error("failed to issue tokens", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	log.Info("Successfully refreshed tokens")

	return nil
}

func validateAndGetJTI(tokenString string, secret string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jti, ok := claims["jti"].(string)
		if !ok {
			return "", fmt.Errorf("missing JTI claim")
		}
		return jti, nil
	}

	return "", fmt.Errorf("invalid token")
}
