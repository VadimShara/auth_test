package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/kuromii5/auth-part/internal/models"
	le "github.com/kuromii5/auth-part/pkg/logger/l_err"
	"golang.org/x/crypto/bcrypt"
)

type SessionSaver interface {
	SaveSession(session models.Session) error
}

func (s *Service) IssueTokens(w http.ResponseWriter, userID uuid.UUID, clientIP string) error {
	const f = "service.IssueTokens"

	log := s.log.With(slog.String("fn", f))

	jti := uuid.New().String()
	accessTokenClaims := jwt.MapClaims{
		"jti": jti,
		"sub": userID.String(),
		"exp": time.Now().Add(s.accessTokenTTL).Unix(),
		"iat": time.Now().Unix(),
		"ip":  clientIP,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessTokenClaims)

	accessTokenString, err := accessToken.SignedString([]byte(s.secret))
	if err != nil {
		log.Error("failed to sign access token", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	refreshTokenBytes := make([]byte, 32)
	_, err = rand.Read(refreshTokenBytes)
	if err != nil {
		log.Error("failed to generate refresh token", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}
	refreshToken := base64.StdEncoding.EncodeToString(refreshTokenBytes)

	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash refresh token", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	session := models.Session{
		UserID:          userID,
		AccessTokenJTI:  jti,
		RefreshToken:    string(hashedRefreshToken),
		RefreshTokenExp: time.Now().Add(s.refreshTokenTTL),
		ClientIP:        clientIP,
	}
	err = s.sessionSaver.SaveSession(session)
	if err != nil {
		log.Error("failed to save session", le.Err(err))

		return fmt.Errorf("%s: %w", f, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessTokenString,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		Path:     "/",
		Expires:  time.Now().Add(s.accessTokenTTL),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		Path:     "/",
		Expires:  time.Now().Add(s.refreshTokenTTL),
	})

	return nil
}
