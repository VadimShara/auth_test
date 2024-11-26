package controllers

import (
	"errors"
	"log/slog"
	"net/http"

	le "github.com/kuromii5/auth-part/pkg/logger/l_err"
)

type TokenRefresher interface {
	RefreshTokens(w http.ResponseWriter, accessToken, refreshToken, clientIP string) error
}

func RefreshTokens(log *slog.Logger, tokenRefresher TokenRefresher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const f = "controllers.RefreshTokens"

		log.With(slog.String("fn", f))
		log.Info("Refreshing tokens for user")

		clientIP := r.RemoteAddr

		refreshTokenCookie, err := r.Cookie("refresh_token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				log.Warn("refresh token not found", le.Err(err))

				w.WriteHeader(http.StatusBadRequest)
				RespondErr(w, r, "refresh token not found")
				return
			}
			log.Error("failed to get refresh token from cookies", le.Err(err))

			w.WriteHeader(http.StatusInternalServerError)
			RespondErr(w, r, "failed to get refresh token from cookies")
			return
		}

		accessTokenCookie, err := r.Cookie("access_token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				log.Warn("access token not found", le.Err(err))

				w.WriteHeader(http.StatusBadRequest)
				RespondErr(w, r, "refresh token not found")
				return
			}
			log.Error("failed to get access token from cookies", le.Err(err))

			w.WriteHeader(http.StatusInternalServerError)
			RespondErr(w, r, "failed to get access token from cookies")
			return
		}

		err = tokenRefresher.RefreshTokens(w, accessTokenCookie.Value, refreshTokenCookie.Value, clientIP)
		if err != nil {
			log.Error("failed to refresh tokens", le.Err(err))

			w.WriteHeader(http.StatusUnauthorized)
			RespondErr(w, r, "failed to refresh tokens")
			return
		}

		log.Info("Successfully refreshed tokens")

		w.Header().Set("Content-Type", "application/json")
		RespondOK(w, r)
	}
}
