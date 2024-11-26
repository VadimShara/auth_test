package controllers

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	le "github.com/kuromii5/auth-part/pkg/logger/l_err"
)

type TokenIssuer interface {
	IssueTokens(w http.ResponseWriter, userID uuid.UUID, clientIP string) error
}

func IssueTokens(log *slog.Logger, tokenIssuer TokenIssuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const f = "controllers.IssueTokens"

		log.With(slog.String("fn", f))
		log.Info("Issuing tokens for user")

		userID := r.URL.Query().Get("user_id")
		userUUID, err := uuid.Parse(userID)
		if err != nil {
			log.Error("invalid user ID", le.Err(err))

			w.WriteHeader(http.StatusBadRequest)
			RespondErr(w, r, "invalid user ID")
			return
		}

		clientIP := r.RemoteAddr
		err = tokenIssuer.IssueTokens(w, userUUID, clientIP)
		if err != nil {
			log.Error("failed to issue tokens", le.Err(err))

			w.WriteHeader(http.StatusInternalServerError)
			RespondErr(w, r, "failed to issue tokens")
			return
		}

		log.Info("Successfully issued tokens for user", slog.String("user_id", userID))

		w.Header().Set("Content-Type", "application/json")
		RespondOK(w, r)
	}
}
