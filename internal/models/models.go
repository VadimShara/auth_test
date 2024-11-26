package models

import (
	"time"

	"github.com/google/uuid"
)

var (
	StatusOK  = "OK"
	StatusErr = "Error"
)

type Response struct {
	Status   string `json:"status"`
	ErrorMsg string `json:"error,omitempty"`
}

type TokenPair struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type Session struct {
	ID              int       `json:"id"`
	UserID          uuid.UUID `json:"user_id"`
	AccessTokenJTI  string    `json:"access_token_jti"`
	RefreshToken    string    `json:"refresh_token"`
	RefreshTokenExp time.Time `json:"refresh_token_exp"`
	ClientIP        string    `json:"client_ip"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
