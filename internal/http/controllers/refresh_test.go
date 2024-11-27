package controllers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"bytes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log/slog"
)

type MockTokenRefresher struct {
	mock.Mock
}

func (m *MockTokenRefresher) RefreshTokens(w http.ResponseWriter, accessToken, refreshToken, clientIP string) error {
	args := m.Called(w, accessToken, refreshToken, clientIP)
	return args.Error(0)
}

func TestRefreshTokens(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	mockTokenRefresher := new(MockTokenRefresher)

	mockTokenRefresher.On("RefreshTokens", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := RefreshTokens(logger, mockTokenRefresher)

	req, err := http.NewRequest(http.MethodGet, "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "access_token", Value: uuid.New().String()})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: uuid.New().String()})

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	mockTokenRefresher.AssertExpectations(t)
	assert.Contains(t, buf.String(), "Successfully refreshed tokens")
}

func TestRefreshTokens_MissingRefreshToken(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	mockTokenRefresher := new(MockTokenRefresher)

	handler := RefreshTokens(logger, mockTokenRefresher)

	req, err := http.NewRequest(http.MethodGet, "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "access_token", Value: uuid.New().String()})

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	assert.Contains(t, buf.String(), "refresh token not found")
}

func TestRefreshTokens_FailedRefresh(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	mockTokenRefresher := new(MockTokenRefresher)

	mockTokenRefresher.On("RefreshTokens", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("refresh error"))

	handler := RefreshTokens(logger, mockTokenRefresher)

	req, err := http.NewRequest(http.MethodGet, "/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "access_token", Value: uuid.New().String()})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: uuid.New().String()})

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)

	assert.Contains(t, buf.String(), "failed to refresh tokens")
}