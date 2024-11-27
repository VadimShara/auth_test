package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/VadimShara/auth-part/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

type MockSessionSaver struct {
	mock.Mock
}

func (m *MockSessionSaver) SaveSession(session models.Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func TestIssueTokens(t *testing.T) {
	mockSessionSaver := new(MockSessionSaver)

	accessTokenTTL := 15 * time.Minute
	refreshTokenTTL := 7 * 24 * time.Hour
	secret := "test_secret"
	appEmail := "test@example.com"
	appPassword := "test_password"
	smtpHost := "smtp.example.com"

	logger := slog.New(slog.NewTextHandler(nil, nil))

	service := NewService(
		logger,
		accessTokenTTL,
		refreshTokenTTL,
		secret,
		appEmail,
		appPassword,
		smtpHost,
		mockSessionSaver,
		nil, 
		nil, 
	)

	userID := uuid.New()
	clientIP := "127.0.0.1"

	w := httptest.NewRecorder()

	var capturedSession models.Session
	mockSessionSaver.On("SaveSession", mock.AnythingOfType("models.Session")).Run(func(args mock.Arguments) {
		capturedSession = args.Get(0).(models.Session)
	}).Return(nil)

	err := service.IssueTokens(w, userID, clientIP)
	assert.NoError(t, err, "IssueTokens should not return an error")

	resp := w.Result()
	defer resp.Body.Close()

	cookies := resp.Cookies()
	assert.Len(t, cookies, 2, "should set 2 cookies (access and refresh tokens)")

	var accessToken, refreshToken *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "access_token" {
			accessToken = cookie
		} else if cookie.Name == "refresh_token" {
			refreshToken = cookie
		}
	}

	assert.NotNil(t, accessToken, "access token cookie should be set")
	assert.NotNil(t, refreshToken, "refresh token cookie should be set")

	token, err := jwt.Parse(accessToken.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	assert.NoError(t, err, "access token should be valid")
	assert.True(t, token.Valid, "access token should be valid")

	t.Logf("Captured RefreshToken (hashed): %s", capturedSession.RefreshToken)
	t.Logf("RefreshToken (original): %s", refreshToken.Value)

	err = bcrypt.CompareHashAndPassword([]byte(capturedSession.RefreshToken), []byte(refreshToken.Value))
	assert.NoError(t, err, "refresh token should match hashed value")

	mockSessionSaver.AssertCalled(t, "SaveSession", mock.AnythingOfType("models.Session"))
	assert.Equal(t, userID, capturedSession.UserID, "userID in session should match")
	assert.Equal(t, clientIP, capturedSession.ClientIP, "clientIP in session should match")
	assert.WithinDuration(t, time.Now().Add(refreshTokenTTL), capturedSession.RefreshTokenExp, time.Second, "refresh token expiration should match")
}