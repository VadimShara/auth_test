package service

import (
	"net/http/httptest"
	"testing"
	"time"
	"os"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/google/uuid"
	"github.com/VadimShara/auth-part/internal/models"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
)

type MockSessionGetter struct {
	mock.Mock
}

func (m *MockSessionGetter) GetSession(jti string) (models.Session, error) {
	args := m.Called(jti)
	if args.Get(0) == nil {
		return models.Session{}, args.Error(1)
	}
	return args.Get(0).(models.Session), args.Error(1)
}

type MockSessionDeleter struct {
	mock.Mock
}

func (m *MockSessionDeleter) DeleteSession(sessionID int) error {
	args := m.Called(sessionID)
	return args.Error(0)
}

type MockEmailSender struct{}

func (m *MockEmailSender) SendWarning(to, from, password, host string) error {
	return nil
}

func TestRefreshTokens(t *testing.T) {
	mockSessionGetter := new(MockSessionGetter)
	mockSessionDeleter := new(MockSessionDeleter)
	mockSessionSaver := new(MockSessionSaver)

	secret := "test_secret"
	accessTokenTTL := 15 * time.Minute
	refreshTokenTTL := 7 * 24 * time.Hour
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if logger == nil {
		t.Fatal("Logger is nil")
	}

	jti := uuid.New().String()
	userID := uuid.New()
	clientIP := "127.0.0.1"
	sessionID := 1
	refreshToken := "refresh_token"

	hashedRefreshToken, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

	session := models.Session{
		ID:             sessionID,
		UserID:         userID,
		AccessTokenJTI: jti,
		RefreshToken:   string(hashedRefreshToken),
		ClientIP:       clientIP,
	}

	accessTokenClaims := jwt.MapClaims{
		"jti": jti,
		"sub": userID.String(),
		"exp": time.Now().Add(accessTokenTTL).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, accessTokenClaims)
	accessTokenString, _ := accessToken.SignedString([]byte(secret))

	mockSessionGetter.On("GetSession", jti).Return(session, nil)
	mockSessionDeleter.On("DeleteSession", sessionID).Return(nil)
	mockSessionSaver.On("SaveSession", mock.Anything).Return(nil)

	service := NewService(
		logger,
		accessTokenTTL,
		refreshTokenTTL,
		secret,
		"test@example.com",
		"password",
		"smtp.example.com",
		mockSessionSaver,
		mockSessionDeleter,
		mockSessionGetter,
	)

	if service == nil {
		t.Fatal("Service is nil")
	}

	w := httptest.NewRecorder()

	err := service.RefreshTokens(w, accessTokenString, refreshToken, clientIP)

	assert.NoError(t, err)
	resp := w.Result()
	defer resp.Body.Close()

	cookies := resp.Cookies()
	assert.Len(t, cookies, 2)

	mockSessionGetter.AssertCalled(t, "GetSession", jti)
	mockSessionDeleter.AssertCalled(t, "DeleteSession", sessionID)
	mockSessionSaver.AssertCalled(t, "SaveSession", mock.Anything)
}