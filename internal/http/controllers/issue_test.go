package controllers

import (
	"bytes"
	"net/http"
	"testing"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"log/slog"
	"net/http/httptest"
)

type MockTokenIssuer struct {
	mock.Mock
}

func (m *MockTokenIssuer) IssueTokens(w http.ResponseWriter, userID uuid.UUID, clientIP string) error {
	args := m.Called(w, userID, clientIP)
	return args.Error(0)
}

func TestIssueTokens(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	mockTokenIssuer := new(MockTokenIssuer)
	mockTokenIssuer.On("IssueTokens", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	handler := IssueTokens(logger, mockTokenIssuer)

	req, err := http.NewRequest(http.MethodGet, "/tokens?user_id="+uuid.New().String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	assert.Contains(t, buf.String(), "Issuing tokens for user")

	mockTokenIssuer.AssertExpectations(t)
}