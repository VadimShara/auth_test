package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRespondOK(t *testing.T) {
	rr := httptest.NewRecorder()

	req, err := http.NewRequest(http.MethodGet, "/ok", nil)
	if err != nil {
		t.Fatal(err)
	}

	RespondOK(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	expected := `{"status":"OK"}`
	assert.JSONEq(t, expected, rr.Body.String())
}

func TestRespondErr(t *testing.T) {
	rr := httptest.NewRecorder()

	req, err := http.NewRequest(http.MethodGet, "/err", nil)
	if err != nil {
		t.Fatal(err)
	}

	errorMessage := "Something went wrong"

	RespondErr(rr, req, errorMessage)

	assert.Equal(t, http.StatusOK, rr.Code)

	expected := `{"status":"Error","error":"Something went wrong"}`
	assert.JSONEq(t, expected, rr.Body.String())
}