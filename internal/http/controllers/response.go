package controllers

import (
	"net/http"

	"github.com/go-chi/render"
	"github.com/kuromii5/auth-part/internal/models"
)

func RespondOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, models.Response{Status: models.StatusOK})
}

func RespondErr(w http.ResponseWriter, r *http.Request, msg string) {
	render.JSON(w, r, models.Response{
		Status:   models.StatusErr,
		ErrorMsg: msg,
	})
}
