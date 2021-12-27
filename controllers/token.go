package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/kibetrutoh/kibetgo/database"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/token"
)

type refreshTokenResponse struct {
	Access_Token  string `json:"access_token"`
	Refresh_Token string `json:"refresh_token"`
}

func (h *BaseHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	req_token := r.Header.Get("refresh-token")
	if req_token == "" {
		helpers.ErrorResponse(w, "refresh token required", 401)
		return
	}

	payload, err := token.VerifyRefreshToken(req_token)
	if err != nil {
		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	db := database.ConnectDB()
	h = NewBaseHandler(db)
	q := sqlc.New(h.db)

	user, err := q.GetUserByEmail(context.Background(), payload.Email)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		helpers.ErrorResponse(w, "token is invalid", 404)
		return
	}

	if user.RefreshTokenID != payload.ID {
		random_token_id, err := uuid.NewRandom()
		if err != nil {
			helpers.ErrorResponse(w, "error generating random uuid", 500)
			return
		}

		arg := sqlc.UpdateRefreshTokenParams{
			UserID:         user.UserID,
			RefreshTokenID: random_token_id,
		}

		err = q.UpdateRefreshToken(context.Background(), arg)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				helpers.ErrorResponse(w, pgErr.Message, 500)
				return
			}
		}

		reqToken := r.Header.Get("Authorization")

		splitToken := strings.Split(reqToken, "Bearer")

		if len(splitToken) != 2 {
			log.Println("Error: Bearer token not in proper format")
		}

		reqToken = strings.TrimSpace(splitToken[1])

		payload, err := token.VerifyAccessToken(reqToken)
		if err != nil {
			helpers.ErrorResponse(w, err.Error(), 500)
			return
		}

		if time.Now().UTC().Before(payload.ExpiresAt) {
			err = q.BlacklistToken(context.Background(), payload.ID)
			if err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					helpers.ErrorResponse(w, pgErr.Message, 500)
					return
				}
			}
		}

		helpers.ErrorResponse(w, "token is invalid", 401)
		return
	}

	access_token, err := token.CreateAccessToken(payload.Email)
	if err != nil {
		helpers.ErrorResponse(w, "error issuing new acces token", 500)
		return
	}

	refresh_token, err := token.CreateRefreshToken(payload.Email)
	if err != nil {
		helpers.ErrorResponse(w, "error issuing new refresh token", 500)
		return
	}

	reqToken := r.Header.Get("Authorization")

	splitToken := strings.Split(reqToken, "Bearer")

	if len(splitToken) != 2 {
		log.Println("Error: Bearer token not in proper format")
	}

	reqToken = strings.TrimSpace(splitToken[1])

	payload, err = token.VerifyAccessToken(reqToken)
	if err != nil {
		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if time.Now().UTC().Before(payload.ExpiresAt) {
		err = q.BlacklistToken(context.Background(), payload.ID)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				helpers.ErrorResponse(w, pgErr.Message, 500)
				return
			}
		}
	}

	payload, err = token.VerifyRefreshToken(refresh_token)
	if err != nil {
		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	arg := sqlc.UpdateRefreshTokenParams{
		UserID:         user.UserID,
		RefreshTokenID: payload.ID,
	}

	err = q.UpdateRefreshToken(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			helpers.ErrorResponse(w, pgErr.Message, 500)
			return
		}
	}

	res := refreshTokenResponse{
		Access_Token:  access_token,
		Refresh_Token: refresh_token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
