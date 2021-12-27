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

	"github.com/go-chi/chi/v5"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/kibetrutoh/kibetgo/database"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/token"
)

type createTenantRequest struct {
	TenantName  string `json:"tenant_name"`
	ProjectName string `json:"project_name"`
}

func (c createTenantRequest) validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.TenantName, validation.Required, validation.Length(5, 500)),
		validation.Field(&c.ProjectName, validation.Required),
	)
}

type createTenantResponse struct {
	TenantName  string    `json:"tenant_name"`
	ProjectName string    `json:"project_name"`
	UserID      uuid.UUID `json:"user_id"`
}

func newCreateTenantResponse(tenant sqlc.Tenant) createTenantResponse {
	return createTenantResponse{
		TenantName:  tenant.TenantName,
		ProjectName: tenant.ProjectName,
		UserID:      tenant.UserID,
	}
}

func (h *BaseHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.Header().Set("Content-Type", "application/json")
	}

	reqToken := r.Header.Get("Authorization")
	if reqToken == "" {
		helpers.ErrorResponse(w, "token not provided", 401)
		return
	}

	splitToken := strings.Split(reqToken, "Bearer")

	if len(splitToken) != 2 {
		log.Println("Error: Bearer token not in proper format")
	}

	reqToken = strings.TrimSpace(splitToken[1])

	payload, err := token.VerifyAccessToken(reqToken)
	if err != nil {
		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if time.Now().UTC().After(payload.ExpiresAt) {
		helpers.ErrorResponse(w, "token is expired", 401)
		return
	}

	db := database.ConnectDB()
	h = NewBaseHandler(db)
	q := sqlc.New(h.db)

	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Message)
			helpers.ErrorResponse(w, "internal server error", 500)
			return
		}
	}

	for _, blackblacklisted_token := range blacklisted_tokens {
		if payload.ID == blackblacklisted_token {
			helpers.ErrorResponse(w, "token is blacklisted", 401)
			return
		}
	}

	uEmail := payload.Email

	data := json.NewDecoder(r.Body)
	data.DisallowUnknownFields()

	var req createTenantRequest

	err = data.Decode(&req)
	if err != nil {
		log.Println(err)
		helpers.ErrorResponse(w, "internal server error", 500)
		return
	}

	err = req.validate()
	if err != nil {
		log.Println(err.Error())
		helpers.ErrorResponse(w, err.Error(), 400)
		return
	}

	user, _ := q.GetUserByEmail(context.Background(), uEmail)

	tenant, err := q.CreateTenant(context.Background(), sqlc.CreateTenantParams{TenantName: req.TenantName, ProjectName: req.ProjectName, UserID: user.UserID})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Message)
			helpers.ErrorResponse(w, "internal server error", 500)
			return
		}
	}

	resp := newCreateTenantResponse(tenant)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

type updateTenantRequest struct {
	TenantName  string `json:"tenant_name"`
	ProjectName string `json:"project_name"`
}

type updateTenantResponse struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	TenantName  string    `json:"tenant_name"`
	ProjectName string    `json:"project_name"`
}

func newUpdateTenantResponse(tenant sqlc.Tenant) updateTenantResponse {
	return updateTenantResponse{
		TenantID:    tenant.TenantID,
		TenantName:  tenant.TenantName,
		ProjectName: tenant.ProjectName,
	}
}

func (u updateTenantRequest) validate() error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.TenantName, validation.Required, validation.Length(5, 500)),
		validation.Field(&u.ProjectName, validation.Required),
	)
}

func (h *BaseHandler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.Header().Set("Content-Type", "application/json")
	}

	reqToken := r.Header.Get("Authorization")

	splitToken := strings.Split(reqToken, "Bearer")

	if len(splitToken) != 2 {
		log.Println("Error: Bearer token not in proper format")
	}

	reqToken = strings.TrimSpace(splitToken[1])

	payload, err := token.VerifyAccessToken(reqToken)
	if err != nil {
		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	if time.Now().UTC().After(payload.ExpiresAt) {
		helpers.ErrorResponse(w, "token is invalid", 401)
		return
	}

	db := database.ConnectDB()
	h = NewBaseHandler(db)
	q := sqlc.New(h.db)

	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Message)
			helpers.ErrorResponse(w, "internal server error", 500)
			return
		}
	}

	for _, blackblacklisted_token := range blacklisted_tokens {
		if payload.ID == blackblacklisted_token {
			helpers.ErrorResponse(w, "token is blacklisted", 401)
			return
		}
	}

	uid := chi.URLParam(r, "uuid")

	uuid, err := uuid.Parse(uid)
	if err != nil {
		panic(err)
	}

	var req updateTenantRequest

	body := json.NewDecoder(r.Body)
	body.DisallowUnknownFields()

	err = body.Decode(&req)
	if err != nil {
		helpers.ErrorResponse(w, "internal server error", 500)
		return
	}

	err = req.validate()
	if err != nil {
		helpers.ErrorResponse(w, err.Error(), 422)
		return
	}

	tenant, err := q.GetTenant(context.Background(), uuid)
	switch {
	case errors.As(err, &sql.ErrNoRows):
		helpers.ErrorResponse(w, "tenant not found", 404)
		return
	}

	arg := sqlc.UpdateTenantParams{
		TenantID:    tenant.TenantID,
		TenantName:  req.TenantName,
		ProjectName: req.ProjectName,
	}

	tenant, err = q.UpdateTenant(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Message)
			helpers.ErrorResponse(w, "internal server error", 500)
			return
		}
	}

	resp := newUpdateTenantResponse(tenant)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
