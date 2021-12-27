package controllers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

type invite_tenant_user struct {
	EmailAddress string `json:"email_address"`
}

func (h *BaseHandler) InviteTenantUser(w http.ResponseWriter, r *http.Request) {
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
		log.Println(err.Error())
		helpers.ErrorResponse(w, "token is invalid", 401)
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

	if err != nil {
		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	admin_email := payload.Email

	user, err := q.GetUserByEmail(context.Background(), admin_email)
	if errors.Is(err, sql.ErrNoRows) {
		log.Println(err.Error())
		helpers.ErrorResponse(w, "an error occured", 404)
		return
	}

	tenant, err := q.GetTenantByUsedID(context.Background(), user.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		log.Println(err.Error())
		helpers.ErrorResponse(w, "an error occured", 404)
		return
	}

	tenant_ID := tenant.TenantID
	tenant_subdomain := tenant.TenantName
	tsds := strings.ReplaceAll(tenant_subdomain, " ", "-")

	body := json.NewDecoder(r.Body)
	body.DisallowUnknownFields()

	var req invite_tenant_user
	err = body.Decode(&req)
	if err != nil {
		log.Println(err.Error())
		helpers.ErrorResponse(w, "an error occured", 500)
		return
	}

	invitation_token, err := uuid.NewRandom()
	if err != nil {
		log.Println(err.Error())
		helpers.ErrorResponse(w, "an error occured", 500)
		return
	}

	invitation_token_string := invitation_token.String()

	arg := sqlc.InviteTenantUserParams{
		ParentTenantID:  tenant_ID,
		EmailAddress:    req.EmailAddress,
		InvitationToken: invitation_token,
	}

	_, err = q.InviteTenantUser(context.Background(), arg)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		log.Println(err.Error())
		helpers.ErrorResponse(w, "an error occured", 500)
		return
	}

	accept_invite_url := fmt.Sprintf("http://localhost:5000/%v/accept-invitation/invitation-token/%v", strings.ToLower(tsds), invitation_token_string)

	log.Println(accept_invite_url)
	helpers.SuccessResponse(w, "user has been invited", 200)
}
