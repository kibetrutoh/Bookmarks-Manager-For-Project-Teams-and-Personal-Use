package controllers

// https://techinscribed.com/different-approaches-to-pass-database-connection-into-controllers-in-golang/

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strings"

	"errors"
	"net/http"

	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/utils"

	"time"
	// "github.com/go-chi/chi/v5"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	"github.com/jackc/pgconn"
	"github.com/kibetrutoh/kibetgo/database"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/token"
)

var (
	ErrInvalidToken        = errors.New("invalid token")
	ErrNoToken             = errors.New("no token associated with this account")
	ErrInvalidRfreshToken  = errors.New("invalid refresh token")
	ErrInternalServerError = errors.New("something went wrong")
	ErrNoEmail             = errors.New("email not found")
	ErrExpiredToken        = errors.New("token has expired")
	ErrTokenRequired       = errors.New("token required")
	ErrAnErrOccured        = errors.New("an error occured")
	ErrInvalidCode         = errors.New("invalid magic code")
)

func (b *BaseHandler) HelloWorld(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to Easy Share / Team Share / Eazy Share!"))
}

type verifyEmailRequest struct {
	EmailAddress string `json:"email_address"`
}

func (c verifyEmailRequest) validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.EmailAddress, validation.Required, is.Email),
	)
}

type verifyEmailResponse struct {
	EmailAddress     string `json:"email_address"`
	VerificationCode string `json:"confirmation_code"`
}

func newVerifyEmailResponse(email sqlc.EmailVerification) (*verifyEmailResponse, error) {
	var err error
	return &verifyEmailResponse{
		EmailAddress:     email.EmailAddress,
		VerificationCode: email.VerificationCode,
	}, err
}

func (b *BaseHandler) SignUp(w http.ResponseWriter, r *http.Request) {

	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	var req verifyEmailRequest
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	err := rBody.Decode(&req)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrAnErrOccured.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "enter a valid email address", 400)
		return
	}

	verificationCode, err := utils.GenerateOTP(6)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	hashedVerificationCode := utils.Hash(verificationCode)

	verificationCodeExpiry := time.Now().UTC().Add(5 * time.Minute)

	db := database.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	arg := sqlc.VerifyEmailParams{
		EmailAddress:              req.EmailAddress,
		VerificationCode:          hashedVerificationCode,
		VerificationCodeExpiresAt: verificationCodeExpiry,
	}

	email, err := q.VerifyEmail(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(err.Error())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	sender := "Organized@organized.com"
	subject := "Welcome to Organized!"
	recipient := req.EmailAddress
	code := verificationCode

	_, err = helpers.SendInvitationEmail(config.DOMAIN, config.MailgunAPIKey, sender, subject, recipient, code)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res, err := newVerifyEmailResponse(email)
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

type confirmEmailRequest struct {
	ConfirmationCode string `json:"confirmation_code"`
}

func (c confirmEmailRequest) validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.ConfirmationCode, validation.Required, validation.Length(6, 6)),
	)
}

type confirmEmailResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshRoken string `json:"refresh_token"`
}

func newConfirmEmailResponse(accessToken, refreshToken string) (*confirmEmailResponse, error) {
	var err error
	return &confirmEmailResponse{
		AccessToken:  accessToken,
		RefreshRoken: refreshToken,
	}, err
}

func (b *BaseHandler) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	var req confirmEmailRequest
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	err := rBody.Decode(&req)
	if err != nil {
		log.Println(err)
		w.Header().Set("Content-Type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "enter a valid code", 400)
		return
	}

	db := database.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	hashedVerificationCode := utils.Hash(req.ConfirmationCode)

	email, err := q.GetEmailByVerificationCode(context.Background(), hashedVerificationCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrNoEmail.Error(), 401)
			return
		}
	}

	if time.Now().UTC().After(email.VerificationCodeExpiresAt) {

		err := q.DeleteEmail(context.Background(), email.VerificationCode)
		if err != nil {
			log.Println(err)
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}

		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrExpiredToken.Error(), 401)
		return
	}

	name := strings.Split(email.EmailAddress, "@")[0]

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	passwordString := []byte(config.PasswordString)
	hashedPassword, err := utils.HashPassword(string(passwordString))
	if err != nil {
		log.Println("error occured when hashing password")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	arg := sqlc.CreateUserParams{
		FullName:     name,
		EmailAddress: email.EmailAddress,
		Password:     hashedPassword,
	}

	user, err := q.CreateUser(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, pgErr.Error(), 500)
			return
		}
	}

	err = q.DeleteEmail(context.Background(), email.VerificationCode)
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	accessToken, err := token.CreateAccessToken(int(user.ID))
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	accessTokenPayload, err := token.VerifyAccessToken(accessToken)
	if err != nil {
		log.Println("error decoding access token")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	refreshToken, err := token.CreateRefreshToken(int(user.ID))
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	refreshTokenPayload, err := token.VerifyRefreshToken(refreshToken)
	if err != nil {
		log.Println("error decoding refresh token")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res, err := newConfirmEmailResponse(accessToken, refreshToken)
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	arg2 := sqlc.CreateTokenPairParams{
		UserID:         user.ID,
		AccessTokenID:  accessTokenPayload.ID,
		RefreshTokenID: refreshTokenPayload.ID,
	}

	_, err = q.CreateTokenPair(context.Background(), arg2)
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

type loginRequest struct {
	EmailAddress string `json:"email_address"`
}

func (lr loginRequest) validate() error {
	return validation.ValidateStruct(&lr,
		validation.Field(&lr.EmailAddress, validation.Required, is.Email),
	)
}

type loginRequestResponse struct {
	EmailAddress string `json:"email_address"`
	MagicCode    string `json:"confirmation_code"`
}

func newLoginRequestResponse(loginMagicCode sqlc.LoginMagicCode) (*loginRequestResponse, error) {
	var err error
	return &loginRequestResponse{
		EmailAddress: loginMagicCode.EmailAddress,
		MagicCode:    loginMagicCode.MagicCode,
	}, err
}

func (b *BaseHandler) LoginRequest(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	var req loginRequest
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	err := rBody.Decode(&req)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrAnErrOccured.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "enter a valid email address", 400)
		return
	}

	magicCode, err := utils.GenerateOTP(6)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	hashedMagicCode := utils.Hash(magicCode)

	magicCodeExpiry := time.Now().UTC().Add(1 * time.Minute)

	db := database.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	arg := sqlc.LoginMagicCodeParams{
		EmailAddress:    req.EmailAddress,
		MagicCode:       hashedMagicCode,
		MagicCodeExpiry: magicCodeExpiry,
	}

	loginMagicCode, err := q.LoginMagicCode(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(err.Error())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	sender := "Organized@organized.com"
	subject := "Welcome to Organized!"
	recipient := req.EmailAddress
	code := magicCode

	_, err = helpers.SendInvitationEmail(config.DOMAIN, config.MailgunAPIKey, sender, subject, recipient, code)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res, err := newLoginRequestResponse(loginMagicCode)
	if err != nil {
		log.Println(err)
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

type loginR struct {
	MagicCode string `json:"magic_code"`
}

func (mc loginR) validate() error {
	return validation.ValidateStruct(&mc,
		validation.Field(&mc.MagicCode, validation.Required, validation.Length(6, 6)),
	)
}

type loginResponse struct {
	AccessTokenID  string `json:"access_token"`
	RefreshTokenID string `json:"refresh_token"`
}

func newLoginResponse(tokenPair sqlc.TokenPair) *loginResponse {
	return &loginResponse{
		AccessTokenID:  tokenPair.AccessTokenID.String(),
		RefreshTokenID: tokenPair.AccessTokenID.String(),
	}
}

func (b *BaseHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	var req loginR
	err := rBody.Decode(&req)
	if err != nil {
		log.Println("error decoding request body")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrAnErrOccured.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "enter a valid magic code", 400)
		return
	}

	hashedMagicCode := utils.Hash(req.MagicCode)

	db := database.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	magicCode, err := q.GetMagicCode(context.Background(), hashedMagicCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println(err)
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInvalidCode.Error(), 401)
			return
		}
	}

	if time.Now().UTC().After(magicCode.MagicCodeExpiry) {
		log.Println("magic code has expired")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "magic code has expired", 401)
		return
	}

	user, err := q.GetUserByEmail(context.Background(), magicCode.EmailAddress)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Message)
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	// TODO: find the dashboard a user belongs to

	accessToken, err := token.CreateAccessToken(int(user.ID))
	if err != nil {
		log.Println("error creating access token")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	accessTokenPayload, err := token.VerifyAccessToken(accessToken)
	if err != nil {
		log.Println("error occured when verifying access token")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	refreshToken, err := token.CreateRefreshToken(int(user.ID))
	if err != nil {
		log.Println("an error occured when generating refresh token")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	refreshTokenPayload, err := token.VerifyRefreshToken(refreshToken)
	if err != nil {
		log.Println("an error occured while verifying refresh token")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	arg := sqlc.CreateTokenPairParams{
		UserID:         user.ID,
		AccessTokenID:  accessTokenPayload.ID,
		RefreshTokenID: refreshTokenPayload.ID,
	}

	tokenPair, err := q.CreateTokenPair(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(pgErr.Message)
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	err = q.DeleteMagicCode(context.Background(), magicCode.MagicCode)
	if err != nil {
		log.Println("an error occured when deleting magic code")
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newLoginResponse(tokenPair)

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// func (h *BaseHandler) GetUser(w http.ResponseWriter, r *http.Request) {
// 	reqToken := r.Header.Get("Authorization")

// 	splitToken := strings.Split(reqToken, "Bearer")

// 	if len(splitToken) != 2 {
// 		log.Println("Error: Bearer token not in proper format")
// 	}

// 	reqToken = strings.TrimSpace(splitToken[1])

// 	payload, err := token.VerifyAccessToken(reqToken)

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is expired", 401)
// 		return
// 	}

// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	for _, blackblacklisted_token := range blacklisted_tokens {
// 		if payload.ID == blackblacklisted_token {
// 			helpers.ErrorResponse(w, "token is blacklisted", 401)
// 			return
// 		}
// 	}

// 	id := chi.URLParam(r, "id")

// 	user, err := q.GetUser(context.Background(), id)
// 	switch {
// 	case errors.Is(err, sql.ErrNoRows):
// 		helpers.ErrorResponse(w, "user not found", 404)
// 		return
// 	}

// 	resp := newUserResponse(user)

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(resp)
// }

// type updateUserRequest struct {
// 	FullName       string `json:"full_name"`
// 	EmailAddress   string `json:"email_address"`
// 	HashedPassword string `json:"hashed_password"`
// }

// func (u updateUserRequest) validate() error {
// 	return validation.ValidateStruct(&u,
// 		validation.Field(&u.FullName, validation.Required, validation.Length(5, 500)),
// 		validation.Field(&u.EmailAddress, validation.Required, is.Email),
// 		validation.Field(&u.HashedPassword, validation.Required, validation.Length(6, 1000)),
// 	)
// }

// func (h *BaseHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
// 	headerContentType := r.Header.Get("Content-Type")
// 	if headerContentType != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	reqToken := r.Header.Get("Authorization")

// 	splitToken := strings.Split(reqToken, "Bearer")

// 	if len(splitToken) != 2 {
// 		log.Println("Error: Bearer token not in proper format")
// 	}

// 	reqToken = strings.TrimSpace(splitToken[1])

// 	payload, err := token.VerifyAccessToken(reqToken)
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is invalid", 401)
// 		return
// 	}

// 	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	for _, blacklisted_token := range blacklisted_tokens {
// 		if payload.ID == blacklisted_token {
// 			helpers.ErrorResponse(w, "token is blacklisted", 401)
// 			return
// 		}
// 	}

// 	id := chi.URLParam(r, "id")

// 	_, err = q.GetUser(context.Background(), id)
// 	switch {
// 	case errors.Is(err, sql.ErrNoRows):
// 		helpers.ErrorResponse(w, "user not found", 404)
// 		return
// 	}

// 	var req updateUserRequest

// 	data := json.NewDecoder(r.Body)
// 	data.DisallowUnknownFields()

// 	err = data.Decode(&req)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	err = req.validate()
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), 422)
// 		return
// 	}

// 	hashedPassword, err := utils.HashPassword(req.HashedPassword)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	arg := sqlc.UpdateUserParams{
// 		UserID:         id,
// 		FullName:       req.FullName,
// 		EmailAddress:   req.EmailAddress,
// 		HashedPassword: hashedPassword,
// 	}

// 	_, err = q.UpdateUser(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	helpers.SuccessResponse(w, "OK", 200)
// }

// func (h *BaseHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
// 	reqToken := r.Header.Get("Authorization")

// 	splitToken := strings.Split(reqToken, "Bearer")

// 	if len(splitToken) != 2 {
// 		log.Println("Error: Bearer token not in proper format")
// 	}

// 	reqToken = strings.TrimSpace(splitToken[1])

// 	payload, err := token.VerifyAccessToken(reqToken)

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is invalid", 401)
// 		return
// 	}

// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	for _, blackblacklisted_token := range blacklisted_tokens {
// 		if payload.ID == blackblacklisted_token {
// 			helpers.ErrorResponse(w, "token is blacklisted", 401)
// 			return
// 		}
// 	}

// 	id := chi.URLParam(r, "id")

// 	_, err = q.GetUser(context.Background(), id)
// 	switch {
// 	case errors.Is(err, sql.ErrNoRows):
// 		helpers.ErrorResponse(w, "user not found", 404)
// 		return
// 	}

// 	err = q.DeleteUser(context.Background(), id)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	helpers.SuccessResponse(w, "OK", 200)
// }

// func (h *BaseHandler) AllUsers(w http.ResponseWriter, r *http.Request) {
// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	reqToken := r.Header.Get("Authorization")

// 	splitToken := strings.Split(reqToken, "Bearer")

// 	if len(splitToken) != 2 {
// 		log.Println("Error: Bearer token not in proper format")
// 	}

// 	reqToken = strings.TrimSpace(splitToken[1])

// 	payload, err := token.VerifyAccessToken(reqToken)

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is invalid", 401)
// 		return
// 	}

// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	for _, blackblacklisted_token := range blacklisted_tokens {
// 		if payload.ID == blackblacklisted_token {
// 			helpers.ErrorResponse(w, "token is blacklisted", 401)
// 			return
// 		}
// 	}

// 	users, err := q.ListUsers(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(users)
// }
