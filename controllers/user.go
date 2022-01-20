package controllers

// // https://techinscribed.com/different-approaches-to-pass-database-connection-into-controllers-in-golang/

import (
	// "context"
	// "database/sql"
	"context"
	"encoding/json"
	"log"

	"errors"
	// "fmt"
	// "log"
	"net/http"

	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/utils"

	// "strings"
	"time"
	// "github.com/go-chi/chi/v5"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"

	// "github.com/mailgun/mailgun-go/v4"
	"github.com/jackc/pgconn"
	"github.com/kibetrutoh/kibetgo/database"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	// "github.com/kibetrutoh/kibetgo/helpers"
	// "github.com/kibetrutoh/kibetgo/token"
	// "github.com/kibetrutoh/kibetgo/utils"
)

func (b *BaseHandler) HelloWorld(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to Easy Share / Team Share / Eazy Share!"))
}

// // struct to store request body
type verifyEmailRequest struct {
	EmailAddress string `json:"email_address"`
}

// // validate email address
func (c verifyEmailRequest) validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.EmailAddress, validation.Required, is.Email),
	)
}

func (b *BaseHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	// // set request header content-type to application json
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	// // get and store request body
	var req verifyEmailRequest
	reqBody := json.NewDecoder(r.Body)
	reqBody.DisallowUnknownFields()
	err := reqBody.Decode(&req)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "an error occured", 500)
		return
	}

	// // validate email
	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			return
		}
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "enter a valid email address", 400)
		return
	}

	// // generate verification code
	verificationCode, err := utils.GenerateOTP(6)
	if err != nil {
		log.Println(err.Error())
		w.Header().Set("content-type", "application/json")
		helpers.Response(w, "an error occured", 500)
		return
	}

	// // generate verification code expiry time
	verificationCodeExpiry := time.Now().UTC().Add(30 * time.Minute)

	// // init db
	db := database.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	// // add email & other details to db
	arg := sqlc.VerifyEmailParams{
		EmailAddress:              req.EmailAddress,
		VerificationCode:          verificationCode,
		VerificationCodeExpiresAt: verificationCodeExpiry,
	}

	email, err := q.VerifyEmail(context.Background(), arg)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			log.Println(err.Error())
			w.Header().Set("content-type", "application/json")
			helpers.Response(w, "an error occured", 500)
			return
		}
	}

	log.Println(email)
	// // send email to email with verification code
	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	sender := "team@organized.com"
	subject := "Welcome to Organized!"
	recipient := req.EmailAddress
	code := verificationCode

	mail, err := helpers.SendInvitationEmail(config.DOMAIN, config.MailgunAPIKey, sender, subject, recipient, code)
	if err != nil {
		log.Println(err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mail)
}

// type createUserRequest struct {
// 	FullName       string `json:"full_name"`
// 	EmailAddress   string `json:"email_address"`
// 	HashedPassword string `json:"password"`
// }

// func (c createUserRequest) validate() error {
// 	return validation.ValidateStruct(&c,
// 		validation.Field(&c.FullName, validation.Required, validation.Length(5, 500)),
// 		validation.Field(&c.EmailAddress, validation.Required, is.Email),
// 		validation.Field(&c.HashedPassword, validation.Required, validation.Length(6, 1000)),
// 	)
// }

// type userResponse struct {
// 	FullName     string `json:"full_name"`
// 	EmailAddress string `json:"email_address"`
// }

// func newUserResponse(user sqlc.User) userResponse {
// 	return userResponse{
// 		FullName:     user.FullName,
// 		EmailAddress: user.EmailAddress,
// 	}
// }

// func (h *BaseHandler) SignUp(w http.ResponseWriter, r *http.Request) {
// 	headerContentType := r.Header.Get("Content-Type")
// 	if headerContentType != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

// 	if err := h.db.Ping(); err != nil {
// 		log.Println(err)
// 	}
// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	var req createUserRequest

// 	data := json.NewDecoder(r.Body)
// 	data.DisallowUnknownFields()

// 	err := data.Decode(&req)
// 	if err != nil {
// 		log.Println(err)
// 	}

// 	err = req.validate()
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, err.Error(), 400)
// 		return
// 	}

// 	hashedPassword, err := utils.HashPassword(req.HashedPassword)
// 	if err != nil {
// 		log.Println(err)
// 	}

// 	eVerificationCode, err := utils.GenerateOTP(6)
// 	if err != nil {
// 		log.Println(err)
// 	}

// 	log.Println(eVerificationCode)

// 	config, err := utils.LoadConfig("/home/kibet/go/organized")
// 	if err != nil {
// 		log.Println(err)
// 	}

// 	mg := mailgun.NewMailgun(config.DOMAIN, config.MailgunAPIKey)

// 	sender := fmt.Sprintf("Eazy Share <mailgun@%s>", config.DOMAIN)
// 	subject := "[eazyshare.com] Verify your email to continue"
// 	recipient := req.EmailAddress
// 	body := fmt.Sprintf(`Hey %s, Please enter this code %s to continue.`, req.FullName, eVerificationCode)
// 	message := mg.NewMessage(sender, subject, body, recipient)

// 	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)

// 	defer cancel()

// 	response, id, err := mg.Send(ctx, message)

// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	log.Printf("ID: %s RES: %s\n", id, response)

// 	user_id, err := utils.UniqueID(6)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	arg := sqlc.CreateUserParams{
// 		UserID:                   user_id,
// 		FullName:                 req.FullName,
// 		EmailAddress:             req.EmailAddress,
// 		HashedPassword:           hashedPassword,
// 		VerificationCode:         eVerificationCode,
// 		VerificatonCodeExpiresAt: time.Now().UTC().Add(30 * time.Minute),
// 		CreatedAt:                time.Now().UTC(),
// 	}

// 	user, err := q.CreateUser(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			detail := pgErr.Message
// 			statusCode := http.StatusInternalServerError
// 			helpers.ErrorResponse(w, detail, statusCode)
// 			return
// 		}
// 	}

// 	res := newUserResponse(user)
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(res)
// }

// type verifyEmailRequest struct {
// 	VerificationCode string `json:"verification_code"`
// }

// type verifyEmailResponse struct {
// 	AccessToken  string `json:"access_token"`
// 	RefreshToken string `json:"refresh_token"`
// }

// func (h *BaseHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
// 	headerContentType := r.Header.Get("Content-Type")
// 	if headerContentType != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

// 	var req verifyEmailRequest

// 	body := json.NewDecoder(r.Body)
// 	body.DisallowUnknownFields()

// 	err := body.Decode(&req)
// 	if err != nil {
// 		helpers.ErrorResponse(w, "internal server error", 500)
// 		return
// 	}

// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	user, err := q.GetUserByVerificationCode(context.Background(), req.VerificationCode)
// 	if errors.Is(err, sql.ErrNoRows) {
// 		helpers.ErrorResponse(w, "invalid verification code", 401)
// 		return
// 	}

// 	if user.Active {
// 		helpers.ErrorResponse(w, "verification code has already been used", 409)
// 		return
// 	}

// 	if time.Now().UTC().After(user.VerificatonCodeExpiresAt) {
// 		err = q.DeleteUser(context.Background(), user.UserID)
// 		if err != nil {
// 			log.Println(err)
// 		}

// 		helpers.ErrorResponse(w, "verification code has expired", 401)
// 		return
// 	}

// 	err = q.UpdateActiveStatus(context.Background(), user.EmailAddress)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}
// 	accessToken, err := token.CreateAccessToken(user.EmailAddress)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "could not generate access token", 500)
// 		return
// 	}

// 	refresh_token, err := token.CreateRefreshToken(user.EmailAddress)
// 	if err != nil {
// 		helpers.ErrorResponse(w, "an error occured", 500)
// 		return
// 	}

// 	payload, err := token.VerifyRefreshToken(refresh_token)
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	arg := sqlc.UpdateRefreshTokenParams{
// 		UserID:         user.UserID,
// 		RefreshTokenID: payload.ID,
// 	}

// 	err = q.UpdateRefreshToken(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			helpers.ErrorResponse(w, pgErr.Message, 500)
// 			return
// 		}
// 	}

// 	res := verifyEmailResponse{
// 		AccessToken:  accessToken,
// 		RefreshToken: refresh_token,
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(res)
// }

// func (h *BaseHandler) ValidateUser(w http.ResponseWriter, r *http.Request) {
// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)
// 	log.Println(q)

// 	userEmail := chi.URLParam(r, "userEmail")
// 	eVerificationCode := chi.URLParam(r, "eVerificationCode")

// 	log.Println(eVerificationCode)

// 	user, err := q.GetUserByEmail(context.Background(), userEmail)

// 	switch {
// 	case errors.As(err, &sql.ErrNoRows):
// 		helpers.ErrorResponse(w, "user not found", 404)
// 		return
// 	case user.Active:
// 		helpers.ErrorResponse(w, "email address has already been verified", 409)
// 		return
// 	case time.Now().UTC().Before(user.VerificatonCodeExpiresAt):
// 		match := utils.CheckActivationCodeHash(eVerificationCode, user.VerificationCode)
// 		if !match {
// 			helpers.ErrorResponse(w, "wrong activation code", 401)
// 			return
// 		}

// 		err := q.UpdateActiveStatus(context.Background(), userEmail)
// 		if err != nil {
// 			var pgErr *pgconn.PgError
// 			if errors.As(err, &pgErr) {
// 				log.Println(pgErr.Message)
// 				helpers.ErrorResponse(w, "internal server error", 500)
// 				return
// 			}
// 		}

// 		helpers.SuccessResponse(w, "OK", 200)
// 		return
// 	case time.Now().After(user.VerificatonCodeExpiresAt):
// 		log.Println("code has expired")
// 	}
// }

// type loginUserRequest struct {
// 	EmailAddress string `json:"email_address"`
// 	Password     string `json:"password"`
// }

// func (l loginUserRequest) validate() error {
// 	return validation.ValidateStruct(&l,
// 		validation.Field(&l.EmailAddress, validation.Required, is.Email),
// 		validation.Field(&l.Password, validation.Required),
// 	)
// }

// type loginUserResponse struct {
// 	AccessToken  string `json:"access_token"`
// 	RefreshToken string `json:"refresh_token"`
// 	User        userResponse `json:"user"`
// }

// func (h *BaseHandler) Login(w http.ResponseWriter, r *http.Request) {
// 	headerContentType := r.Header.Get("Content-Type")
// 	if headerContentType != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

// 	db := database.ConnectDB()
// 	h = NewBaseHandler(db)
// 	q := sqlc.New(h.db)

// 	var req loginUserRequest

// 	reqdata := json.NewDecoder(r.Body)
// 	reqdata.DisallowUnknownFields()

// 	err := reqdata.Decode(&req)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "internal server error", 500)
// 		return
// 	}

// 	err = req.validate()
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), 422)
// 		return
// 	}

// 	user, err := q.GetUserByEmail(context.Background(), req.EmailAddress)
// 	switch {
// 	case errors.Is(err, sql.ErrNoRows):
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "user not found", 404)
// 		return
// 	}

// 	if !user.Active {
// 		helpers.ErrorResponse(w, "user not active", 401)
// 		return
// 	}

// 	match := utils.CheckPasswordHash(req.Password, user.HashedPassword)
// 	if !match {
// 		helpers.ErrorResponse(w, "invalid email or password", 401)
// 		return
// 	}

// 	accessToken, err := token.CreateAccessToken(user.EmailAddress)
// 	if err != nil {
// 		helpers.ErrorResponse(w, "could not generate access token", 500)
// 		return
// 	}

// 	refresh_token, err := token.CreateRefreshToken(user.EmailAddress)
// 	if err != nil {
// 		helpers.ErrorResponse(w, "an error occured", 500)
// 		return
// 	}

// 	payload, err := token.VerifyRefreshToken(refresh_token)
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	arg := sqlc.UpdateRefreshTokenParams{
// 		UserID:         user.UserID,
// 		RefreshTokenID: payload.ID,
// 	}

// 	err = q.UpdateRefreshToken(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			helpers.ErrorResponse(w, pgErr.Message, 500)
// 			return
// 		}
// 	}

// 	response := loginUserResponse{
// 		AccessToken:  accessToken,
// 		RefreshToken: refresh_token,
// 		//User:        newUserResponse(user),
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

// func (h *BaseHandler) Logout(w http.ResponseWriter, r *http.Request) {
// 	reqToken := r.Header.Get("Authorization")
// 	if reqToken == "" {
// 		helpers.ErrorResponse(w, "token not provided", 401)
// 		return
// 	}

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

// 	token_id := payload.ID

// 	err = q.BlacklistToken(context.Background(), token_id)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "internal server error", 500)
// 			return
// 		}
// 	}

// 	helpers.SuccessResponse(w, "logout successful", 200)
// }

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
