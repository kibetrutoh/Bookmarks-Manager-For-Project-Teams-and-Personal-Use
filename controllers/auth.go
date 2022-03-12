package controllers

// https://techinscribed.com/different-approaches-to-pass-database-connection-into-controllers-in-golang/

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/utils"

	"time"
	// "github.com/go-chi/chi/v5"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/kibetrutoh/kibetgo/db/connection"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/token"
	"github.com/mssola/user_agent"
)

var (
	ErrInternalServerError = errors.New("something went wrong")
)

// SIGN UP
type emailVerificationCodeRequest struct {
	EmailAddress string `json:"email_address"`
}

func (e emailVerificationCodeRequest) validate() error {
	return validation.ValidateStruct(&e,
		validation.Field(&e.EmailAddress, validation.Required, is.Email),
	)
}

type emailVerificationCodeRequestResponse struct {
	EmailAddress     string `json:"email_address"`
	VerificationCode string `json:"confirmation_code"`
}

func newEmailVerificationCodeRequestResponse(email, verificatonCode string) *emailVerificationCodeRequestResponse {
	return &emailVerificationCodeRequestResponse{
		EmailAddress:     email,
		VerificationCode: verificatonCode,
	}
}

func (b *BaseHandler) RequestVerificationCode(w http.ResponseWriter, r *http.Request) {

	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	var req emailVerificationCodeRequest
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	err := rBody.Decode(&req)
	if err != nil {
		log.Println(err.Error())
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}

		helpers.Response(w, "enter a valid email address", 400)
		return
	}

	verificationCode := utils.GenerateOTP()

	stripHyphenFromVerificationCode := strings.Split(verificationCode, "-")

	stripSpaceFromVerificationCode := stripHyphenFromVerificationCode[0] + stripHyphenFromVerificationCode[1]

	hashedVerificationCode := utils.Hmac256Hash(stripSpaceFromVerificationCode)

	verificationCodeExpiry := time.Now().UTC().Add(15 * time.Minute)

	db := connection.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	arg := sqlc.InsertIntoSignUpEmailVerificationTableParams{
		EmailAddress:     req.EmailAddress,
		VerificationCode: hashedVerificationCode,
		Expiry:           verificationCodeExpiry,
	}

	if _, err = q.InsertIntoSignUpEmailVerificationTable(context.Background(), arg); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	sender := "Organized@organized.com"
	subject := "Welcome to Organized!"
	recipient := req.EmailAddress
	code := verificationCode

	if _, err = helpers.SendEmailVerificationCode(config.DOMAIN, config.MailgunAPIKey, sender, subject, recipient, code); err != nil {
		log.Println("error sending verification code email")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newEmailVerificationCodeRequestResponse(req.EmailAddress, verificationCode)

	helpers.JsonResponse(w, res)
}

// VERIFY EMAIL
type verifyEmailRequest struct {
	ConfirmationCode string `json:"confirmation_code"`
}

func (v verifyEmailRequest) validate() error {
	return validation.ValidateStruct(&v,
		validation.Field(&v.ConfirmationCode, validation.Required, validation.Length(6, 6)),
	)
}

type verifyEmailRequestResponse struct {
	SessionID          uuid.UUID `json:"session_id"`
	AccessToken        string    `json:"access_token"`
	RefreshRoken       string    `json:"refresh_token"`
	AccessTokenExpiry  time.Time `json:"access_token_expiry"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
}

func newConfirmEmailResponse(sessionID uuid.UUID, accessToken string, accessTokenExpiry time.Time, refreshToken string, refreshTokenExpiry time.Time) *verifyEmailRequestResponse {
	return &verifyEmailRequestResponse{
		SessionID:          sessionID,
		AccessToken:        accessToken,
		RefreshRoken:       refreshToken,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
	}
}

func (b *BaseHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	var req verifyEmailRequest
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	err := rBody.Decode(&req)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		helpers.Response(w, "enter a valid code", 400)
		return
	}

	db := connection.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	hashedVerificationCode := utils.Hmac256Hash(req.ConfirmationCode)

	signUpVerificationCode, err := q.GetSignupEmailVerificationCode(context.Background(), hashedVerificationCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			helpers.Response(w, "no email found", 401)
			return
		}
	}

	if time.Now().UTC().After(signUpVerificationCode.Expiry) {

		err := q.DeleteSignupEmailVerificationCode(context.Background(), signUpVerificationCode.VerificationCode)
		if err != nil {
			log.Println(err)
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}

		helpers.Response(w, "token has expired", 401)
		return
	}

	name := strings.Split(signUpVerificationCode.EmailAddress, "@")[0]

	user_agent := user_agent.New(r.UserAgent())

	os := user_agent.OS()

	agent := user_agent.UA()

	ip, err := utils.GetIP(r)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 500)
		return
	}

	browser, _ := user_agent.Browser()

	user_agent.Parse(r.UserAgent())

	if err != nil {
		log.Println("error occured when hashing password")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	createUser_arg := sqlc.InsertIntoUsersTableParams{
		FullName:      name,
		EmailAddress:  signUpVerificationCode.EmailAddress,
		ClientOs:      os,
		ClientAgent:   agent,
		ClientBrowser: browser,
	}

	user, err := q.InsertIntoUsersTable(context.Background(), createUser_arg)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	err = q.DeleteSignupEmailVerificationCode(context.Background(), signUpVerificationCode.VerificationCode)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	accessToken, accessTokenPayload, err := token.CreateToken(int(user.ID), time.Now().UTC().Add(config.Access_Token_Duration))
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	refreshToken, refreshTokenPayload, err := token.CreateToken(int(user.ID), time.Now().UTC().Add(config.Refresh_Token_Duration))
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	sessionID := refreshTokenPayload.ID

	args := sqlc.InsertIntoUserSessionTableParams{
		ID:           sessionID,
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ClientAgent:  agent,
		ClientIp:     ip,
		ClientOs:     os,
		ExpiresAt:    time.Now().UTC().Add(config.Refresh_Token_Duration),
	}

	if _, err := q.InsertIntoUserSessionTable(context.Background(), args); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newConfirmEmailResponse(sessionID, accessToken, accessTokenPayload.ExpiresAt, refreshToken, refreshTokenPayload.ExpiresAt)

	helpers.JsonResponse(w, res)
}

// REQUEST MAGIC CODE
type magicCodeRequest struct {
	EmailAddress string `json:"email_address"`
}

func (m magicCodeRequest) validate() error {
	return validation.ValidateStruct(&m,
		validation.Field(&m.EmailAddress, validation.Required, is.Email),
	)
}

type magicCodeRequestResponse struct {
	UserID       int32  `json:"user_id"`
	EmailAddress string `json:"email_address"`
	MagicCode    string `json:"confirmation_code"`
}

func newMagicCodeRequestResponse(userID int32, email, magicCode string) *magicCodeRequestResponse {
	return &magicCodeRequestResponse{
		UserID:       userID,
		EmailAddress: email,
		MagicCode:    magicCode,
	}
}

type emailNotRegisteredResponse struct {
	EmailID string `json:"email"`
}

func newEmailNotRegisteredResponse(emailID string) *emailNotRegisteredResponse {
	return &emailNotRegisteredResponse{
		EmailID: emailID,
	}
}

func (b *BaseHandler) RequestLoginMagicCode(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	var req magicCodeRequest
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	err := rBody.Decode(&req)
	if err != nil {
		log.Println(err.Error())
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		helpers.Response(w, "enter a valid email address", 400)
		return
	}

	connectDB := connection.ConnectDB()
	baseHandler := NewBaseHandler(connectDB)
	queries := sqlc.New(baseHandler.db)

	if _, err = queries.GetUserByEmail(context.Background(), req.EmailAddress); err != nil {
		if ok := errors.Is(err, sql.ErrNoRows); ok {
			log.Println("email is not registered yet")

			config, err := utils.LoadConfig("/home/kibet/go/organized")
			if err != nil {
				log.Println(err.Error())
			}

			sender := "Organized@organized.com"
			subject := "Welcome to Organized"
			recipient := req.EmailAddress

			emailID, err := helpers.SendEmailNotRegisteredEmail(config.DOMAIN, config.MailgunAPIKey, sender, recipient, subject)
			if err != nil {
				log.Println(err)
				helpers.Response(w, ErrInternalServerError.Error(), 500)
				return
			}

			res := newEmailNotRegisteredResponse(emailID)

			helpers.JsonResponse(w, res)
		}
	}

	// TODO -> check if user belongs to any dashboard

	userLoginMagicCodes, err := queries.GetAllUserLoginMagicCodes(context.Background(), req.EmailAddress)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	for _, userLoginMagicCode := range userLoginMagicCodes {

		deleteMagicCode_arg := sqlc.DeleteMagicCodeParams{
			Code:         userLoginMagicCode.Code,
			EmailAddress: userLoginMagicCode.EmailAddress,
		}

		if err := queries.DeleteMagicCode(context.Background(), deleteMagicCode_arg); err != nil {
			log.Println(err)
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	magicCode := utils.GenerateOTP()

	splitMagicCode := strings.Split(magicCode, "-")

	result := splitMagicCode[0] + splitMagicCode[1]

	hashedMagicCode := utils.Hmac256Hash(result)

	magicCodeExpiry := time.Now().UTC().Add(15 * time.Minute)

	user, err := queries.GetUserByEmail(context.Background(), req.EmailAddress)
	if err != nil {
		log.Println(err)
		helpers.Response(w, "no user with email found", 401)
		return
	}

	userID := user.ID

	arg := sqlc.CreateLoginMagicCodeParams{
		UserID:       userID,
		EmailAddress: req.EmailAddress,
		Code:         hashedMagicCode,
		CodeExpiry:   magicCodeExpiry,
	}

	_, err = queries.CreateLoginMagicCode(context.Background(), arg)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	sender := "Organized@organized.com"
	subject := "Welcome to Organized!"
	recipient := req.EmailAddress
	code := magicCode

	if _, err = helpers.SendEmailVerificationCode(config.DOMAIN, config.MailgunAPIKey, sender, subject, recipient, code); err != nil {
		log.Println(err.Error())
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newMagicCodeRequestResponse(userID, req.EmailAddress, magicCode)

	helpers.JsonResponse(w, res)
}

// VERIFY LOGIN MAGIC CODE
type verifyMagicCodeRequest struct {
	MagicCode string `json:"magic_code"`
}

func (v verifyMagicCodeRequest) validate() error {
	return validation.ValidateStruct(&v,
		validation.Field(&v.MagicCode, validation.Required, validation.Length(6, 6)),
	)
}

type verifyMagicCodeResponse struct {
	SessionID          uuid.UUID `json:"session_id"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token"`
	AccessTokenExpiry  time.Time `json:"access_token_expiry"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
}

func newVerifyMagicCodeResponse(sessionID uuid.UUID, accessToken string, accessTokenExpiry time.Time, refreshToken string, refreshTokenExpiry time.Time) *verifyMagicCodeResponse {
	return &verifyMagicCodeResponse{
		SessionID:          sessionID,
		AccessToken:        accessToken,
		RefreshToken:       refreshToken,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
	}
}

func (b *BaseHandler) VerifyMagicCode(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()
	var req verifyMagicCodeRequest
	err := rBody.Decode(&req)
	if err != nil {
		log.Println("error decoding request body")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		helpers.Response(w, "enter a valid magic code", 400)
		return
	}

	hashedMagicCode := utils.Hmac256Hash(req.MagicCode)

	db := connection.ConnectDB()
	b = NewBaseHandler(db)
	q := sqlc.New(b.db)

	loginMagicCode, err := q.GetMagicCode(context.Background(), hashedMagicCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Println(err)
			helpers.Response(w, "no logic magic code found", 401)
			return
		}
	}

	if time.Now().UTC().After(loginMagicCode.CodeExpiry) {
		helpers.Response(w, "magic code has expired", 401)
		return
	}

	// TODO: FIND AND REDIRECT USER TO THEIR APPROPRIATE DASHBOARD

	if _, err := q.GetUserById(context.Background(), loginMagicCode.UserID); err != nil {
		log.Println(err)
		if errors.Is(err, sql.ErrNoRows) {
			log.Println("no user found")
			helpers.Response(w, "no user found", 401)
			return
		}
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	userID := loginMagicCode.UserID

	user_sessions, err := q.GetAllSessionsForUser(context.Background(), userID)
	if err != nil {
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if len(user_sessions) > 0 {
		if err := q.DeleteAllSessionsForaUser(context.Background(), userID); err != nil {
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	newAccessToken, accessTokenPayload, err := token.CreateToken(int(userID), time.Now().UTC().Add(config.Access_Token_Duration))
	if err != nil {
		log.Println("error creating access token")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	newRefreshToken, refreshTokenPayload, err := token.CreateToken(int(userID), time.Now().UTC().Add(config.Refresh_Token_Duration))
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	sessionID := refreshTokenPayload.ID

	user_agent := user_agent.New(r.UserAgent())

	os := user_agent.OS()

	agent := user_agent.UA()

	ip, err := utils.GetIP(r)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 500)
		return
	}

	arg := sqlc.InsertIntoUserSessionTableParams{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: newRefreshToken,
		ClientAgent:  agent,
		ClientIp:     ip,
		ClientOs:     os,
		ExpiresAt:    time.Now().UTC().Add(config.Refresh_Token_Duration),
	}

	if _, err := q.InsertIntoUserSessionTable(context.Background(), arg); err != nil {
		log.Println("an error occured when creating refresh token")
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	deleteMagicCode_arg := sqlc.DeleteMagicCodeParams{
		Code:         loginMagicCode.Code,
		EmailAddress: loginMagicCode.EmailAddress,
	}

	if err := q.DeleteMagicCode(context.Background(), deleteMagicCode_arg); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newVerifyMagicCodeResponse(sessionID, newAccessToken, accessTokenPayload.ExpiresAt, newRefreshToken, refreshTokenPayload.ExpiresAt)

	helpers.JsonResponse(w, res)
}

// REFRESH TOKEN========================================================================//
type refreshTokenResponse struct {
	SessionID            uuid.UUID `json:"session_id"`
	AccessToken          string    `json:"access_token"`
	RefreshToken         string    `json:"refresh_token"`
	Access_Token_Expiry  time.Time `json:"access_token_expiry"`
	Refresh_Token_Expiry time.Time `json:"refresh_token_expiry"`
}

func newRefreshTokenResponse(sessionID uuid.UUID, newAccessToken string, accessTokenExpiry time.Time, newRefreshToken string, refreshTokenExpiry time.Time) *refreshTokenResponse {
	return &refreshTokenResponse{
		SessionID:            sessionID,
		AccessToken:          newAccessToken,
		RefreshToken:         newRefreshToken,
		Access_Token_Expiry:  accessTokenExpiry,
		Refresh_Token_Expiry: refreshTokenExpiry,
	}
}

func (b *BaseHandler) RequestNewAccessToken(w http.ResponseWriter, r *http.Request) {

	getAuthorizationHeader := r.Header.Get("Authorization")

	splitAuthHeader := strings.Split(getAuthorizationHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		helpers.Response(w, "improper bearer token format", 401)
		return
	}

	refreshTokenFromRequest := strings.TrimSpace(splitAuthHeader[1])

	refreshToken, err := token.VerifyToken(refreshTokenFromRequest)
	if err != nil {
		log.Println(err.Error())
		helpers.Response(w, err.Error(), 401)
		return
	}

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	userSession, err := queries.GetUserSessionByID(context.Background(), refreshToken.ID)
	if err != nil {
		if ok := errors.Is(err, sql.ErrNoRows); ok {
			helpers.Response(w, "user session with this token not found", 401)
			return
		}
	}

	if userSession.RefreshToken != refreshTokenFromRequest {
		err := fmt.Errorf("wrong token provided")
		helpers.Response(w, err.Error(), 401)
		return
	}

	if userSession.UserID != int32(refreshToken.UserID) {
		err := fmt.Errorf("wrong token provided")
		helpers.Response(w, err.Error(), 401)
		return
	}

	if time.Now().UTC().After(userSession.ExpiresAt) {
		if userSession.Active {
			if err := queries.UpdateOneActiveUserSessionToInactive(context.Background(), userSession.ID); err != nil {
				log.Println(err)
				helpers.Response(w, ErrInternalServerError.Error(), 500)
				return
			}
		}
		helpers.Response(w, "session with this token has expired", 401)
		return
	}

	if !userSession.Active {

		allSessionsForUser, err := queries.GetAllSessionsForUser(context.Background(), userSession.UserID)
		if err != nil {
			log.Println(err)
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}

		for _, eachSession := range allSessionsForUser {
			if err := queries.DeleteAllSessionsForaUser(context.Background(), eachSession.UserID); err != nil {
				log.Println()
				helpers.Response(w, ErrInternalServerError.Error(), 500)
				return
			}
		}

		err = fmt.Errorf("this token has been used hence no more active")
		helpers.Response(w, err.Error(), 401)
		return
	}

	if err := queries.UpdateActiveSessionsForUserToInactive(context.Background(), userSession.UserID); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	newAccessToken, accessTokenPayload, err := token.CreateToken(int(userSession.UserID), time.Now().UTC().Add(config.Access_Token_Duration))
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	newRefreshToken, refreshTokenPayload, err := token.CreateToken(int(userSession.UserID), time.Now().UTC().Add(config.Refresh_Token_Duration))
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	sessionID := refreshTokenPayload.ID

	user_agent := user_agent.New(r.UserAgent())

	os := user_agent.OS()

	agent := user_agent.UA()

	ip, err := utils.GetIP(r)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 500)
		return
	}

	arg := sqlc.InsertIntoUserSessionTableParams{
		ID:           sessionID,
		UserID:       userSession.UserID,
		RefreshToken: newRefreshToken,
		ClientAgent:  agent,
		ClientIp:     ip,
		ClientOs:     os,
		ExpiresAt:    time.Now().UTC().Add(config.Refresh_Token_Duration),
	}

	if _, err := queries.InsertIntoUserSessionTable(context.Background(), arg); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newRefreshTokenResponse(sessionID, newAccessToken, accessTokenPayload.ExpiresAt, newRefreshToken, refreshTokenPayload.ExpiresAt)

	helpers.JsonResponse(w, res)
}

func (b *BaseHandler) ManualLogout(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("logout"))
}
