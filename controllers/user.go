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

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
	"github.com/kibetrutoh/kibetgo/db/connection"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/token"
	"github.com/kibetrutoh/kibetgo/utils"
	"github.com/mssola/user_agent"
)

// GET USER

type getUserResponse struct {
	Fullname     string `json:"fullname"`
	EmailAddress string `json:"email_address"`
}

func newGetUserResponse(user sqlc.User) *getUserResponse {
	return &getUserResponse{
		Fullname:     user.FullName,
		EmailAddress: user.EmailAddress,
	}
}

func (b *BaseHandler) GetUser(w http.ResponseWriter, r *http.Request) {

	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		err := fmt.Errorf("improper token format")
		helpers.Response(w, err.Error(), 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	user, err := queries.GetUser(context.Background(), int32(tokenPayload.UserID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = fmt.Errorf("user with id not found")
			helpers.Response(w, err.Error(), 401)
			return
		}
	}

	res := newGetUserResponse(user)

	helpers.JsonResponse(w, res)
}

// UPDATE FULL NAME
type updateNameRequest struct {
	Name string `json:"name"`
}

func (u updateNameRequest) validate() error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.Name, validation.Required, validation.Min(5)),
	)
}

type updateNameResponse struct {
	Name string `json:"name"`
}

func newUpdateNameResponse(name string) *updateNameResponse {
	return &updateNameResponse{
		Name: name,
	}
}

func (b *BaseHandler) UpdateName(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		err := fmt.Errorf("improper token format")
		helpers.Response(w, err.Error(), 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()

	var req updateNameRequest

	err = rBody.Decode(&req)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	err = req.validate()
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	arg := sqlc.UpdateUserFullNameParams{
		ID:       int32(tokenPayload.UserID),
		FullName: req.Name,
	}

	user, err := queries.UpdateUserFullName(context.Background(), arg)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newUpdateNameResponse(user.FullName)

	helpers.JsonResponse(w, res)
}

// UPDATE EMAIL
type updateEmailRequest struct {
	EmailAddress string `json:"email_address"`
}

func (u updateEmailRequest) validate() error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.EmailAddress, validation.Required, is.Email),
	)
}

type sendEmail struct {
	Domain    string
	APIKey    string
	Sender    string
	Recipient string
	Subject   string
	Code      string
}

func newSendEmail(domain, apiKey, sender, recipient, subject, code string) *sendEmail {
	return &sendEmail{
		Domain:    domain,
		APIKey:    apiKey,
		Recipient: recipient,
		Sender:    sender,
		Subject:   subject,
		Code:      code,
	}
}

func (b *BaseHandler) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		err := fmt.Errorf("improper token format")
		helpers.Response(w, err.Error(), 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()

	var req updateEmailRequest

	err = rBody.Decode(&req)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	err = req.validate()
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	verificationCode := utils.GenerateOTP()

	stripDashFromCode := strings.Split(verificationCode, "-")

	stripSpace := stripDashFromCode[0] + stripDashFromCode[1]

	hashCode := utils.Hmac256Hash(stripSpace)

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	sender := "team@organized.com"
	recipient := req.EmailAddress
	subject := "Verify Your New Email"
	code := verificationCode

	newEmail := newSendEmail(config.DOMAIN, config.MailgunAPIKey, sender, recipient, subject, code)

	if _, err := helpers.Send_ChangeEmail_Email(newEmail.Domain, newEmail.APIKey, newEmail.Sender, newEmail.Recipient, newEmail.Subject, newEmail.Code); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	expiry := time.Now().UTC().Add(30 * time.Minute)

	arg := sqlc.CreateChangeEmailCodeParams{
		UserID:       int32(tokenPayload.UserID),
		Code:         hashCode,
		EmailAddress: req.EmailAddress,
		Expiry:       expiry,
	}

	if _, err := queries.CreateChangeEmailCode(context.Background(), arg); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	helpers.Response(w, "verification code had been sent to your email", 200)
}

type verifyChangeEmailRequest struct {
	Code string `json:"code"`
}

func (v verifyChangeEmailRequest) validate() error {
	return validation.ValidateStruct(&v,
		validation.Field(&v.Code, validation.Required, validation.Length(6, 6)),
	)
}

type changeEmailResponse struct {
	EmailAddress       string    `json:"email_address"`
	SessionID          uuid.UUID `json:"session_id"`
	AccessToken        string    `json:"access_token"`
	RefreshRoken       string    `json:"refresh_token"`
	AccessTokenExpiry  time.Time `json:"access_token_expiry"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
}

func newChangeEmailResponse(sessionID uuid.UUID, emailAddress, accessToken, refreshToken string, accessTokenExpiry, refreshTokenExpiry time.Time) *changeEmailResponse {
	return &changeEmailResponse{
		EmailAddress:       emailAddress,
		SessionID:          sessionID,
		AccessToken:        accessToken,
		RefreshRoken:       refreshToken,
		AccessTokenExpiry:  accessTokenExpiry,
		RefreshTokenExpiry: refreshTokenExpiry,
	}
}

func (b *BaseHandler) VerifyChangeEmailCode(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}

	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		err := fmt.Errorf("improper token format")
		helpers.Response(w, err.Error(), 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()

	var req verifyChangeEmailRequest

	if err := rBody.Decode(&req); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := req.validate(); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	hashCode := utils.Hmac256Hash(req.Code)

	dbCode, err := queries.GetChangeEmailCode(context.Background(), hashCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err := fmt.Errorf("invalid code")
			helpers.Response(w, err.Error(), 401)
			return
		}

		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if time.Now().UTC().After(dbCode.Expiry) {
		if err := queries.DeleteChangeEmailCode(context.Background(), dbCode.Code); err != nil {
			log.Println(err)
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}

		err := fmt.Errorf("code has expired")
		helpers.Response(w, err.Error(), 401)
		return
	}

	if tokenPayload.UserID != int(dbCode.UserID) {
		err := fmt.Errorf(`users don't match`)
		helpers.Response(w, err.Error(), 401)
		return
	}

	updateUserEmail_arg := sqlc.UpdateUserEmailParams{
		ID:           dbCode.UserID,
		EmailAddress: dbCode.EmailAddress,
	}

	user, err := queries.UpdateUserEmail(context.Background(), updateUserEmail_arg)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if err := queries.DeleteChangeEmailCode(context.Background(), dbCode.Code); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	userSessions, err := queries.GetAllSessionsForUser(context.Background(), user.ID)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	for _, userSession := range userSessions {
		if userSession.Active {
			if err := queries.UpdateOneActiveUserSessionToInactive(context.Background(), userSession.ID); err != nil {
				log.Println(err)
				helpers.Response(w, ErrInternalServerError.Error(), 500)
				return
			}
		}
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

	user_agent := user_agent.New(r.UserAgent())

	os := user_agent.OS()

	agent := user_agent.UA()

	ip, err := utils.GetIP(r)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 500)
		return
	}

	createUserSession_arg := sqlc.CreateUserSessionParams{
		ID:           sessionID,
		UserID:       user.ID,
		RefreshToken: refreshToken,
		ClientAgent:  agent,
		ClientIp:     ip,
		ClientOs:     os,
		ExpiresAt:    time.Now().UTC().Add(config.Refresh_Token_Duration),
	}

	if _, err := queries.CreateUserSession(context.Background(), createUserSession_arg); err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	res := newChangeEmailResponse(createUserSession_arg.ID, user.EmailAddress, accessToken, refreshToken, accessTokenPayload.ExpiresAt, refreshTokenPayload.ExpiresAt)

	helpers.JsonResponse(w, res)
}

// UPDATE PASSWORD
func (b *BaseHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("update password"))
}

// UPDATE TIMEZONE
func (b *BaseHandler) UpdateTimezone(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("update timezone"))
}

// DELETE ACCOUNT
func (b *BaseHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		err := fmt.Errorf("improper token format")
		helpers.Response(w, err.Error(), 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	userID := tokenPayload.UserID

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	users, err := queries.GetAllUsers(context.Background())
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if len(users) > 0 {
		for _, user := range users {
			if user.ID == int32(userID) {
				thisUser := user
				if thisUser.Role != "User" {
					res := "admins are not authorized to access this route"
					helpers.Response(w, res, 402)
					return
				}
				userID = int(thisUser.ID)
				if err := queries.DeleteUserAccount(context.Background(), user.ID); err != nil {
					log.Println(err)
					helpers.Response(w, ErrInternalServerError.Error(), 500)
					return
				}
				res := fmt.Sprintf("account id :%d deleted successfully", userID)
				helpers.Response(w, res, 200)
				return
			} else {
				res := "user not found"
				helpers.Response(w, res, 401)
				return
			}
		}
	} else {
		res := "user not found"
		helpers.Response(w, res, 401)
		return
	}
}

// GET USERS
type getUsersResponse struct {
	UserID       int32  `json:"user_id"`
	EmailAddress string `json:"email_address"`
}

func newGetUsersResponse(user sqlc.User) *getUsersResponse {
	return &getUsersResponse{
		UserID:       user.ID,
		EmailAddress: user.EmailAddress,
	}
}

func (b *BaseHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		err := fmt.Errorf("improper token format")
		helpers.Response(w, err.Error(), 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	userID := tokenPayload.UserID

	user, err := queries.GetUser(context.Background(), int32(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			res := fmt.Sprintf("no user with id %d found in database", userID)
			helpers.Response(w, res, 401)
			return
		} else {
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
	}

	if user.Role != "Admin" {
		res := "only admins can view all users"
		helpers.Response(w, res, 401)
		return
	}

	users, err := queries.GetAllUsers(context.Background())
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if len(users) > 0 {
		for _, user := range users {
			res := newGetUsersResponse(user)
			helpers.JsonResponse(w, res)
			return
		}
	} else {
		res := "no user found in database"
		helpers.Response(w, res, 401)
		return
	}
}
