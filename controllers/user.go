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

	"github.com/kibetrutoh/kibetgo/database"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/token"
)

func (b *BaseHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	//: GOAL = get user details using user id
	//: get and verify access token
	//: get user id from token
	//: get user from db using id

	getAuthHeader := r.Header.Get("authorization")
	splitAuthHeader := strings.Split(getAuthHeader, "Bearer")

	if len(splitAuthHeader) != 2 {
		log.Println("Error: Bearer token not in proper format")
		helpers.Response(w, "improper bearer token format", 401)
		return
	}

	requestToken := strings.TrimSpace(splitAuthHeader[1])

	tokenPayload, err := token.VerifyToken(requestToken)
	if err != nil {
		log.Println(err)
		helpers.Response(w, err.Error(), 401)
		return
	}

	connectDatabase := database.ConnectDB()
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

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (b *BaseHandler) UpdateFullName(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("update full name"))
}

func (b *BaseHandler) UpdateEmail(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("update email"))
}

func (b *BaseHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("update password"))
}

func (b *BaseHandler) UpdateTimezone(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("update timezone"))
}

func (b *BaseHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("delete account"))
}

func (b *BaseHandler) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	// only admin can get user
}
