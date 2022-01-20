package controllers

// import (
// 	"context"
// 	"database/sql"
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"strings"
// 	"time"

// 	"github.com/go-chi/chi/v5"

// 	"github.com/google/uuid"
// 	"github.com/jackc/pgconn"
// 	"github.com/kibetrutoh/kibetgo/database"
// 	"github.com/kibetrutoh/kibetgo/db/sqlc"
// 	"github.com/kibetrutoh/kibetgo/helpers"
// 	"github.com/kibetrutoh/kibetgo/token"
// 	"github.com/kibetrutoh/kibetgo/utils"
// )

// type invite_workspace_user struct {
// 	EmailAddress string `json:"email_address"`
// 	AccessLevel  string `json:"access_level"`
// }

// func (h *BaseHandler) InviteWorkspaceUser(w http.ResponseWriter, r *http.Request) {
// 	if r.Header.Get("Content-Type") != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

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
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "token is invalid", 401)
// 		return
// 	}

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is expired", 401)
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
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	for _, blackblacklisted_token := range blacklisted_tokens {
// 		if payload.ID == blackblacklisted_token {
// 			helpers.ErrorResponse(w, "token is blacklisted", 401)
// 			return
// 		}
// 	}

// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	admin_email := payload.UserID

// 	_, err = q.GetUserByEmail(context.Background(), admin_email)
// 	if errors.Is(err, sql.ErrNoRows) {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "not authorized", 404)
// 		return
// 	}

// 	workspace_id := chi.URLParam(r, "workspace")

// 	_, err = q.GetWorkspace(context.Background(), workspace_id)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			log.Println(err.Error())
// 			helpers.ErrorResponse(w, "not authorized", 404)
// 			return
// 		}
// 	}

// 	body := json.NewDecoder(r.Body)
// 	body.DisallowUnknownFields()

// 	var req invite_workspace_user
// 	err = body.Decode(&req)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	invitation_token, err := uuid.NewRandom()
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	invitation_token_string := invitation_token.String()

// 	workspace_user_id, err := utils.UniqueID(6)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "an error occured", 500)
// 		return
// 	}

// 	arg := sqlc.InviteWorkspaceUserParams{
// 		WorkspaceUserID: workspace_user_id,
// 		EmailAddress:    req.EmailAddress,
// 		AccessLevel:     req.AccessLevel,
// 		WorkspaceID:     workspace_id,
// 		InvitationToken: invitation_token,
// 	}

// 	_, err = q.InviteWorkspaceUser(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(err.Error())
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	accept_invite_url := fmt.Sprintf("http://localhost:5000/%v/accept-invitation/%v", workspace_id, invitation_token_string)

// 	// send invitation email to user with link to accept invitation

// 	log.Println(accept_invite_url)
// 	helpers.SuccessResponse(w, "user has been invited", 200)
// }

// type accept_invitation struct {
// 	FullName string `json:"full_name"`
// 	Password string `json:"password"`
// }

// type accept_invitation_response struct {
// 	AccessToken  string `json:"access_token"`
// 	RefreshToken string `json:"refresh_token"`
// }

// func (b *BaseHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
// 	if r.Header.Get("Content-Type") != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

// 	invitation_token := chi.URLParam(r, "invitation-token")

// 	invitation_token_uid, err := uuid.Parse(invitation_token)
// 	if err != nil {
// 		log.Println(err.Error())
// 	}

// 	db := database.ConnectDB()
// 	b = NewBaseHandler(db)
// 	q := sqlc.New(b.db)

// 	workspace_user, err := q.GetWorkspaceUserByInvitationToken(context.Background(), invitation_token_uid)
// 	if errors.Is(err, sql.ErrNoRows) {
// 		helpers.ErrorResponse(w, "no workspace user found", 404)
// 		return
// 	}

// 	if workspace_user.AcceptedInvitation {
// 		helpers.ErrorResponse(w, "you are already here", 404)
// 		return
// 	}

// 	var req accept_invitation

// 	body := json.NewDecoder(r.Body)
// 	body.DisallowUnknownFields()

// 	err = body.Decode(&req)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	hashed_password, err := utils.HashPassword(req.Password)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	arg := sqlc.UpdateWorkspaceUserParams{
// 		WorkspaceUserID: workspace_user.WorkspaceUserID,
// 		FullName:        req.FullName,
// 		HashedPassword:  hashed_password,
// 	}

// 	workspace_user, err = q.UpdateWorkspaceUser(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	err = q.UpdateAcceptedInvitationStatus(context.Background(), arg.WorkspaceUserID)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	access_token, err := token.CreateAccessToken(workspace_user.EmailAddress)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	refresh_token, err := token.CreateRefreshToken(workspace_user.EmailAddress)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	res := accept_invitation_response{
// 		AccessToken:  access_token,
// 		RefreshToken: refresh_token,
// 	}

// 	w.Header().Set("content-type", "application/json")
// 	json.NewEncoder(w).Encode(res)
// }

// type get_workspace_user_response struct {
// 	FullName     string `json:"full_name"`
// 	EmailAddress string `json:"email_address"`
// 	WorkspaceID  string `json:"workspace_id"`
// }

// func newGetWorkspaceUserResponse(workspace_user sqlc.WorkspaceUser) get_workspace_user_response {
// 	return get_workspace_user_response{
// 		FullName:     workspace_user.FullName,
// 		EmailAddress: workspace_user.EmailAddress,
// 		WorkspaceID:  workspace_user.WorkspaceID,
// 	}
// }

// func (b *BaseHandler) GetWorkspaceUser(w http.ResponseWriter, r *http.Request) {
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
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is expired", 401)
// 		return
// 	}

// 	db := database.ConnectDB()
// 	b = NewBaseHandler(db)
// 	q := sqlc.New(b.db)

// 	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "something went wrong", 500)
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

// 	workspace_user, err := q.GetWorkspaceUser(context.Background(), id)
// 	if err != nil {
// 		log.Println(err.Error())
// 		if errors.Is(err, sql.ErrNoRows) {
// 			helpers.ErrorResponse(w, "workspace user not found", 404)
// 			return
// 		}
// 	}

// 	res := newGetWorkspaceUserResponse(workspace_user)
// 	w.Header().Set("content-type", "application/json")
// 	json.NewEncoder(w).Encode(res)
// }

// func (b *BaseHandler) DeleteWorkspaceUser(w http.ResponseWriter, r *http.Request) {
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
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
// 		return
// 	}

// 	if time.Now().UTC().After(payload.ExpiresAt) {
// 		helpers.ErrorResponse(w, "token is expired", 401)
// 		return
// 	}

// 	db := database.ConnectDB()
// 	b = NewBaseHandler(db)
// 	q := sqlc.New(b.db)

// 	blacklisted_tokens, err := q.ListBlacklistedAcessTokens(context.Background())
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "something went wrong", 500)
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

// 	err = q.DeleteWorkspaceUser(context.Background(), id)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(err.Error())
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	w.Header().Set("content-type", "application-json")
// 	helpers.SuccessResponse(w, "workspace user deleted successfully", 200)
// }

// type WorkspaceMemberRes struct {
// 	FullName     string `json:"full_name"`
// 	EmailAddress string `json:"email_address"`
// 	AccessLevel  string `json:"access_level"`
// }

// func newWorkspaceMember(workspace_member sqlc.WorkspaceUser) WorkspaceMemberRes {
// 	return WorkspaceMemberRes{
// 		FullName:     workspace_member.FullName,
// 		EmailAddress: workspace_member.EmailAddress,
// 		AccessLevel:  workspace_member.AccessLevel,
// 	}
// }

// func (b *BaseHandler) WorkspaceMembers(w http.ResponseWriter, r *http.Request) {
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

// 	db := database.ConnectDB()
// 	b = NewBaseHandler(db)
// 	q := sqlc.New(b.db)

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

// 	workspace_id := chi.URLParam(r, "workspace")

// 	workspace, err := q.GetWorkspace(context.Background(), workspace_id)
// 	if err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			log.Println(err.Error())
// 			helpers.ErrorResponse(w, "workspace not found", 404)
// 			return
// 		}
// 	}

// 	workspace_admin_id := workspace.UserID
// 	log.Println(workspace_admin_id)

// 	workspace_members, err := q.GetWorkspaceMembers(context.Background(), workspace_id)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(err.Error())
// 			helpers.Response(w, "something went wrong", 500)
// 			return
// 		}
// 	}
// 	log.Println(workspace_members)

// 	workspace_admin, err := q.GetUser(context.Background(), workspace_admin_id)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(err.Error())
// 			helpers.Response(w, "something went wrong", 500)
// 			return
// 		}
// 	}
// 	log.Println(workspace_admin)
// 	for _, workspace_member := range workspace_members {
// 		res := newWorkspaceMember(workspace_member)
// 		w.Header().Set("content-type", "application/json")
// 		json.NewEncoder(w).Encode(res)
// 	}

// 	// w.Header().Set("content-type", "application/json")
// 	// json.NewEncoder(w).Encode(workspace_members)
// 	// json.NewEncoder(w).Encode(workspace_admin)
// }
