package controllers

// import (
// 	"context"
// 	"database/sql"
// 	"encoding/json"
// 	"errors"
// 	"log"
// 	"net/http"
// 	"strings"
// 	"time"

// 	"github.com/go-chi/chi/v5"
// 	validation "github.com/go-ozzo/ozzo-validation/v4"
// 	"github.com/jackc/pgconn"
// 	"github.com/kibetrutoh/kibetgo/database"
// 	"github.com/kibetrutoh/kibetgo/db/sqlc"
// 	"github.com/kibetrutoh/kibetgo/helpers"
// 	"github.com/kibetrutoh/kibetgo/token"
// 	"github.com/kibetrutoh/kibetgo/utils"
// )

// type createWorkspaceRequest struct {
// 	WorkspaceName string `json:"workspace_name"`
// 	ProjectName   string `json:"project_name"`
// }

// func (c createWorkspaceRequest) validate() error {
// 	return validation.ValidateStruct(&c,
// 		validation.Field(&c.WorkspaceName, validation.Required, validation.Length(5, 500)),
// 		validation.Field(&c.ProjectName, validation.Required),
// 	)
// }

// type createWorkspaceResponse struct {
// 	WorkspaceName string `json:"workspace_name"`
// 	ProjectName   string `json:"project_name"`
// 	UserID        string `json:"user_id"`
// }

// func newCreateWorkspaceResponse(workspace sqlc.Workspace) createWorkspaceResponse {
// 	return createWorkspaceResponse{
// 		WorkspaceName: workspace.WorkspaceName,
// 		ProjectName:   workspace.ProjectName,
// 		UserID:        workspace.UserID,
// 	}
// }

// func (h *BaseHandler) CreateWorkspace(w http.ResponseWriter, r *http.Request) {
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
// 		helpers.ErrorResponse(w, err.Error(), http.StatusUnauthorized)
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

// 	uEmail := payload.UserID

// 	data := json.NewDecoder(r.Body)
// 	data.DisallowUnknownFields()

// 	var req createWorkspaceRequest

// 	err = data.Decode(&req)
// 	if err != nil {
// 		log.Println(err)
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	err = req.validate()
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, err.Error(), 400)
// 		return
// 	}

// 	user, _ := q.GetUserByEmail(context.Background(), uEmail)

// 	log.Println(user.UserID)

// 	workspace_id, err := utils.UniqueID(6)
// 	if err != nil {
// 		log.Println(err.Error())
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	arg := sqlc.CreateWorkspaceParams{
// 		WorkspaceID:   workspace_id,
// 		WorkspaceName: req.WorkspaceName,
// 		ProjectName:   req.ProjectName,
// 		UserID:        user.UserID,
// 	}

// 	workspace, err := q.CreateWorkspace(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	resp := newCreateWorkspaceResponse(workspace)

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(resp)
// }

// type updateWorkspaceRequest struct {
// 	WorkspaceName string `json:"workspace_name"`
// 	ProjectName   string `json:"project_name"`
// }

// type updateWorkspaceResponse struct {
// 	WorkspaceID   string `json:"workspace_id"`
// 	WorkspaceName string `json:"workspace_name"`
// 	ProjectName   string `json:"project_name"`
// }

// func newUpdateWorkspaceResponse(workspace sqlc.Workspace) updateWorkspaceResponse {
// 	return updateWorkspaceResponse{
// 		WorkspaceID:   workspace.WorkspaceID,
// 		WorkspaceName: workspace.WorkspaceName,
// 		ProjectName:   workspace.ProjectName,
// 	}
// }

// func (u updateWorkspaceRequest) validate() error {
// 	return validation.ValidateStruct(&u,
// 		validation.Field(&u.WorkspaceName, validation.Required, validation.Length(5, 500)),
// 		validation.Field(&u.ProjectName, validation.Required),
// 	)
// }

// func (h *BaseHandler) UpdateWorkspace(w http.ResponseWriter, r *http.Request) {
// 	if r.Header.Get("Content-Type") != "application/json" {
// 		w.Header().Set("Content-Type", "application/json")
// 	}

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

// 	var req updateWorkspaceRequest

// 	body := json.NewDecoder(r.Body)
// 	body.DisallowUnknownFields()

// 	err = body.Decode(&req)
// 	if err != nil {
// 		helpers.ErrorResponse(w, "something went wrong", 500)
// 		return
// 	}

// 	err = req.validate()
// 	if err != nil {
// 		helpers.ErrorResponse(w, err.Error(), 422)
// 		return
// 	}

// 	workspace, err := q.GetWorkspace(context.Background(), id)
// 	switch {
// 	case errors.As(err, &sql.ErrNoRows):
// 		helpers.ErrorResponse(w, "workspace not found", 404)
// 		return
// 	}

// 	arg := sqlc.UpdateWorkspaceParams{
// 		WorkspaceID:   workspace.WorkspaceID,
// 		WorkspaceName: req.WorkspaceName,
// 		ProjectName:   req.ProjectName,
// 	}

// 	workspace, err = q.UpdateWorkspace(context.Background(), arg)
// 	if err != nil {
// 		var pgErr *pgconn.PgError
// 		if errors.As(err, &pgErr) {
// 			log.Println(pgErr.Message)
// 			helpers.ErrorResponse(w, "something went wrong", 500)
// 			return
// 		}
// 	}

// 	resp := newUpdateWorkspaceResponse(workspace)
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(resp)
// }

// func (b *BaseHandler) GetAllWorkspaces(w http.ResponseWriter, r *http.Request) {
// 	w.Write([]byte("get all workspaces"))
// }

// func (b *BaseHandler) FindWorkspaces(w http.ResponseWriter, r *http.Request) {
// 	w.Write([]byte("find workspaces"))
// }
