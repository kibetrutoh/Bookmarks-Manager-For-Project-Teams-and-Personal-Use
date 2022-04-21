package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/kibetrutoh/kibetgo/db/connection"
	"github.com/kibetrutoh/kibetgo/db/sqlc"
	"github.com/kibetrutoh/kibetgo/helpers"
	"github.com/kibetrutoh/kibetgo/token"
	"github.com/kibetrutoh/kibetgo/utils"
)

type createDashboardRequest struct {
	DashboardName string `json:"dashboard_name"`
}

func (c createDashboardRequest) validate() error {
	return validation.ValidateStruct(&c,
		validation.Field(&c.DashboardName, validation.Required, validation.Length(3, 100)),
	)
}

type createDashboardResponse struct {
	DashboardName  string `json:"dashboard_name"`
	DashboardAdmin int32  `json:"dashboard_admin"`
}

func newCreateDashboardResponse(dashboard sqlc.Dashboard) *createDashboardResponse {
	return &createDashboardResponse{
		DashboardName:  dashboard.DashboardName,
		DashboardAdmin: dashboard.DashboardAdmin,
	}
}

func (b *BaseHandler) CreateDashboard(w http.ResponseWriter, r *http.Request) {
	// check and set request header to json
	utils.SetRequestHeaderToJson(r)
	// get and verify access token
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

	// get and store dashboard name value from post request
	rBody := json.NewDecoder(r.Body)
	rBody.DisallowUnknownFields()

	var req createDashboardRequest

	err = rBody.Decode(&req)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}
	// validate name
	if err := req.validate(); err != nil {
		if e, ok := err.(validation.InternalError); ok {
			log.Println(e.InternalError())
			helpers.Response(w, ErrInternalServerError.Error(), 500)
			return
		}
		res := fmt.Errorf("enter a valid name")
		helpers.Response(w, res.Error(), 400)
		return
	}
	// init db
	connectDatabase := connection.ConnectDB()
	newBaseHandler := NewBaseHandler(connectDatabase)
	queries := sqlc.New(newBaseHandler.db)

	// get user id from token payload
	userID := tokenPayload.UserID

	// check if user has dashboard by same name
	dashboards, err := queries.GetAllDashboards(context.Background())
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}

	if len(dashboards) > 0 {
		for _, dashboard := range dashboards {
			if dashboard.DashboardAdmin == int32(userID) {
				thisUserDashboard := dashboard
				if thisUserDashboard.DashboardName == req.DashboardName {
					res := fmt.Errorf("dashboard with this name already exists")
					helpers.Response(w, res.Error(), 401)
					return
				}
			}
		}
	}

	// create dashboard id
	dashboardID := utils.GenerateRandomString()

	// create dashboard with name and user id

	arg := sqlc.CreateDashboardParams{
		ID:             dashboardID,
		DashboardName:  req.DashboardName,
		DashboardAdmin: int32(userID),
	}

	dashboard, err := queries.CreateDashboard(context.Background(), arg)
	if err != nil {
		log.Println(err)
		helpers.Response(w, ErrInternalServerError.Error(), 500)
		return
	}
	// return dashboard name and admin
	res := newCreateDashboardResponse(dashboard)

	helpers.JsonResponse(w, res)
}

// UPDATE DASHBOARD
func (b *BaseHandler) UpdateDashboardName(w http.ResponseWriter, r *http.Request) {
	// update dashboard name by dashboard id and admin id
}

// SHOW USER DASHBOADS
func (b *BaseHandler) ShowUserDashboards(w http.ResponseWriter, r *http.Request) {
	// show all user dashboards here
}
