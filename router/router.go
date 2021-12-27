package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kibetrutoh/kibetgo/controllers"
	"github.com/kibetrutoh/kibetgo/database"
)

func Router() *chi.Mux {

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.AllowContentEncoding("application/json"))
	r.Use(middleware.CleanPath)
	r.Use(middleware.RedirectSlashes)

	db := database.ConnectDB()
	h := controllers.NewBaseHandler(db)

	r.Get("/", h.HelloWorld)
	r.Post("/account/signup", h.SignUp)
	r.Post("/account/verify-email/{userEmail:^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$}/{eVerificationCode:^[0-9]*$}", h.ValidateUser)
	r.Post("/account/verify-email", h.VerifyEmail)
	r.Post("/account/login", h.Login)
	r.Post("/account/logout", h.Logout)
	r.Get("/account/{uuid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.GetUser)
	r.Put("/account/{uuid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.UpdateUser)
	r.Delete("/account/{uuid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.DeleteUser)
	r.Get("/account/allusers", h.AllUsers)

	r.Post("/token/refresh-token", h.RefreshToken)

	r.Post("/tenant/create-tenant", h.CreateTenant)
	r.Put("/tenant/{uuid:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.UpdateTenant)

	r.Post("/invite-tenant-user", h.InviteTenantUser)

	return r
}
