package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kibetrutoh/kibetgo/controllers"
	"github.com/kibetrutoh/kibetgo/db/connection"
)

func Router() *chi.Mux {

	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.AllowContentEncoding("application/json"))
	r.Use(middleware.CleanPath)
	r.Use(middleware.RedirectSlashes)

	db := connection.ConnectDB()
	baseHandler := controllers.NewBaseHandler(db)

	r.Get("/", baseHandler.Test)

	r.Route("/users", func(r chi.Router) {

		r.Get("/", baseHandler.GetAllUsers)

		r.Route("/auth", func(r chi.Router) {

			r.Route("/signup", func(r chi.Router) {
				r.Post("/", baseHandler.SignUp)
				r.Post("/verify-email", baseHandler.VerifyEmail)
				r.Get("/dashboards", baseHandler.ShowUserDashboards)
			})

			r.Route("/login", func(r chi.Router) {
				r.Post("/", baseHandler.Login)
				r.Post("/verify-email", baseHandler.LoginVerifyEmail)
				r.Get("/dashboards", baseHandler.ShowUserDashboards)
			})

			r.Post("/refresh-token", baseHandler.RequestNewAccessToken)
			r.Post("/logout", baseHandler.ManualLogout)
		})

	})

	r.Route("/user", func(r chi.Router) {
		r.Get("/get/one", baseHandler.GetUser)
		r.Put("/update/name", baseHandler.UpdateName)
		r.Post("/update/email", baseHandler.ChangeEmail)
		r.Put("/update/email/code/verify", baseHandler.VerifyChangeEmailCode)
		r.Put("/update/timezone", baseHandler.UpdateTimezone)
		r.Delete("/delete/account", baseHandler.DeleteAccount)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Post("/create", baseHandler.CreateAdmin)
		r.Put("/update", baseHandler.UpdateAdmin)
		r.Delete("/remove", baseHandler.RemoveAdmin)
	})

	r.Route("/dashboards", func(r chi.Router) {
		r.Post("/", baseHandler.CreateDashboard)
	})

	return r
}
