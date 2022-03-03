package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/kibetrutoh/kibetgo/controllers"
	"github.com/kibetrutoh/kibetgo/database"
)

func Router() *chi.Mux {

	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.AllowContentEncoding("application/json"))
	r.Use(middleware.CleanPath)
	r.Use(middleware.RedirectSlashes)

	db := database.ConnectDB()
	baseHandler := controllers.NewBaseHandler(db)

	r.Get("/", baseHandler.HelloWorld)

	r.Route("/users", func(r chi.Router) {

		r.Get("/", baseHandler.GetAllUsers)

		r.Route("/auth", func(r chi.Router) {
			r.Post("/request/email/verification/code", baseHandler.RequestVerificationCode)
			r.Post("/email/verify", baseHandler.VerifyEmail)
			r.Post("/request/login/magic/code", baseHandler.RequestLoginMagicCode)
			r.Post("/verify/login/magic/code", baseHandler.VerifyMagicCode)
			r.Post("/request/new/access/token", baseHandler.RequestNewAccessToken)
			r.Post("/manual/sign/out", baseHandler.ManualLogout)
		})

	})

	r.Route("/user", func(r chi.Router) {
		r.Get("/get/one", baseHandler.GetUser)
		r.Put("/update/name", baseHandler.UpdateFullName)
		r.Put("/update/email", baseHandler.UpdateEmail)
		r.Put("/update/password", baseHandler.UpdatePassword)
		r.Put("/update/timezone", baseHandler.UpdateTimezone)
		r.Delete("/delete/account", baseHandler.DeleteAccount)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Post("/create", baseHandler.CreateAdmin)
		r.Put("/update", baseHandler.UpdateAdmin)
		r.Delete("/remove", baseHandler.RemoveAdmin)
	})

	return r
}
