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
	// r.Post("/account/signup", h.SignUp)
	// r.Post("/account/verify-email/{userEmail:^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$}/{eVerificationCode:^[0-9]*$}", h.ValidateUser)
	// r.Post("/account/verifyemail", h.VerifyEmail)
	// r.Post("/account/login", h.Login)

	// r.Post("/account/logout", h.Logout)
	// r.Get("/account/{id:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.GetUser)
	// r.Put("/account/{id:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.UpdateUser)
	// r.Delete("/account/{id:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.DeleteUser)
	// r.Get("/account/allusers", h.AllUsers)
	// r.Post("/token/refreshtoken", h.RefreshToken)
	// r.Put("/tenant/{id:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.UpdateWorkspace)
	// r.Get("/tenant-user/{id:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.GetWorkspaceUser)
	// r.Delete("/tenant-user/{id:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.DeleteWorkspaceUser)

	// r.Route("/workspaces", func(r chi.Router) {
	// 	r.Get("/all", h.GetAllWorkspaces)
	// 	r.Get("/find", h.FindWorkspaces)

	// 	r.Route("/workspace", func(r chi.Router) {
	// 		r.Post("/create-workspace", h.CreateWorkspace)
	// 	})

	// 	r.Route("/{workspace:^[0-9]*$}", func(r chi.Router) {
	// 		r.Post("/inviteuser", h.InviteWorkspaceUser)
	// 		r.Post("/accept-invitation/{invitation-code:[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}}", h.AcceptInvitation)
	// 		r.Get("/members", h.WorkspaceMembers)
	// 	})
	// })

	r.Route("/account", func(r chi.Router) {
		r.Post("/new", h.SignUp)
	})

	return r
}
