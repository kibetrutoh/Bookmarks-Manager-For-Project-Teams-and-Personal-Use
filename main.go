package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kibetrutoh/kibetgo/router"
	"github.com/kibetrutoh/kibetgo/utils"
	"github.com/rollbar/rollbar-go"
)

func main() {
	fmt.Println("server running 🚀🔥")

	config, err := utils.LoadConfig(".")
	if err != nil {
		rollbar.Critical(err)
		return
	}

	port := config.PORT
	router := router.Router()

	log.Fatal(http.ListenAndServe(port, router))

	rollbar.SetToken(config.RollBarToken)
	rollbar.SetEnvironment("production")                 // defaults to "development"
	rollbar.SetCodeVersion("v2")                         // optional Git hash/branch/tag (required for GitHub integration)
	rollbar.SetServerHost("web.1")                       // optional override; defaults to hostname
	rollbar.SetServerRoot("github.com/heroku/myproject") // path of project (required for GitHub integration and non-project stacktrace collapsing)

	rollbar.Info("Message body goes here")

	rollbar.Wait()
}
