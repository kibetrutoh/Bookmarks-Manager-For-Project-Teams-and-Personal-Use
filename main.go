package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kibetrutoh/kibetgo/router"
	"github.com/kibetrutoh/kibetgo/utils"
)

func main() {
	fmt.Println("server running 🚀🔥")

	config, err := utils.LoadConfig(".")
	if err != nil {
		return
	}

	port := config.PORT
	router := router.Router()

	log.Fatal(http.ListenAndServe(port, router))

}
