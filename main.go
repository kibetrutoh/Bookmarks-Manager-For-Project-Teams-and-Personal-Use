package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kibetrutoh/kibetgo/router"
	"github.com/kibetrutoh/kibetgo/utils"
)

func main() {
	fmt.Println("ok! running 🚀🔥")

	config, err := utils.LoadConfig(".")
	if err != nil {
		log.Println("cannot load config", err)
	}

	port := config.PORT
	router := router.Router()

	log.Fatal(http.ListenAndServe(port, router))
}
