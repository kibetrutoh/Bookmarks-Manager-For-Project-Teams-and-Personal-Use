package controllers

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime"

	"github.com/kibetrutoh/kibetgo/utils"
	"github.com/mssola/user_agent"
)

func (b *BaseHandler) HelloWorld(w http.ResponseWriter, r *http.Request) {

	userAgent := r.UserAgent()

	user_ip, err := utils.GetIP(r)
	if err != nil {
		log.Println(err)
	}

	log.Printf("User Agent: %v AND Ip Address: %v", userAgent, user_ip)

	os := runtime.GOOS
	os_architecture := runtime.GOARCH

	log.Printf("os: %v, AND os architechture is: %v", os, os_architecture)

	ua := user_agent.New(userAgent)

	n, v := ua.Browser()
	a := ua.UA()
	json.NewEncoder(w).Encode(n)
	json.NewEncoder(w).Encode(v)
	json.NewEncoder(w).Encode(a)
}
