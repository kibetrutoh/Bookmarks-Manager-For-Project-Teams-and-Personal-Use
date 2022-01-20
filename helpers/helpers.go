package helpers

import (
	"encoding/json"
	"log"
	"net/http"
)

func Response(w http.ResponseWriter, message string, httpStatusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	resp := make(map[string]string)
	resp["message"] = message
	jsonResponse, err := json.Marshal(resp)
	if err != nil {
		log.Println(err)
	}
	w.Write(jsonResponse)
}
