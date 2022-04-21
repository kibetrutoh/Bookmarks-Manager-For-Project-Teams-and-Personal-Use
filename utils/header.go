package utils

import "net/http"

func SetRequestHeaderToJson(r *http.Request) {
	if r.Header.Get("content-type") != "application/json" {
		r.Header.Set("content-type", "application/json")
	}
}
