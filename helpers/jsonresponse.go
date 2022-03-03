package helpers

import (
	"encoding/json"
	"net/http"
)

func JsonResponse(w http.ResponseWriter, res ...interface{}) {
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(res)
}
