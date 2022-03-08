package controllers

import "net/http"

func (b *BaseHandler) Test(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("test handler"))
}
