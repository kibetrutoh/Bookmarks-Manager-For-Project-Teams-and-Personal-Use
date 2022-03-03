package controllers

import "net/http"

func (b *BaseHandler) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("create admin"))
}

func (b *BaseHandler) UpdateAdmin(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("create admin"))
}

func (b *BaseHandler) RemoveAdmin(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("create admin"))
}
