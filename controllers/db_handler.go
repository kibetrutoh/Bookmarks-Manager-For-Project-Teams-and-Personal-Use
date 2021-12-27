package controllers

import "database/sql"

type BaseHandler struct {
	db *sql.DB
}

func NewBaseHandler(db *sql.DB) *BaseHandler {
	return &BaseHandler{
		db: db,
	}
}
