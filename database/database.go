package database

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/kibetrutoh/kibetgo/utils"
)

func ConnectDB() *sql.DB {
	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err.Error())
	}

	db, err := sql.Open("pgx", config.DBString)
	if err != nil {
		log.Println(err.Error())
	}

	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(30 * time.Second)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db
}
