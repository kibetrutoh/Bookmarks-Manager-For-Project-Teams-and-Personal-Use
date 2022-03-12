migrateup:
		migrate -path db/migrations -database "postgresql://kibet:535169003@localhost:5432/veryorganized?sslmode=disable" -verbose up

migratedown:
		migrate -path db/migrations -database "postgresql://kibet:535169003@localhost:5432/veryorganized?sslmode=disable" -verbose down

run:
	go run main.go

sqlc:
	sqlc generate

tidy:
	go mod tidy

golangmigratecreate:
		migrate create -ext sql -dir db/migrations -seq teams
