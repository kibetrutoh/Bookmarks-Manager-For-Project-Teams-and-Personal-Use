// Code generated by sqlc. DO NOT EDIT.
// source: user.sql

package sqlc

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (full_name, email_address, hashed_password, verification_code, verificaton_code_expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (email_address) DO UPDATE
SET verification_code = EXCLUDED.verification_code, verificaton_code_expires_at = EXCLUDED.verificaton_code_expires_at, created_at = EXCLUDED.created_at, full_name = EXCLUDED.full_name, hashed_password = EXCLUDED.hashed_password
RETURNING user_id, full_name, email_address, hashed_password, hashed_password_updated_at, role, active, verification_code, verificaton_code_expires_at, created_at, updated_at, refresh_token_id
`

type CreateUserParams struct {
	FullName                 string    `json:"full_name"`
	EmailAddress             string    `json:"email_address"`
	HashedPassword           string    `json:"hashed_password"`
	VerificationCode         string    `json:"verification_code"`
	VerificatonCodeExpiresAt time.Time `json:"verificaton_code_expires_at"`
	CreatedAt                time.Time `json:"created_at"`
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser,
		arg.FullName,
		arg.EmailAddress,
		arg.HashedPassword,
		arg.VerificationCode,
		arg.VerificatonCodeExpiresAt,
		arg.CreatedAt,
	)
	var i User
	err := row.Scan(
		&i.UserID,
		&i.FullName,
		&i.EmailAddress,
		&i.HashedPassword,
		&i.HashedPasswordUpdatedAt,
		&i.Role,
		&i.Active,
		&i.VerificationCode,
		&i.VerificatonCodeExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RefreshTokenID,
	)
	return i, err
}

const deleteUser = `-- name: DeleteUser :exec
DELETE FROM users
WHERE user_id = $1
`

func (q *Queries) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteUser, userID)
	return err
}

const getUser = `-- name: GetUser :one
SELECT user_id, full_name, email_address, hashed_password, hashed_password_updated_at, role, active, verification_code, verificaton_code_expires_at, created_at, updated_at, refresh_token_id FROM users
WHERE user_id = $1 LIMIT 1
`

func (q *Queries) GetUser(ctx context.Context, userID uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, userID)
	var i User
	err := row.Scan(
		&i.UserID,
		&i.FullName,
		&i.EmailAddress,
		&i.HashedPassword,
		&i.HashedPasswordUpdatedAt,
		&i.Role,
		&i.Active,
		&i.VerificationCode,
		&i.VerificatonCodeExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RefreshTokenID,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT user_id, full_name, email_address, hashed_password, hashed_password_updated_at, role, active, verification_code, verificaton_code_expires_at, created_at, updated_at, refresh_token_id FROM users
WHERE email_address = $1 LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, emailAddress string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, emailAddress)
	var i User
	err := row.Scan(
		&i.UserID,
		&i.FullName,
		&i.EmailAddress,
		&i.HashedPassword,
		&i.HashedPasswordUpdatedAt,
		&i.Role,
		&i.Active,
		&i.VerificationCode,
		&i.VerificatonCodeExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RefreshTokenID,
	)
	return i, err
}

const getUserByVerificationCode = `-- name: GetUserByVerificationCode :one
SELECT user_id, full_name, email_address, hashed_password, hashed_password_updated_at, role, active, verification_code, verificaton_code_expires_at, created_at, updated_at, refresh_token_id FROM users
WHERE verification_code = $1 LIMIT 1
`

func (q *Queries) GetUserByVerificationCode(ctx context.Context, verificationCode string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByVerificationCode, verificationCode)
	var i User
	err := row.Scan(
		&i.UserID,
		&i.FullName,
		&i.EmailAddress,
		&i.HashedPassword,
		&i.HashedPasswordUpdatedAt,
		&i.Role,
		&i.Active,
		&i.VerificationCode,
		&i.VerificatonCodeExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RefreshTokenID,
	)
	return i, err
}

const listUsers = `-- name: ListUsers :many
SELECT user_id, full_name, email_address, hashed_password, hashed_password_updated_at, role, active, verification_code, verificaton_code_expires_at, created_at, updated_at, refresh_token_id FROM users
ORDER BY full_name ASC
`

func (q *Queries) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := q.db.QueryContext(ctx, listUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.UserID,
			&i.FullName,
			&i.EmailAddress,
			&i.HashedPassword,
			&i.HashedPasswordUpdatedAt,
			&i.Role,
			&i.Active,
			&i.VerificationCode,
			&i.VerificatonCodeExpiresAt,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.RefreshTokenID,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateActiveStatus = `-- name: UpdateActiveStatus :exec
UPDATE users
SET active = NOT active
WHERE email_address = $1
`

func (q *Queries) UpdateActiveStatus(ctx context.Context, emailAddress string) error {
	_, err := q.db.ExecContext(ctx, updateActiveStatus, emailAddress)
	return err
}

const updateRefreshToken = `-- name: UpdateRefreshToken :exec
UPDATE users
SET refresh_token_id = $2
WHERE user_id = $1
`

type UpdateRefreshTokenParams struct {
	UserID         uuid.UUID `json:"user_id"`
	RefreshTokenID uuid.UUID `json:"refresh_token_id"`
}

func (q *Queries) UpdateRefreshToken(ctx context.Context, arg UpdateRefreshTokenParams) error {
	_, err := q.db.ExecContext(ctx, updateRefreshToken, arg.UserID, arg.RefreshTokenID)
	return err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET full_name = $2, email_address = $3, hashed_password = $4
WHERE user_id = $1
RETURNING user_id, full_name, email_address, hashed_password, hashed_password_updated_at, role, active, verification_code, verificaton_code_expires_at, created_at, updated_at, refresh_token_id
`

type UpdateUserParams struct {
	UserID         uuid.UUID `json:"user_id"`
	FullName       string    `json:"full_name"`
	EmailAddress   string    `json:"email_address"`
	HashedPassword string    `json:"hashed_password"`
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser,
		arg.UserID,
		arg.FullName,
		arg.EmailAddress,
		arg.HashedPassword,
	)
	var i User
	err := row.Scan(
		&i.UserID,
		&i.FullName,
		&i.EmailAddress,
		&i.HashedPassword,
		&i.HashedPasswordUpdatedAt,
		&i.Role,
		&i.Active,
		&i.VerificationCode,
		&i.VerificatonCodeExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RefreshTokenID,
	)
	return i, err
}