// Code generated by sqlc. DO NOT EDIT.
// source: user.sql

package sqlc

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const deleteAllActiveSessionsForUser = `-- name: DeleteAllActiveSessionsForUser :exec
DELETE FROM user_session
WHERE active = 'true' AND user_id = $1
`

func (q *Queries) DeleteAllActiveSessionsForUser(ctx context.Context, userID int32) error {
	_, err := q.db.ExecContext(ctx, deleteAllActiveSessionsForUser, userID)
	return err
}

const deleteAllSessionsForaUser = `-- name: DeleteAllSessionsForaUser :exec
DELETE FROM user_session
WHERE user_id = $1
`

func (q *Queries) DeleteAllSessionsForaUser(ctx context.Context, userID int32) error {
	_, err := q.db.ExecContext(ctx, deleteAllSessionsForaUser, userID)
	return err
}

const deleteEmailUpdateVerificationCode = `-- name: DeleteEmailUpdateVerificationCode :exec
DELETE FROM email_update_verification_code
WHERE code = $1
`

func (q *Queries) DeleteEmailUpdateVerificationCode(ctx context.Context, code string) error {
	_, err := q.db.ExecContext(ctx, deleteEmailUpdateVerificationCode, code)
	return err
}

const deleteSignupEmailVerificationCode = `-- name: DeleteSignupEmailVerificationCode :exec
DELETE FROM signup_email_verification_code
WHERE verification_code = $1
`

func (q *Queries) DeleteSignupEmailVerificationCode(ctx context.Context, verificationCode string) error {
	_, err := q.db.ExecContext(ctx, deleteSignupEmailVerificationCode, verificationCode)
	return err
}

const deleteUserAccount = `-- name: DeleteUserAccount :exec
DELETE FROM users
WHERE id = $1
`

func (q *Queries) DeleteUserAccount(ctx context.Context, id int32) error {
	_, err := q.db.ExecContext(ctx, deleteUserAccount, id)
	return err
}

const deleteUserLogicMagicCode = `-- name: DeleteUserLogicMagicCode :exec
DELETE FROM login_magic_code
WHERE code = $1 AND user_id = $2
`

type DeleteUserLogicMagicCodeParams struct {
	Code   string `json:"code"`
	UserID int32  `json:"user_id"`
}

func (q *Queries) DeleteUserLogicMagicCode(ctx context.Context, arg DeleteUserLogicMagicCodeParams) error {
	_, err := q.db.ExecContext(ctx, deleteUserLogicMagicCode, arg.Code, arg.UserID)
	return err
}

const deleteUserSessionByID = `-- name: DeleteUserSessionByID :exec
DELETE FROM user_session
WHERE id = $1
`

func (q *Queries) DeleteUserSessionByID(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteUserSessionByID, id)
	return err
}

const getAllActiveSessionsForUser = `-- name: GetAllActiveSessionsForUser :many
SELECT id, user_id, refresh_token, client_agent, client_ip, client_os, active, issued_at, expires_at FROM user_session
WHERE active = 'true' AND user_id = $1
`

func (q *Queries) GetAllActiveSessionsForUser(ctx context.Context, userID int32) ([]UserSession, error) {
	rows, err := q.db.QueryContext(ctx, getAllActiveSessionsForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []UserSession
	for rows.Next() {
		var i UserSession
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.RefreshToken,
			&i.ClientAgent,
			&i.ClientIp,
			&i.ClientOs,
			&i.Active,
			&i.IssuedAt,
			&i.ExpiresAt,
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

const getAllInactiveSessionsForUser = `-- name: GetAllInactiveSessionsForUser :many
SELECT id, user_id, refresh_token, client_agent, client_ip, client_os, active, issued_at, expires_at FROM user_session
WHERE active = 'false' AND user_id = $1
`

func (q *Queries) GetAllInactiveSessionsForUser(ctx context.Context, userID int32) ([]UserSession, error) {
	rows, err := q.db.QueryContext(ctx, getAllInactiveSessionsForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []UserSession
	for rows.Next() {
		var i UserSession
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.RefreshToken,
			&i.ClientAgent,
			&i.ClientIp,
			&i.ClientOs,
			&i.Active,
			&i.IssuedAt,
			&i.ExpiresAt,
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

const getAllSessionsForUser = `-- name: GetAllSessionsForUser :many
SELECT id, user_id, refresh_token, client_agent, client_ip, client_os, active, issued_at, expires_at
FROM user_session
WHERE user_id = $1
`

func (q *Queries) GetAllSessionsForUser(ctx context.Context, userID int32) ([]UserSession, error) {
	rows, err := q.db.QueryContext(ctx, getAllSessionsForUser, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []UserSession
	for rows.Next() {
		var i UserSession
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.RefreshToken,
			&i.ClientAgent,
			&i.ClientIp,
			&i.ClientOs,
			&i.Active,
			&i.IssuedAt,
			&i.ExpiresAt,
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

const getAllUsers = `-- name: GetAllUsers :many
SELECT id, full_name, email_address, client_os, client_agent, client_browser, timezone, created_at, updated_at FROM users
`

func (q *Queries) GetAllUsers(ctx context.Context) ([]User, error) {
	rows, err := q.db.QueryContext(ctx, getAllUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.FullName,
			&i.EmailAddress,
			&i.ClientOs,
			&i.ClientAgent,
			&i.ClientBrowser,
			&i.Timezone,
			&i.CreatedAt,
			&i.UpdatedAt,
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

const getEmailUpdateVerificationCode = `-- name: GetEmailUpdateVerificationCode :one
SELECT id, user_id, code, email_address, expiry FROM email_update_verification_code
WHERE code = $1 LIMIT 1
`

func (q *Queries) GetEmailUpdateVerificationCode(ctx context.Context, code string) (EmailUpdateVerificationCode, error) {
	row := q.db.QueryRowContext(ctx, getEmailUpdateVerificationCode, code)
	var i EmailUpdateVerificationCode
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Code,
		&i.EmailAddress,
		&i.Expiry,
	)
	return i, err
}

const getLoginMagicCode = `-- name: GetLoginMagicCode :one
SELECT id, user_id, code, email_address, code_expiry FROM login_magic_code
WHERE code = $1
LIMIT 1
`

func (q *Queries) GetLoginMagicCode(ctx context.Context, code string) (LoginMagicCode, error) {
	row := q.db.QueryRowContext(ctx, getLoginMagicCode, code)
	var i LoginMagicCode
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Code,
		&i.EmailAddress,
		&i.CodeExpiry,
	)
	return i, err
}

const getSignupEmailVerificationCode = `-- name: GetSignupEmailVerificationCode :one
SELECT id, email_address, verification_code, expiry FROM signup_email_verification_code
WHERE verification_code = $1
LIMIT 1
`

func (q *Queries) GetSignupEmailVerificationCode(ctx context.Context, verificationCode string) (SignupEmailVerificationCode, error) {
	row := q.db.QueryRowContext(ctx, getSignupEmailVerificationCode, verificationCode)
	var i SignupEmailVerificationCode
	err := row.Scan(
		&i.ID,
		&i.EmailAddress,
		&i.VerificationCode,
		&i.Expiry,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, full_name, email_address, client_os, client_agent, client_browser, timezone, created_at, updated_at FROM users
WHERE email_address = $1
LIMIT 1
`

func (q *Queries) GetUserByEmail(ctx context.Context, emailAddress string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, emailAddress)
	var i User
	err := row.Scan(
		&i.ID,
		&i.FullName,
		&i.EmailAddress,
		&i.ClientOs,
		&i.ClientAgent,
		&i.ClientBrowser,
		&i.Timezone,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserById = `-- name: GetUserById :one
SELECT id, full_name, email_address, client_os, client_agent, client_browser, timezone, created_at, updated_at FROM users
WHERE id = $1
LIMIT 1
`

func (q *Queries) GetUserById(ctx context.Context, id int32) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserById, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.FullName,
		&i.EmailAddress,
		&i.ClientOs,
		&i.ClientAgent,
		&i.ClientBrowser,
		&i.Timezone,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getUserLoginMagicCodes = `-- name: GetUserLoginMagicCodes :many
SELECT id, user_id, code, email_address, code_expiry FROM login_magic_code
WHERE user_id = $1
`

func (q *Queries) GetUserLoginMagicCodes(ctx context.Context, userID int32) ([]LoginMagicCode, error) {
	rows, err := q.db.QueryContext(ctx, getUserLoginMagicCodes, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []LoginMagicCode
	for rows.Next() {
		var i LoginMagicCode
		if err := rows.Scan(
			&i.ID,
			&i.UserID,
			&i.Code,
			&i.EmailAddress,
			&i.CodeExpiry,
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

const getUserSessionByID = `-- name: GetUserSessionByID :one
SELECT id, user_id, refresh_token, client_agent, client_ip, client_os, active, issued_at, expires_at FROM user_session
WHERE id = $1
LIMIT 1
`

func (q *Queries) GetUserSessionByID(ctx context.Context, id uuid.UUID) (UserSession, error) {
	row := q.db.QueryRowContext(ctx, getUserSessionByID, id)
	var i UserSession
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.RefreshToken,
		&i.ClientAgent,
		&i.ClientIp,
		&i.ClientOs,
		&i.Active,
		&i.IssuedAt,
		&i.ExpiresAt,
	)
	return i, err
}

const insertIntoEmailUpdateVerificationTable = `-- name: InsertIntoEmailUpdateVerificationTable :one
INSERT INTO email_update_verification_code (user_id, code, email_address, expiry)
VALUES ($1, $2, $3, $4)
ON CONFLICT (email_address) DO UPDATE
SET user_id = EXCLUDED.user_id, code = EXCLUDED.code, expiry = EXCLUDED.expiry
RETURNING id, user_id, code, email_address, expiry
`

type InsertIntoEmailUpdateVerificationTableParams struct {
	UserID       int32     `json:"user_id"`
	Code         string    `json:"code"`
	EmailAddress string    `json:"email_address"`
	Expiry       time.Time `json:"expiry"`
}

func (q *Queries) InsertIntoEmailUpdateVerificationTable(ctx context.Context, arg InsertIntoEmailUpdateVerificationTableParams) (EmailUpdateVerificationCode, error) {
	row := q.db.QueryRowContext(ctx, insertIntoEmailUpdateVerificationTable,
		arg.UserID,
		arg.Code,
		arg.EmailAddress,
		arg.Expiry,
	)
	var i EmailUpdateVerificationCode
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Code,
		&i.EmailAddress,
		&i.Expiry,
	)
	return i, err
}

const insertIntoLoginMagicCodeTable = `-- name: InsertIntoLoginMagicCodeTable :one
INSERT INTO login_magic_code (user_id, email_address, code, code_expiry)
VALUES ($1, $2, $3, $4)
ON CONFLICT (code) DO UPDATE
SET email_address = EXCLUDED.email_address, code_expiry = EXCLUDED.code_expiry
RETURNING id, user_id, code, email_address, code_expiry
`

type InsertIntoLoginMagicCodeTableParams struct {
	UserID       int32     `json:"user_id"`
	EmailAddress string    `json:"email_address"`
	Code         string    `json:"code"`
	CodeExpiry   time.Time `json:"code_expiry"`
}

func (q *Queries) InsertIntoLoginMagicCodeTable(ctx context.Context, arg InsertIntoLoginMagicCodeTableParams) (LoginMagicCode, error) {
	row := q.db.QueryRowContext(ctx, insertIntoLoginMagicCodeTable,
		arg.UserID,
		arg.EmailAddress,
		arg.Code,
		arg.CodeExpiry,
	)
	var i LoginMagicCode
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Code,
		&i.EmailAddress,
		&i.CodeExpiry,
	)
	return i, err
}

const insertIntoSignUpEmailVerificationTable = `-- name: InsertIntoSignUpEmailVerificationTable :one
INSERT INTO signup_email_verification_code (email_address, verification_code, expiry)
VALUES ($1, $2, $3)
ON CONFLICT (email_address) DO UPDATE
SET verification_code = EXCLUDED.verification_code, expiry = EXCLUDED.expiry
RETURNING id, email_address, verification_code, expiry
`

type InsertIntoSignUpEmailVerificationTableParams struct {
	EmailAddress     string    `json:"email_address"`
	VerificationCode string    `json:"verification_code"`
	Expiry           time.Time `json:"expiry"`
}

func (q *Queries) InsertIntoSignUpEmailVerificationTable(ctx context.Context, arg InsertIntoSignUpEmailVerificationTableParams) (SignupEmailVerificationCode, error) {
	row := q.db.QueryRowContext(ctx, insertIntoSignUpEmailVerificationTable, arg.EmailAddress, arg.VerificationCode, arg.Expiry)
	var i SignupEmailVerificationCode
	err := row.Scan(
		&i.ID,
		&i.EmailAddress,
		&i.VerificationCode,
		&i.Expiry,
	)
	return i, err
}

const insertIntoUserSessionTable = `-- name: InsertIntoUserSessionTable :one
INSERT INTO user_session (id, user_id, refresh_token, client_agent, client_ip, client_os, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, user_id, refresh_token, client_agent, client_ip, client_os, active, issued_at, expires_at
`

type InsertIntoUserSessionTableParams struct {
	ID           uuid.UUID `json:"id"`
	UserID       int32     `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	ClientAgent  string    `json:"client_agent"`
	ClientIp     string    `json:"client_ip"`
	ClientOs     string    `json:"client_os"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (q *Queries) InsertIntoUserSessionTable(ctx context.Context, arg InsertIntoUserSessionTableParams) (UserSession, error) {
	row := q.db.QueryRowContext(ctx, insertIntoUserSessionTable,
		arg.ID,
		arg.UserID,
		arg.RefreshToken,
		arg.ClientAgent,
		arg.ClientIp,
		arg.ClientOs,
		arg.ExpiresAt,
	)
	var i UserSession
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.RefreshToken,
		&i.ClientAgent,
		&i.ClientIp,
		&i.ClientOs,
		&i.Active,
		&i.IssuedAt,
		&i.ExpiresAt,
	)
	return i, err
}

const insertIntoUsersTable = `-- name: InsertIntoUsersTable :one
INSERT INTO users (full_name, email_address, client_os, client_agent, client_browser)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, full_name, email_address, client_os, client_agent, client_browser, timezone, created_at, updated_at
`

type InsertIntoUsersTableParams struct {
	FullName      string `json:"full_name"`
	EmailAddress  string `json:"email_address"`
	ClientOs      string `json:"client_os"`
	ClientAgent   string `json:"client_agent"`
	ClientBrowser string `json:"client_browser"`
}

func (q *Queries) InsertIntoUsersTable(ctx context.Context, arg InsertIntoUsersTableParams) (User, error) {
	row := q.db.QueryRowContext(ctx, insertIntoUsersTable,
		arg.FullName,
		arg.EmailAddress,
		arg.ClientOs,
		arg.ClientAgent,
		arg.ClientBrowser,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.FullName,
		&i.EmailAddress,
		&i.ClientOs,
		&i.ClientAgent,
		&i.ClientBrowser,
		&i.Timezone,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateActiveSessionsForUserToInactive = `-- name: UpdateActiveSessionsForUserToInactive :exec
UPDATE user_session
SET active = 'false'
WHERE active = 'true' AND user_id = $1
`

func (q *Queries) UpdateActiveSessionsForUserToInactive(ctx context.Context, userID int32) error {
	_, err := q.db.ExecContext(ctx, updateActiveSessionsForUserToInactive, userID)
	return err
}

const updateOneActiveUserSessionToInactive = `-- name: UpdateOneActiveUserSessionToInactive :exec
UPDATE user_session
SET active = 'false'
WHERE id = $1
`

func (q *Queries) UpdateOneActiveUserSessionToInactive(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, updateOneActiveUserSessionToInactive, id)
	return err
}

const updateUserEmail = `-- name: UpdateUserEmail :one
UPDATE users
SET email_address = $2
WHERE id = $1
RETURNING id, full_name, email_address, client_os, client_agent, client_browser, timezone, created_at, updated_at
`

type UpdateUserEmailParams struct {
	ID           int32  `json:"id"`
	EmailAddress string `json:"email_address"`
}

func (q *Queries) UpdateUserEmail(ctx context.Context, arg UpdateUserEmailParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserEmail, arg.ID, arg.EmailAddress)
	var i User
	err := row.Scan(
		&i.ID,
		&i.FullName,
		&i.EmailAddress,
		&i.ClientOs,
		&i.ClientAgent,
		&i.ClientBrowser,
		&i.Timezone,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateUserFullName = `-- name: UpdateUserFullName :one
UPDATE users
SET full_name = $2
WHERE id = $1
RETURNING id, full_name, email_address, client_os, client_agent, client_browser, timezone, created_at, updated_at
`

type UpdateUserFullNameParams struct {
	ID       int32  `json:"id"`
	FullName string `json:"full_name"`
}

func (q *Queries) UpdateUserFullName(ctx context.Context, arg UpdateUserFullNameParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserFullName, arg.ID, arg.FullName)
	var i User
	err := row.Scan(
		&i.ID,
		&i.FullName,
		&i.EmailAddress,
		&i.ClientOs,
		&i.ClientAgent,
		&i.ClientBrowser,
		&i.Timezone,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
