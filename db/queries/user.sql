-- name: InsertIntoUsersTable :one
INSERT INTO users (full_name, email_address, client_os, client_agent, client_browser)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1
LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email_address = $1
LIMIT 1;

-- name: GetAllUsers :many
SELECT * FROM users;

-- name: UpdateUserFullName :one
UPDATE users
SET full_name = $2
WHERE id = $1
RETURNING *;

-- name: UpdateUserEmail :one
UPDATE users
SET email_address = $2
WHERE id = $1
RETURNING *;

-- name: DeleteUserAccount :exec
DELETE FROM users
WHERE id = $1;

-- name: InsertIntoSignUpEmailVerificationTable :one
INSERT INTO signup_email_verification_code (email_address, verification_code, expiry)
VALUES ($1, $2, $3)
ON CONFLICT (email_address) DO UPDATE
SET verification_code = EXCLUDED.verification_code, expiry = EXCLUDED.expiry
RETURNING *;

-- name: GetSignupEmailVerificationCode :one
SELECT * FROM signup_email_verification_code
WHERE verification_code = $1
LIMIT 1;

-- name: DeleteSignupEmailVerificationCode :exec
DELETE FROM signup_email_verification_code
WHERE verification_code = $1;

-- name: InsertIntoLoginMagicCodeTable :one
INSERT INTO login_magic_code (user_id, email_address, code, code_expiry)
VALUES ($1, $2, $3, $4)
ON CONFLICT (code) DO UPDATE
SET email_address = EXCLUDED.email_address, code_expiry = EXCLUDED.code_expiry
RETURNING *;

-- name: GetLoginMagicCode :one
SELECT * FROM login_magic_code
WHERE code = $1
LIMIT 1;

-- name: GetUserLoginMagicCodes :many
SELECT * FROM login_magic_code
WHERE user_id = $1;

-- name: DeleteUserLogicMagicCode :exec
DELETE FROM login_magic_code
WHERE code = $1 AND user_id = $2;

-- name: InsertIntoUserSessionTable :one
INSERT INTO user_session (id, user_id, refresh_token, client_agent, client_ip, client_os, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetUserSessionByID :one
SELECT * FROM user_session
WHERE id = $1
LIMIT 1;

-- name: GetAllActiveSessionsForUser :many
SELECT * FROM user_session
WHERE active = 'true' AND user_id = $1;

-- name: GetAllInactiveSessionsForUser :many
SELECT * FROM user_session
WHERE active = 'false' AND user_id = $1;

-- name: DeleteAllActiveSessionsForUser :exec
DELETE FROM user_session
WHERE active = 'true' AND user_id = $1;

-- name: DeleteAllSessionsForaUser :exec
DELETE FROM user_session
WHERE user_id = $1;

-- name: DeleteUserSessionByID :exec
DELETE FROM user_session
WHERE id = $1;

-- name: UpdateActiveSessionsForUserToInactive :exec
UPDATE user_session
SET active = 'false'
WHERE active = 'true' AND user_id = $1;

-- name: UpdateOneActiveUserSessionToInactive :exec
UPDATE user_session
SET active = 'false'
WHERE id = $1;

-- name: GetAllSessionsForUser :many
SELECT *
FROM user_session
WHERE user_id = $1;

-- name: InsertIntoEmailUpdateVerificationTable :one
INSERT INTO email_update_verification_code (user_id, code, email_address, expiry)
VALUES ($1, $2, $3, $4)
ON CONFLICT (email_address) DO UPDATE
SET user_id = EXCLUDED.user_id, code = EXCLUDED.code, expiry = EXCLUDED.expiry
RETURNING *;

-- name: GetEmailUpdateVerificationCode :one
SELECT * FROM email_update_verification_code
WHERE code = $1 LIMIT 1;

-- name: DeleteEmailUpdateVerificationCode :exec
DELETE FROM email_update_verification_code
WHERE code = $1;