-- name: GetUser :one
SELECT * FROM users
WHERE user_id = $1
LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email_address = $1
LIMIT 1;

-- name: GetUserByVerificationCode :one
SELECT * FROM users
WHERE verification_code = $1
LIMIT 1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY full_name ASC;

-- name: CreateUser :one
INSERT INTO users (user_id, full_name, email_address, hashed_password, verification_code, verificaton_code_expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (email_address) DO UPDATE
SET verification_code = EXCLUDED.verification_code, verificaton_code_expires_at = EXCLUDED.verificaton_code_expires_at, created_at = EXCLUDED.created_at, full_name = EXCLUDED.full_name, hashed_password = EXCLUDED.hashed_password, user_id = EXCLUDED.user_id
RETURNING *;

-- name: UpdateUser :one
UPDATE users
SET full_name = $2, email_address = $3, hashed_password = $4
WHERE user_id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users
WHERE user_id = $1;

-- name: UpdateActiveStatus :exec
UPDATE users
SET active = NOT active
WHERE email_address = $1;

-- name: UpdateRefreshToken :exec
UPDATE users
SET refresh_token_id = $2
WHERE user_id = $1;