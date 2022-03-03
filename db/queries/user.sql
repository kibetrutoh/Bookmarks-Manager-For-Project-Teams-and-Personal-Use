-- name: CreateVerifyEmail :one
INSERT INTO email_verification (email_address, verification_code, verification_code_expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (email_address) DO UPDATE
SET verification_code = EXCLUDED.verification_code, verification_code_expires_at = EXCLUDED.verification_code_expires_at
RETURNING *;

-- name: GetEmailByVerificationCode :one
SELECT * FROM email_verification
WHERE verification_code = $1
LIMIT 1;

-- name: DeleteEmail :exec
DELETE FROM email_verification
WHERE verification_code = $1;

-- name: CreateUser :one
INSERT INTO users (full_name, email_address, password)
VALUES ($1, $2, $3)
ON CONFLICT (email_address) DO UPDATE
SET full_name = EXCLUDED.full_name, password = EXCLUDED.password
RETURNING *;

-- name: GetUser :one
SELECT * FROM users
WHERE id = $1
LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email_address = $1
LIMIT 1;

-- name: GetAllUsers :many
SELECT * FROM users
ORDER BY full_name ASC;

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

-- name: UpdateUserPassword :one
UPDATE users
SET password = $2
WHERE id = $1
RETURNING *;

-- name: DeleteUserAccount :exec
DELETE FROM users
WHERE id = $1;