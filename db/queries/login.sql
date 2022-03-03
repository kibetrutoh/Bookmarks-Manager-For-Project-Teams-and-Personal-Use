-- name: CreateLoginMagicCode :one
INSERT INTO login_magic_code (user_id, email_address, code, code_expiry)
VALUES ($1, $2, $3, $4)
ON CONFLICT (code) DO UPDATE
SET email_address = EXCLUDED.email_address, code_expiry = EXCLUDED.code_expiry
RETURNING *;

-- name: GetMagicCode :one
SELECT * FROM login_magic_code
WHERE code = $1
LIMIT 1;

-- name: GetAllUserLoginMagicCodes :many
SELECT * FROM login_magic_code
WHERE email_address = $1;

-- name: DeleteMagicCode :exec
DELETE FROM login_magic_code
WHERE code = $1 AND email_address = $2;