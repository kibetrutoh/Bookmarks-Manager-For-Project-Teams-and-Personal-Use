-- name: LoginMagicCode :one
INSERT INTO login_magic_code (email_address, magic_code, magic_code_expiry)
VALUES ($1, $2, $3)
ON CONFLICT (magic_code) DO UPDATE
SET email_address = EXCLUDED.email_address, magic_code_expiry = EXCLUDED.magic_code_expiry
RETURNING *;

-- name: GetMagicCode :one
SELECT * FROM login_magic_code
WHERE magic_code = $1
LIMIT 1;

-- name: DeleteMagicCode :exec
DELETE FROM login_magic_code
WHERE magic_code = $1;