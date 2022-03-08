-- name: CreateChangeEmailCode :one
INSERT INTO change_email (user_id, code, email_address, expiry)
VALUES ($1, $2, $3, $4)
ON CONFLICT (email_address) DO UPDATE
SET user_id = EXCLUDED.user_id, code = EXCLUDED.code, expiry = EXCLUDED.expiry
RETURNING *;

-- name: GetChangeEmailCode :one
SELECT * FROM change_email
WHERE code = $1 LIMIT 1;

-- name: DeleteChangeEmailCode :exec
DELETE FROM change_email
WHERE code = $1;