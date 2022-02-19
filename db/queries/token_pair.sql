-- name: CreateTokenPair :one
INSERT INTO token_pair(user_id, access_token_id, refresh_token_id)
VALUES ($1, $2, $3)
RETURNING *;
