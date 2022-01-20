-- name: BlacklistToken :exec
INSERT INTO blacklisted_access_tokens (
  token_id
) VALUES (
  $1
);

-- name: BlacklistAccessToken :many
SELECT * FROM blacklisted_access_tokens;
