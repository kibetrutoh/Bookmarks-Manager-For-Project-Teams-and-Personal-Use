-- name: CreateUserSession :one
INSERT INTO user_sessions (id, user_id, refresh_token, client_agent, client_ip, client_os, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetUserSessionByID :one
SELECT * FROM user_sessions
WHERE id = $1
LIMIT 1;

-- name: GetAllActiveSessionsForUser :many
SELECT * FROM user_sessions
WHERE active = 'true' AND user_id = $1;

-- name: GetAllInactiveSessionsForUser :many
SELECT * FROM user_sessions
WHERE active = 'false' AND user_id = $1;

-- name: DeleteAllActiveSessionsForUser :exec
DELETE FROM user_sessions
WHERE active = 'true' AND user_id = $1;

-- name: DeleteAllSessionsForaUser :exec
DELETE FROM user_sessions
WHERE user_id = $1;

-- name: DeleteUserSessionByID :exec
DELETE FROM user_sessions
WHERE id = $1;

-- name: UpdateActiveSessionsForUserToInactive :exec
UPDATE user_sessions
SET active = 'false'
WHERE active = 'true' AND user_id = $1;

-- name: UpdateOneActiveUserSessionToInactive :exec
UPDATE user_sessions
SET active = 'false'
WHERE id = $1;

-- name: GetAllSessionsForUser :many
SELECT *
FROM user_sessions
WHERE user_id = $1;