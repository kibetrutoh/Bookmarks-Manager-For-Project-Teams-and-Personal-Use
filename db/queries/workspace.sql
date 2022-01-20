-- name: CreateWorkspace :one
INSERT INTO workspace (user_id, name)
VALUES ($1, $2)
RETURNING *;

-- name: UpdateWorkspace :one
UPDATE workspace
SET name = $2
WHERE id = $1
RETURNING *;