-- name: CreateWorkspace :one
INSERT INTO workspace (
  workspace_name, project_name, user_id
) VALUES (
  $1, $2, $3
)
RETURNING *;

-- name: GetWorkspace :one
SELECT * FROM workspace
WHERE workspace_id = $1 LIMIT 1;

-- name: GetWorkspaceByUsedID :one
SELECT * FROM workspace
WHERE user_id = $1 LIMIT 1;

-- name: UpdateWorkspace :one
UPDATE workspace
SET workspace_name = $2, project_name = $3
WHERE workspace_id = $1
RETURNING *;

-- name: GetWorkspacesByUserID :many
SELECT * FROM workspace
WHERE user_id = $1
ORDER BY workspace_name ASC;