-- name: InviteWorkspaceUser :one
INSERT INTO workspace_user (email_address, workspace_id, access_level, invitation_token)
VALUES ($1, $2, $3, $4)
ON CONFLICT (email_address) DO UPDATE
SET workspace_id = EXCLUDED.workspace_id, invitation_token = EXCLUDED.invitation_token
RETURNING *;

-- name: GetWorkspaceUserByInvitationToken :one
SELECT * FROM workspace_user
WHERE invitation_token = $1
LIMIT 1;

-- name: UpdateWorkspaceUser :one
UPDATE workspace_user
SET full_name = $2, hashed_password = $3
WHERE workspace_user_id = $1
RETURNING *;

-- name: UpdateAcceptedInvitationStatus :exec
UPDATE workspace_user
SET accepted_invitation = NOT accepted_invitation
WHERE workspace_user_id = $1;

-- name: GetWorkspaceUser :one
SELECT * FROM workspace_user
WHERE workspace_user_id = $1
LIMIT 1;

-- name: DeleteWorkspaceUser :exec
DELETE FROM workspace_user
WHERE workspace_user_id = $1;

-- name: GetWorkspaceUsersByWorspaceID :many
SELECT * FROM workspace_user
WHERE workspace_id = $1
ORDER BY full_name ASC;