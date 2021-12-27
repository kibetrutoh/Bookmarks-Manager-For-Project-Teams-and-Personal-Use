-- name: InviteTenantUser :one
INSERT INTO tenant_user (parent_tenant_id, email_address, invitation_token)
VALUES ($1, $2, $3)
RETURNING *;