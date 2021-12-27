-- name: CreateTenant :one
INSERT INTO tenant (
  tenant_name, project_name, user_id
) VALUES (
  $1, $2, $3
)
RETURNING *;

-- name: GetTenant :one
SELECT * FROM tenant
WHERE tenant_id = $1 LIMIT 1;

-- name: GetTenantByUsedID :one
SELECT * FROM tenant
WHERE user_id = $1 LIMIT 1;

-- name: UpdateTenant :one
UPDATE tenant
SET tenant_name = $2, project_name = $3
WHERE tenant_id = $1
RETURNING *;