-- name: CreateDashboard :one
INSERT INTO dashboard (id, dashboard_name, dashboard_admin)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateDashboardName :one
UPDATE dashboard
SET dashboard_name = $3
WHERE id = $1 AND dashboard_admin = $2
RETURNING *;

-- name: GetAllDashboards :many
SELECT * FROM dashboard;