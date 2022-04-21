-- name: CreateAdmin :one
INSERT INTO administrator (name, password)
VALUES ($1, $2)
RETURNING *;

-- name: GetAdmin :one
SELECT * FROM administrator
WHERE id = $1
LIMIT 1;

-- name: UpdateAdminName :one
UPDATE administrator
SET name = $2
WHERE id = $1
RETURNING *;

-- name: UpdateAdminEmail :one
UPDATE administrator
SET email_address = $2
WHERE id = $1
RETURNING *;

-- name: UpdateAdminPassword :one
UPDATE administrator
SET password = $2
WHERE id = $1
RETURNING *;

-- name: DeleteAdminAccount :exec
DELETE FROM administrator
WHERE id = $1;