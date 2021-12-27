// Code generated by sqlc. DO NOT EDIT.
// source: tenant_user.sql

package sqlc

import (
	"context"

	"github.com/google/uuid"
)

const inviteTenantUser = `-- name: InviteTenantUser :one
INSERT INTO tenant_user (parent_tenant_id, email_address, invitation_token)
VALUES ($1, $2, $3)
RETURNING tenant_user_id, parent_tenant_id, full_name, email_address, hashed_password, access_level, invitation_token, accepted_invite, accepted_invite_on
`

type InviteTenantUserParams struct {
	ParentTenantID  uuid.UUID `json:"parent_tenant_id"`
	EmailAddress    string    `json:"email_address"`
	InvitationToken uuid.UUID `json:"invitation_token"`
}

func (q *Queries) InviteTenantUser(ctx context.Context, arg InviteTenantUserParams) (TenantUser, error) {
	row := q.db.QueryRowContext(ctx, inviteTenantUser, arg.ParentTenantID, arg.EmailAddress, arg.InvitationToken)
	var i TenantUser
	err := row.Scan(
		&i.TenantUserID,
		&i.ParentTenantID,
		&i.FullName,
		&i.EmailAddress,
		&i.HashedPassword,
		&i.AccessLevel,
		&i.InvitationToken,
		&i.AcceptedInvite,
		&i.AcceptedInviteOn,
	)
	return i, err
}
