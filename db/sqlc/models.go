// Code generated by sqlc. DO NOT EDIT.

package sqlc

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

type BlacklistedAccessToken struct {
	TokenID uuid.UUID `json:"token_id"`
}

type EmailVerification struct {
	EmailAddress              string    `json:"email_address"`
	VerificationCode          string    `json:"verification_code"`
	VerificationCodeExpiresAt time.Time `json:"verification_code_expires_at"`
	Verified                  bool      `json:"verified"`
}

type Invite struct {
	EmailAddress   string        `json:"email_address"`
	InvitationCode string        `json:"invitation_code"`
	WorkspaceID    sql.NullInt32 `json:"workspace_id"`
	AccessLevel    string        `json:"access_level"`
}

type User struct {
	ID                int32     `json:"id"`
	FullName          string    `json:"full_name"`
	EmailAddress      string    `json:"email_address"`
	Password          string    `json:"password"`
	PasswordCreatedAt time.Time `json:"password_created_at"`
	PasswordExpiresAt time.Time `json:"password_expires_at"`
	PasswordUpdatedAt time.Time `json:"password_updated_at"`
	Role              string    `json:"role"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	RefreshTokenID    uuid.UUID `json:"refresh_token_id"`
}

type UserProfile struct {
	UserID int32 `json:"user_id"`
}

type Workspace struct {
	UserID       sql.NullInt32  `json:"user_id"`
	ID           int32          `json:"id"`
	Name         string         `json:"name"`
	ProfileImage sql.NullString `json:"profile_image"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	Status       string         `json:"status"`
	Tier         string         `json:"tier"`
}

type WorkspaceUser struct {
	UserID      sql.NullInt32 `json:"user_id"`
	WorkspaceID sql.NullInt32 `json:"workspace_id"`
	AccessLevel string        `json:"access_level"`
	JoinedOn    time.Time     `json:"joined_on"`
}
