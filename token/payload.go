package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidToken     = errors.New("token is invalid")
	ErrExpiredToken     = errors.New("token is expired")
	ErrBlacklistedToken = errors.New("token is blacklisted")
)

type Payload struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expired_at"`
}

func AccessTokenPayload(email string) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        tokenID,
		Email:     email,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	return payload, nil
}

func RefreshTokenPayload(email string) (*Payload, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:    tokenID,
		Email: email,
	}

	return payload, nil
}

func (payload *Payload) Valid() error {
	if time.Now().UTC().After(payload.ExpiresAt) {
		return ErrExpiredToken
	}
	return nil
}
