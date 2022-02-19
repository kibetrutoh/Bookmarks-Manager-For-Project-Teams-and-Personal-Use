package token

import (
	"log"

	"github.com/google/uuid"
	"github.com/kibetrutoh/kibetgo/utils"
	"github.com/o1egl/paseto"
)

func CreateAccessToken(userID int) (string, error) {
	payload, err := AccessTokenPayload(userID)
	if err != nil {
		return "", err
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
		return "", ErrInternalServerError
	}

	footer, err := uuid.NewRandom()
	if err != nil {
		log.Println(err)
		return "", ErrInternalServerError
	}

	return paseto.NewV2().Encrypt([]byte(config.Access_Token_Key), payload, footer)
}

func VerifyAccessToken(token string) (*Payload, error) {
	payload := &Payload{}
	var newFooter string

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
		return nil, ErrInternalServerError
	}

	err = paseto.NewV2().Decrypt(token, []byte(config.Access_Token_Key), payload, &newFooter)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func CreateRefreshToken(userID int) (string, error) {
	payload, err := RefreshTokenPayload(userID)
	if err != nil {
		return "", err
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
		return "", ErrInternalServerError
	}

	footer, err := uuid.NewRandom()
	if err != nil {
		log.Println(err)
		return "", ErrInternalServerError
	}

	return paseto.NewV2().Encrypt([]byte(config.Refresh_Token_Key), payload, footer)
}

func VerifyRefreshToken(token string) (*Payload, error) {
	payload := &Payload{}
	var newFooter string

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
		return nil, ErrInternalServerError
	}

	err = paseto.NewV2().Decrypt(token, []byte(config.Refresh_Token_Key), payload, &newFooter)
	if err != nil {
		return nil, ErrInvalidToken
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}
