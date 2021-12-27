package token

import (
	"log"

	"github.com/kibetrutoh/kibetgo/utils"
	"github.com/o1egl/paseto"
)

func CreateAccessToken(email string) (string, error) {
	payload, err := AccessTokenPayload(email)
	if err != nil {
		return "", err
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
	}

	footer := "access token footer... footer will be an interface just line payload"

	return paseto.NewV2().Encrypt([]byte(config.Access_Token_Key), payload, footer)
}

func VerifyAccessToken(token string) (*Payload, error) {
	payload := &Payload{}
	var newFooter string

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
	}

	err = paseto.NewV2().Decrypt(token, []byte(config.Access_Token_Key), payload, &newFooter)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// err = payload.Valid()
	// if err != nil {
	// 	return nil, err
	// }

	return payload, nil
}

func CreateRefreshToken(email string) (string, error) {
	payload, err := RefreshTokenPayload(email)
	if err != nil {
		return "", err
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
	}

	footer := "refresh token footer... footer will be an interface just like payload"

	return paseto.NewV2().Encrypt([]byte(config.Refresh_Token_Key), payload, footer)
}

func VerifyRefreshToken(token string) (*Payload, error) {
	paylaod := &Payload{}
	var newFooter string

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
	}

	err = paseto.NewV2().Decrypt(token, []byte(config.Refresh_Token_Key), paylaod, &newFooter)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return paylaod, nil
}
