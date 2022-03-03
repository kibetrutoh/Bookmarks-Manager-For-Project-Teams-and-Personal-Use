package token

import (
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/kibetrutoh/kibetgo/utils"
	"github.com/o1egl/paseto"
)

func CreateToken(userID int, duration time.Time) (string, *Payload, error) {
	payload, err := TokenPayload(userID, duration)
	if err != nil {
		return "", payload, err
	}

	config, err := utils.LoadConfig("/home/kibet/go/organized")
	if err != nil {
		log.Println(err)
		return "", payload, ErrInternalServerError
	}

	footer, err := uuid.NewRandom()
	if err != nil {
		log.Println(err)
		return "", payload, ErrInternalServerError
	}

	token, err := paseto.NewV2().Encrypt([]byte(config.Access_Token_Key), payload, footer)
	return token, payload, err
}

func VerifyToken(token string) (*Payload, error) {
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
