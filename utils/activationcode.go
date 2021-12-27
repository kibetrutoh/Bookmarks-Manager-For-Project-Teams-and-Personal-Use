package utils

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// function to hash password using bcrypt
func HashActivationCode(activationCode string) (string, error) {
	hashedActivationCode, err := bcrypt.GenerateFromPassword([]byte(activationCode), 16)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedActivationCode), err
}

func CheckActivationCodeHash(eVerificationCode, hashedActivationCode string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedActivationCode), []byte(eVerificationCode))
	return err == nil
}
