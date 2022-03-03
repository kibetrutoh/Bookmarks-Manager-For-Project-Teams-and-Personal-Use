package utils

import (
	"crypto/sha256"
	"encoding/base64"
)

func Hmac256Hash(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.StdEncoding.EncodeToString(h[:])
}
