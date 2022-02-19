package utils

import (
	"crypto/sha1"
	"encoding/base64"
)

func Hash(value string) string {
	h := sha1.New()
	h.Write([]byte(value))
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return hash
}
