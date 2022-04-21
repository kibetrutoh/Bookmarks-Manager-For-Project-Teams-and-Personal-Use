package utils

import (
	"math/rand"
	"time"
)

func randomNumber(min, max int32) int32 {
	rand.Seed(time.Now().UnixNano())
	return min + int32(rand.Intn(int(max-min)))
}

func randomStringGen(charSet string, codeLenghth int32) string {
	code := ""
	charSetLenghth := int32(len(charSet))
	for i := int32(0); i < codeLenghth; i++ {
		index := randomNumber(0, charSetLenghth)
		code += string(charSet[index])
	}

	return code
}

func GenerateOTP() string {
	charSet := "ABCDEFGHJKLMNPQRSTUVWXYZ123456789"
	OTP := randomStringGen(charSet, 3) + "-" + randomStringGen(charSet, 3)
	return OTP
}

func GenerateRandomString() string {
	charSet := "ABCDEFGHJKLMNPQRSTUVWXYZ123456789"
	return randomStringGen(charSet, 11)
}
