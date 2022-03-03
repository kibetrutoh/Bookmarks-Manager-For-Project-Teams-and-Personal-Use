package utils

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	res1, err := HashPassword("Brm/2018/30333")
	if err != nil {
		return
	}

	res2, err := HashPassword("Brm/2018/30333")
	if err != nil {
		return
	}

	if res1 == res2 {
		t.Errorf("results should not be equal")
	}

}
