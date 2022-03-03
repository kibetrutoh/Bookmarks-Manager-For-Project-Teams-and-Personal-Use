package utils

import (
	"reflect"
	"testing"
)

func TestRandomNumber(t *testing.T) {
	got := randomNumber(6, 9)
	want := int32(8)
	if reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Errorf("expected :%v but got :%v", reflect.TypeOf(want), reflect.TypeOf(got))
	}
}
