package errors

import (
	"errors"
	"fmt"
)

const (
	ErrInternal = "internal"
)

type Error struct {
	code    string
	message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("error: code: %v, message: %v", e.code, e.message)
}

func ErrCode(err error) string {
	var e *Error
	if err == nil {
		return ""
	} else if errors.As(err, &e) {
		return e.code
	}
	return ErrInternal
}

func ErrMessage(err error) string {
	var e *Error
	if err == nil {
		return ""
	} else if errors.As(err, &e) {
		return e.message
	}
	return ErrInternal
}

func Errorf(code string, format string, args ...interface{}) *Error {
	return &Error{
		code:    code,
		message: fmt.Sprintf(format, args...),
	}
}
