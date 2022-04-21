package token_default

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"errors"
)

var (
	errHashUnavaliable = errors.New("Hash unavailable.")
)

func hmacSign(data string, key string) (string, error) {
	if !crypto.SHA1.Available() {
		return "", errHashUnavaliable
	}

	hasher := hmac.New(crypto.SHA1.New, []byte(key))
	hasher.Write([]byte(data))

	code := hasher.Sum(nil)

	return base64.URLEncoding.EncodeToString(code), nil
}

func hmacVerify(data, sign string, key string) error {
	if !crypto.SHA1.Available() {
		return errHashUnavaliable
	}

	sig, err := base64.URLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	hasher := hmac.New(crypto.SHA1.New, []byte(key))
	hasher.Write([]byte(data))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return errHashUnavaliable
	}

	return nil
}
