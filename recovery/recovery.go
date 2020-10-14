package recovery

import (
	crand "crypto/rand"
	"errors"
	"math/big"
)

const (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// GenerateRecoveryCodes generates recovery codes.
func GenerateRecoveryCodes(length, count uint) ([]string, error) {
	if length == 0 {
		return nil, errors.New("invalid length. please pass greater than 0")
	}
	if count == 0 {
		return nil, errors.New("invalid count. please pass greater than 0")
	}

	var codes []string
	for i := uint(0); i < count; i++ {
		code, err := cryptoRandString(length)
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}

	return codes, nil
}

func cryptoRandString(length uint) (string, error) {
	b := make([]byte, length)
	n := big.NewInt(int64(len(letters)))
	for i := range b {
		x, err := crand.Int(crand.Reader, n)
		if err != nil {
			return "", err
		}

		b[i] = letters[int(x.Int64())]
	}

	return string(b), nil
}
