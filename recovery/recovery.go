package recovery

import (
	crand "crypto/rand"
	"math/big"
)

// GenerateRecoveryCodes generates recovery codes
func GenerateRecoveryCodes() ([]string, error) {
	opt := NewOption()
	return GenerateRecoveryCodesWithOption(opt)
}

// GenerateRecoveryCodesWithOption generates recovery codes by passing option.
func GenerateRecoveryCodesWithOption(opt *Option) ([]string, error) {
	if opt == nil {
		return nil, ErrRecoveryCodeOptionIsNil
	}

	var codes []string
	for i := uint(0); i < opt.count; i++ {
		code, err := cryptoRandString(opt.letters, opt.length)
		if err != nil {
			return nil, err
		}
		codes = append(codes, opt.format.apply(code))
	}

	return codes, nil
}

func cryptoRandString(letters string, length uint) (string, error) {
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
