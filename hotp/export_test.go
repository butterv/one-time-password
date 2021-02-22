package hotp

import "github.com/butterv/one-time-password/otpauth"

func (opt *Option) Digits() otpauth.Digits {
	if opt == nil {
		return 0
	}

	return opt.digits
}

func (opt *Option) Algorithm() otpauth.Algorithm {
	if opt == nil {
		return 0
	}

	return opt.algorithm
}

func DefaultOption() *Option {
	return &Option{
		digits:    6,
		algorithm: 0,
	}
}
