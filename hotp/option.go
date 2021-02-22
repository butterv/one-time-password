package hotp

import (
	"errors"
	"fmt"

	"github.com/butterv/one-time-password/otpauth"
)

// ErrHOTPOptionIsNil is an error when the hotp option is nil
var ErrHOTPOptionIsNil = errors.New("hotp option is nil")

// Option is used when operates the HMAC-based One Time Password
type Option struct {
	// digits is the number of digits
	// The default value is 6
	digits otpauth.Digits
	// algorithm is the hash function to use in the HMAC operation
	// The default value is SHA1
	algorithm otpauth.Algorithm
}

// SetDigits sets the number of digits
func (opt *Option) SetDigits(d otpauth.Digits) error {
	if opt == nil {
		return ErrHOTPOptionIsNil
	}
	if !d.Enabled() {
		return fmt.Errorf("invalid digits. please pass %d or %d", otpauth.DigitsSix, otpauth.DigitsEight)
	}

	opt.digits = d
	return nil
}

// SetAlgorithm sets the hash algorithm
func (opt *Option) SetAlgorithm(a otpauth.Algorithm) error {
	if opt == nil {
		return ErrHOTPOptionIsNil
	}
	if !a.Enabled() {
		return fmt.Errorf("invalid algorithm. please pass any of %d to %d", otpauth.AlgorithmSHA1, otpauth.AlgorithmMD5)
	}

	opt.algorithm = a
	return nil
}

// NewOption generates an option with default values
func NewOption() *Option {
	return &Option{
		digits:    otpauth.DigitsSix,
		algorithm: otpauth.AlgorithmSHA1,
	}
}
