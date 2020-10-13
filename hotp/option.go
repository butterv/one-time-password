package hotp

import (
	"fmt"

	"github.com/istsh/one-time-password/otpauth"
)

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
		return otpauth.ErrOptionIsNil
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
		return otpauth.ErrOptionIsNil
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
