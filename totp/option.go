package totp

import (
	"errors"
	"fmt"

	"github.com/butterv/one-time-password/otpauth"
)

const (
	defaultSkew = uint(1)
)

// ErrTOTPOptionIsNil is an error when the totp option is nil
var ErrTOTPOptionIsNil = errors.New("totp option is nil")

// Option is used when operates the Time-based One Time Password
type Option struct {
	// period is the seconds that a Time-based One Time Password hash is valid
	// The default value is 30 seconds
	period uint
	// skew verifies one time password by expanding the counter back and forth by this value only
	// This considers any possible synchronization delay between the server and the client that generates the one time password
	// The default value is 1
	skew uint
	// digits is the number of digits
	// The default value is 6
	digits otpauth.Digits
	// algorithm is the hash function to use in the HMAC operation
	// The default value is SHA1
	algorithm otpauth.Algorithm
}

// SetPeriod sets a period that Time-based One Time Password hash is valid
func (opt *Option) SetPeriod(period uint) error {
	if opt == nil {
		return ErrTOTPOptionIsNil
	}
	if period == 0 {
		return errors.New("invalid period. please pass greater than 0")
	}

	opt.period = period
	return nil
}

// SetSkew sets a skew
func (opt *Option) SetSkew(skew uint) error {
	if opt == nil {
		return ErrTOTPOptionIsNil
	}
	if skew == 0 {
		return errors.New("invalid skew. please pass greater than 0")
	}

	opt.skew = skew
	return nil
}

// SetDigits sets the number of digits
func (opt *Option) SetDigits(d otpauth.Digits) error {
	if opt == nil {
		return ErrTOTPOptionIsNil
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
		return ErrTOTPOptionIsNil
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
		period:    otpauth.DefaultPeriod,
		skew:      defaultSkew,
		digits:    otpauth.DigitsSix,
		algorithm: otpauth.AlgorithmSHA1,
	}
}
