package totp

import (
	"math"
	"time"

	"github.com/istsh/one-time-password/hotp"
)

// Validate validates a Time-based One Time Password with using default value of option
func Validate(passcode, secret string, t time.Time) (bool, error) {
	opt := NewOption()
	return ValidateWithOption(passcode, secret, t, opt)
}

// ValidateWithOption validates a Time-based One Time Password
// This function can pass custom value of option
// See: https://tools.ietf.org/html/rfc6238#section-4.2
func ValidateWithOption(passcode, secret string, t time.Time, opt *Option) (bool, error) {
	hotpOpt := hotp.NewOption()
	_ = hotpOpt.SetDigits(opt.digits)
	_ = hotpOpt.SetAlgorithm(opt.algorithm)

	cs := counters(t, opt)
	for _, c := range cs {
		ok, err := hotp.ValidateWithOption(passcode, secret, c, hotpOpt)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

func counters(t time.Time, opt *Option) []uint64 {
	var cs []uint64
	c := uint64(math.Floor(float64(t.Unix()) / float64(opt.period)))

	cs = append(cs, c)
	for i := 1; i <= int(opt.skew); i++ {
		cs = append(cs, c+uint64(i))
		cs = append(cs, c-uint64(i))
	}

	return cs
}
