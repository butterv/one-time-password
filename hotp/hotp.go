package hotp

import (
	"crypto/hmac"
	"encoding/base32"
	"encoding/binary"
	"math"
	"strings"

	"github.com/butterv/one-time-password/otpauth"
)

// GeneratePasscode generates a passcode with using default value of option
func GeneratePasscode(secret string, counter uint64) (string, error) {
	opt := NewOption()
	return GeneratePasscodeWithOption(secret, counter, opt)
}

// GeneratePasscodeWithOption generates a passcode
// This function can pass custom value of option
// When this executes, it returns a HMAC-based One Time Password
// See: https://tools.ietf.org/html/rfc4226#section-5.2
func GeneratePasscodeWithOption(secret string, counter uint64, opt *Option) (string, error) {
	// secret = strings.ToUpper(secret)
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}

	hs, err := hmacSHA1(secretBytes, counter, opt)
	if err != nil {
		return "", err
	}

	return dynamicTruncation(hs, opt)
}

// See: https://tools.ietf.org/html/rfc4226#section-5.3
// Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)
func hmacSHA1(secretBytes []byte, counter uint64, opt *Option) ([]byte, error) {
	cb := make([]byte, 8)
	binary.BigEndian.PutUint64(cb, counter)

	mac := hmac.New(opt.algorithm.Hash, secretBytes)
	_, err := mac.Write(cb)
	if err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

// See: http://tools.ietf.org/html/rfc4226#section-5.4
func dynamicTruncation(hs []byte, opt *Option) (string, error) {
	offset := hs[len(hs)-1] & 0xf
	binCode := int64(((int(hs[offset]) & 0x7f) << 24) |
		((int(hs[offset+1] & 0xff)) << 16) |
		((int(hs[offset+2] & 0xff)) << 8) |
		(int(hs[offset+3]) & 0xff))

	l := opt.digits.Length()
	mod := int32(binCode % int64(math.Pow10(l)))
	return opt.digits.Format(mod), nil
}

// Validate validates a HMAC-based One Time Password with using default value of option
func Validate(passcode string, secret string, counter uint64) (bool, error) {
	opt := NewOption()
	return ValidateWithOption(passcode, secret, counter, opt)
}

// ValidateWithOption validates a HMAC-based One Time Password
// This function can pass custom value of option
func ValidateWithOption(passcode string, secret string, counter uint64, opt *Option) (bool, error) {
	if len(passcode) != opt.digits.Length() {
		return false, otpauth.ErrInvalidDigitsLength
	}

	otpstr, err := GeneratePasscodeWithOption(secret, counter, opt)
	if err != nil {
		return false, err
	}

	if strings.Compare(otpstr, passcode) == 0 {
		return true, nil
	}

	return false, nil
}
