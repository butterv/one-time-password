package otpauth

import (
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	// DefaultPeriod is a default value of period
	DefaultPeriod = 30

	defaultScheme     = "otpauth"
	defaultSecretSize = 20
)

// ErrOptionIsNil is an error when the option is nil
var ErrOptionIsNil = errors.New("option is nil")

// ErrInvalidDigitsLength is an error when the digits length unexpected
var ErrInvalidDigitsLength = errors.New("digits length unexpected")

// Host is a host of otpauth
type Host int

const (
	// HostHOTP is a host of HMAC-based One Time Password
	HostHOTP Host = iota
	// HostTOTP is a host of Time-based One Time Password
	HostTOTP
)

func (h Host) enabled() bool {
	return h == HostHOTP || h == HostTOTP
}

func (h Host) name() string {
	switch h {
	case HostHOTP:
		return "hotp"
	case HostTOTP:
		return "totp"
	}

	panic("invalid host")
}

// Digits is the number of digits
type Digits int

const (
	// DigitsSix represents that the digit is 6.
	DigitsSix Digits = 6
	// DigitsEight represents that the digit is 8.
	DigitsEight Digits = 8
)

// Enabled returns a boolean value for whether digits are valid
func (d Digits) Enabled() bool {
	return d == DigitsSix || d == DigitsEight
}

// Length returns the number of digits
func (d Digits) Length() int {
	return int(d)
}

// Format converts from argument to zero-filled characters
func (d Digits) Format(in int32) string {
	switch d {
	case DigitsSix:
		return fmt.Sprintf("%06d", in)
	case DigitsEight:
		return fmt.Sprintf("%08d", in)
	}

	panic("invalid digits")
}

// Algorithm is the hash function to use in the HMAC operation
type Algorithm int

const (
	// AlgorithmSHA1 is a cryptographic hash function of SHA-1
	AlgorithmSHA1 Algorithm = iota
	// AlgorithmSHA256 is a cryptographic hash function of SHA-256
	AlgorithmSHA256
	// AlgorithmSHA512 is a cryptographic hash function of SHA-512
	AlgorithmSHA512
	// AlgorithmMD5 is a cryptographic hash function of MD5
	AlgorithmMD5
)

// Enabled returns a boolean value for whether algorithm are valid
func (a Algorithm) Enabled() bool {
	return a >= AlgorithmSHA1 && a <= AlgorithmMD5
}

func (a Algorithm) name() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}

	panic("invalid algorithm")
}

// Hash returns an initialization function of each hash algorithm
func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}

	panic("invalid algorithm")
}

// Option is used when generates otpauth
type Option struct {
	// issuer is the issuing organization or company
	issuer string
	// accountName is the user's account name
	// e.g. email address
	accountName string
	// period is the seconds that a Time-based One Time Password hash is valid
	// The default value is 30 seconds
	period uint
	// secretSize is a size of the generated Secret
	// The default value is 20 bytes
	secretSize uint
	// secret is a secret that has already been generated
	secret string
	// scheme is an url scheme
	// The default value is `otpauth`
	scheme string
	// host is a host of One Time Password
	// The default value is `totp`
	host Host
	// digits is the number of digits
	// The default value is 6
	digits Digits
	// algorithm is the hash function to use in the HMAC operation
	// The default value is SHA1
	algorithm Algorithm
	// iconURL is the url of icon
	iconURL string
	// rand is the reader to use for generating secret Key.
	// The default value is reader of crypto/rand
	rand io.Reader
}

// SetPeriod sets a period that Time-based One Time Password hash is valid
func (opt *Option) SetPeriod(period uint) error {
	if opt == nil {
		return ErrOptionIsNil
	}
	if period == 0 {
		return errors.New("invalid period. please pass greater than 0")
	}

	opt.period = period
	return nil
}

// SetSecretSize sets a secretSize of the generated Secret
func (opt *Option) SetSecretSize(secretSize uint) error {
	if opt == nil {
		return ErrOptionIsNil
	}
	if secretSize == 0 {
		return errors.New("invalid secretSize. please pass greater than 0")
	}

	opt.secretSize = secretSize
	return nil
}

// Secret returns a secret that option has
func (opt *Option) Secret() string {
	if opt == nil {
		return ""
	}

	return opt.secret
}

// SetSecret sets a secret that has already been generated
func (opt *Option) SetSecret(secret string) error {
	if opt == nil {
		return ErrOptionIsNil
	}

	opt.secret = secret
	return nil
}

// SetDigits sets the number of digits
func (opt *Option) SetDigits(d Digits) error {
	if opt == nil {
		return ErrOptionIsNil
	}
	if !d.Enabled() {
		return fmt.Errorf("invalid digits. please pass %d or %d", DigitsSix, DigitsEight)
	}

	opt.digits = d
	return nil
}

// SetAlgorithm sets the hash algorithm
func (opt *Option) SetAlgorithm(a Algorithm) error {
	if opt == nil {
		return ErrOptionIsNil
	}
	if !a.Enabled() {
		return fmt.Errorf("invalid algorithm. please pass any of %d to %d", AlgorithmSHA1, AlgorithmMD5)
	}

	opt.algorithm = a
	return nil
}

// SetIconURL sets a url of icon
func (opt *Option) SetIconURL(url string) error {
	if opt == nil {
		return ErrOptionIsNil
	}

	opt.iconURL = url
	return nil
}

// NewOption generates an option by passing issuer, account name and host
func NewOption(issuer, accountName string, host Host) (*Option, error) {
	if issuer == "" {
		return nil, errors.New("issuer is empty")
	}
	if accountName == "" {
		return nil, errors.New("accountName is empty")
	}
	if !host.enabled() {
		return nil, fmt.Errorf("invalid host. please pass %d or %d", HostHOTP, HostTOTP)
	}

	return &Option{
		issuer:      issuer,
		accountName: accountName,
		period:      DefaultPeriod,
		secretSize:  defaultSecretSize,
		scheme:      defaultScheme,
		host:        host,
		digits:      DigitsSix,
		algorithm:   AlgorithmSHA1,
		rand:        crand.Reader,
	}, nil
}
