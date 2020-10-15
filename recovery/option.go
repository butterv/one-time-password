package recovery

import "errors"

const (
	defaultLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	defaultLength  = 8
	defaultCount   = 8
)

// ErrRecoveryCodeOptionIsNil is an error when the recovery code option is nil
var ErrRecoveryCodeOptionIsNil = errors.New("recovery code option is nil")

// Option is used when generates recovery codes
type Option struct {
	// letters is the candidate characters used to generate random string
	letters string
	// length is the length of generated random string
	length uint
	// count is the count of random string
	count uint
}

// SetLetters sets letters that used to generate random string
func (opt *Option) SetLetters(letters string) error {
	if opt == nil {
		return ErrRecoveryCodeOptionIsNil
	}
	if len(letters) == 0 {
		return errors.New("letters is empty")
	}

	opt.letters = letters
	return nil
}

// SetLength sets a length of generated random string
func (opt *Option) SetLength(length uint) error {
	if opt == nil {
		return ErrRecoveryCodeOptionIsNil
	}
	if length == 0 {
		return errors.New("invalid length. please pass greater than 0")
	}

	opt.length = length
	return nil
}

// SetCount sets a count of random string
func (opt *Option) SetCount(count uint) error {
	if opt == nil {
		return ErrRecoveryCodeOptionIsNil
	}
	if count == 0 {
		return errors.New("invalid count. please pass greater than 0")
	}

	opt.count = count
	return nil
}

// NewOption generates an option for generating recovery code
func NewOption() *Option {
	return &Option{
		letters: defaultLetters,
		length:  defaultLength,
		count:   defaultCount,
	}
}
