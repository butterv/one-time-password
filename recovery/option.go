package recovery

import (
	"errors"
	"fmt"
)

const (
	defaultLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	defaultLength  = 8
	defaultCount   = 8
)

// ErrRecoveryCodeOptionIsNil is an error when the recovery code option is nil
var ErrRecoveryCodeOptionIsNil = errors.New("recovery code option is nil")

// Format is the format of recovery code
type Format int

const (
	// FormatNormal is the normal format of recovery code
	// This format doesn't make any changes to the generated code
	FormatNormal Format = iota
	// FormatSplitByHyphen is the format of recovery code
	// This format splits the generated code by hyphen
	FormatSplitByHyphen
	// FormatSplitBySpace is the format of recovery code
	// This format splits the generated code by space
	FormatSplitBySpace
)

func (f Format) enabled() bool {
	return f >= FormatNormal && f <= FormatSplitBySpace
}

func (f Format) apply(code string) string {
	length := len(code)
	if length == 1 {
		return code
	}

	center := length / 2
	var bh, ah string
	if length%2 == 0 {
		bh, ah = code[:center], code[center:]
	} else {
		bh, ah = code[:center+1], code[center+1:]
	}

	format := "%s%s"
	switch f {
	case FormatSplitByHyphen:
		format = "%s-%s"
	case FormatSplitBySpace:
		format = "%s %s"
	}

	return fmt.Sprintf(format, bh, ah)
}

// Option is used when generates recovery codes
type Option struct {
	// letters is the candidate characters used to generate random string
	letters string
	// length is the length of generated random string
	length uint
	// count is the count of random string
	count uint
	// format is the format of recovery code
	format Format
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

// SetFormat sets a format of recovery code
func (opt *Option) SetFormat(format Format) error {
	if opt == nil {
		return ErrRecoveryCodeOptionIsNil
	}
	if !format.enabled() {
		return fmt.Errorf("invalid format. please pass any of %d to %d", FormatNormal, FormatSplitBySpace)
	}

	opt.format = format
	return nil
}

// NewOption generates an option for generating recovery code
func NewOption() *Option {
	return &Option{
		letters: defaultLetters,
		length:  defaultLength,
		count:   defaultCount,
		format:  FormatNormal,
	}
}
