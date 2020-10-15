package otpauth

import crand "crypto/rand"

var ExportHostEnabled = Host.enabled

var ExportHostName = Host.name

var ExportAlgorithmName = Algorithm.name

func (opt *Option) Period() uint {
	if opt == nil {
		return 0
	}

	return opt.period
}

func (opt *Option) SecretSize() uint {
	if opt == nil {
		return 0
	}

	return opt.secretSize
}

func (opt *Option) Digits() Digits {
	if opt == nil {
		return 0
	}

	return opt.digits
}

func (opt *Option) Algorithm() Algorithm {
	if opt == nil {
		return 0
	}

	return opt.algorithm
}

func (opt *Option) IconURL() string {
	if opt == nil {
		return ""
	}

	return opt.iconURL
}

func DefaultOption() *Option {
	return &Option{
		period:     30,
		secretSize: 20,
		scheme:     "otpauth",
		digits:     6,
		algorithm:  0,
		iconURL:    "",
		rand:       crand.Reader,
	}
}

func DefaultOtpAuth() *OtpAuth {
	return &OtpAuth{
		url:    "TEST_URL",
		secret: "TEST_SECRET",
	}
}
