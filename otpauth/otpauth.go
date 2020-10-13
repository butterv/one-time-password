package otpauth

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// OtpAuth has an optauth url and a secret key
type OtpAuth struct {
	url    string
	secret string
}

// URL returns an url that is included in otpAuth
func (oa *OtpAuth) URL() string {
	if oa == nil {
		return ""
	}

	return oa.url
}

// Secret returns a secret that is included in otpAuth
func (oa *OtpAuth) Secret() string {
	if oa == nil {
		return ""
	}

	return oa.secret
}

// GenerateOtpAuth generates an otpAuth by passing issuer and account name
func GenerateOtpAuth(issuer, accountName string) (*OtpAuth, error) {
	opt, err := NewOption(issuer, accountName)
	if err != nil {
		return nil, err
	}

	return GenerateOtpAuthWithOption(opt)
}

// GenerateOtpAuthWithOption generates an otpAuth by passing issuer, account name and option
func GenerateOtpAuthWithOption(opt *Option) (*OtpAuth, error) {
	secretBytes := make([]byte, opt.secretSize)
	_, err := opt.rand.Read(secretBytes)
	if err != nil {
		return nil, err
	}

	secret := base32NoPadding.EncodeToString(secretBytes)
	u := newURL(opt, secret)

	return &OtpAuth{
		url:    u.String(),
		secret: secret,
	}, nil
}

func newURL(opt *Option, secret string) url.URL {
	v := url.Values{}
	v.Set("issuer", opt.issuer)
	v.Set("period", strconv.FormatUint(uint64(opt.period), 10))
	v.Set("algorithm", opt.algorithm.name())
	v.Set("digits", fmt.Sprintf("%d", opt.digits))
	v.Set("secret", secret)

	if opt.iconURL != "" {
		v.Set("icon", opt.iconURL)
	}

	return url.URL{
		Scheme:   opt.scheme,
		Host:     opt.host.name(),
		Path:     fmt.Sprintf("/%s:%s", opt.issuer, opt.accountName),
		RawQuery: v.Encode(),
	}
}
