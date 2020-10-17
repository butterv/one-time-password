package otpauth

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/skip2/go-qrcode"
)

const qrCodeSize = 256

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

// QRCode returns value is the base64 encoded image data
func (oa *OtpAuth) QRCode() (string, error) {
	qr, err := qrcode.New(oa.URL(), qrcode.Medium)
	if err != nil {
		return "", err
	}

	bytes, err := qr.PNG(qrCodeSize)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s", "data:image/png;base64,", base64.StdEncoding.EncodeToString(bytes)), nil
}

// GenerateOtpAuth generates an otpAuth by passing issuer, account name and host
func GenerateOtpAuth(issuer, accountName string, host Host) (*OtpAuth, error) {
	opt, err := NewOption()
	if err != nil {
		return nil, err
	}

	return GenerateOtpAuthWithOption(issuer, accountName, host, opt)
}

// GenerateOtpAuthWithOption generates an otpAuth by passing option
func GenerateOtpAuthWithOption(issuer, accountName string, host Host, opt *Option) (*OtpAuth, error) {
	err := validate(issuer, accountName, host)
	if err != nil {
		return nil, err
	}

	secret := opt.Secret()
	if len(secret) == 0 {
		secretBytes := make([]byte, opt.secretSize)
		_, err := opt.rand.Read(secretBytes)
		if err != nil {
			return nil, err
		}
		secret = base32NoPadding.EncodeToString(secretBytes)
	}

	v := url.Values{}
	v.Set("issuer", issuer)
	v.Set("period", strconv.FormatUint(uint64(opt.period), 10))
	v.Set("algorithm", opt.algorithm.name())
	v.Set("digits", fmt.Sprintf("%d", opt.digits))
	v.Set("secret", secret)

	if opt.iconURL != "" {
		v.Set("icon", opt.iconURL)
	}

	u := url.URL{
		Scheme:   opt.scheme,
		Host:     host.name(),
		Path:     fmt.Sprintf("/%s:%s", issuer, accountName),
		RawQuery: v.Encode(),
	}

	return &OtpAuth{
		url:    u.String(),
		secret: secret,
	}, nil
}

func validate(issuer, accountName string, host Host) error {
	if issuer == "" {
		return errors.New("issuer is empty")
	}
	if accountName == "" {
		return errors.New("accountName is empty")
	}
	if !host.enabled() {
		return fmt.Errorf("invalid host. please pass %d or %d", HostHOTP, HostTOTP)
	}

	return nil
}
