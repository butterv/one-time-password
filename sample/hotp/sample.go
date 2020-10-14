package main

import (
	"flag"
	"fmt"

	"github.com/istsh/one-time-password/hotp"
	"github.com/istsh/one-time-password/otpauth"
)

var (
	issuer      = flag.String("issuer", "example.com", "")
	accountName = flag.String("accountName", "istsh@example.com", "")
	option      = flag.Bool("option", false, "")
	period      = flag.Uint("period", 0, "")
	secretSize  = flag.Uint("secretSize", 0, "")
	secret      = flag.String("secret", "", "")
	digits      = flag.Int("digits", 0, "")
	algorithm   = flag.Int("algorithm", 0, "")
	counter     = flag.Uint64("counter", 1, "")
)

func main() {
	flag.Parse()

	oa, err := newOtpAuth()
	if err != nil {
		panic(err)
	}

	var otp string
	var ok bool
	if *option {
		o := hotp.NewOption()
		if *digits != 0 {
			err = o.SetDigits(otpauth.Digits(*digits))
			if err != nil {
				panic(err)
			}
		}
		if *algorithm != 0 {
			err = o.SetAlgorithm(otpauth.Algorithm(*algorithm))
			if err != nil {
				panic(err)
			}
		}

		otp, err = hotp.GeneratePasscodeWithOption(oa.Secret(), *counter, o)
		if err != nil {
			panic(err)
		}

		ok, err = hotp.ValidateWithOption(otp, oa.Secret(), *counter, o)
		if err != nil {
			panic(err)
		}
	} else {
		otp, err = hotp.GeneratePasscode(oa.Secret(), *counter)
		if err != nil {
			panic(err)
		}

		ok, err = hotp.Validate(otp, oa.Secret(), *counter)
		if err != nil {
			panic(err)
		}
	}

	fmt.Printf("url:         %s\n", oa.URL())
	fmt.Printf("issuer:      %s\n", *issuer)
	fmt.Printf("accountName: %s\n", *accountName)
	fmt.Printf("secret:      %s\n", oa.Secret())
	fmt.Printf("counter:     %d\n", *counter)
	fmt.Printf("passcode:    %s\n", otp)
	fmt.Printf("matched:     %v\n", ok)
}

func newOtpAuth() (oa *otpauth.OtpAuth, err error) {
	if *option {
		o, err := otpauth.NewOption(*issuer, *accountName, otpauth.HostHOTP)
		if err != nil {
			return nil, err
		}

		if *period > 0 {
			_ = o.SetPeriod(*period)
		}
		if *secretSize > 0 {
			_ = o.SetSecretSize(*secretSize)
		}
		if len(*secret) > 0 {
			_ = o.SetSecret(*secret)
		}
		if *digits != 0 {
			_ = o.SetDigits(otpauth.Digits(*digits))
		}
		if *algorithm != 0 {
			_ = o.SetAlgorithm(otpauth.Algorithm(*algorithm))
		}

		oa, err = otpauth.GenerateOtpAuthWithOption(o)
		if err != nil {
			return nil, err
		}
	} else {
		oa, err = otpauth.GenerateOtpAuth(*issuer, *accountName, otpauth.HostHOTP)
		if err != nil {
			return nil, err
		}
	}

	return oa, nil
}
