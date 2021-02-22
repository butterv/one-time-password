package main

import (
	"flag"
	"fmt"

	"github.com/butterv/one-time-password/hotp"
	"github.com/butterv/one-time-password/otpauth"
)

var (
	issuer      = flag.String("issuer", "example.com", "the issuing organization or company")
	accountName = flag.String("accountName", "butter@example.com", "the user's account name or email address")
	option      = flag.Bool("option", false, "the flag of using custom option")
	secretSize  = flag.Uint("secretSize", 0, "the size of the secret")
	secret      = flag.String("secret", "", "sets the generated secret")
	digits      = flag.Int("digits", 0, "the number of digits")
	algorithm   = flag.Int("algorithm", 0, "the hash function to use in the HMAC operation")
	counter     = flag.Uint64("counter", 1, "verify the password for this counter")
)

func main() {
	flag.Parse()

	oa, err := newOtpAuth()
	if err != nil {
		panic(err)
	}

	o := hotp.NewOption()
	if *option {
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
	}

	otp, err := hotp.GeneratePasscodeWithOption(oa.Secret(), *counter, o)
	if err != nil {
		panic(err)
	}

	ok, err := hotp.ValidateWithOption(otp, oa.Secret(), *counter, o)
	if err != nil {
		panic(err)
	}

	data, _ := oa.QRCode()
	fmt.Printf("url:         %s\n", oa.URL())
	fmt.Printf("data:        %s\n", data)
	fmt.Printf("issuer:      %s\n", *issuer)
	fmt.Printf("accountName: %s\n", *accountName)
	fmt.Printf("secret:      %s\n", oa.Secret())
	fmt.Printf("counter:     %d\n", *counter)
	fmt.Printf("passcode:    %s\n", otp)
	fmt.Printf("matched:     %v\n", ok)
}

func newOtpAuth() (oa *otpauth.OtpAuth, err error) {
	o, err := otpauth.NewOption()
	if err != nil {
		return nil, err
	}

	if *option {
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
	}

	oa, err = otpauth.GenerateOtpAuthWithOption(*issuer, *accountName, otpauth.HostHOTP, o)
	if err != nil {
		return nil, err
	}

	return oa, nil
}
