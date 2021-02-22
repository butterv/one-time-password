package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/butterv/one-time-password/otpauth"
	"github.com/butterv/one-time-password/totp"
)

const qrCodeSize = 256

var (
	issuer      = flag.String("issuer", "example.com", "the issuing organization or company")
	accountName = flag.String("accountName", "butter@example.com", "the user's account name or email address")
	option      = flag.Bool("option", false, "the flag of using custom option")
	period      = flag.Uint("period", 0, "the seconds that a one time password is valid")
	skew        = flag.Uint("skew", 0, "verifies one time password by expanding the counter back and forth by this value only")
	secretSize  = flag.Uint("secretSize", 0, "the size of the secret")
	secret      = flag.String("secret", "", "sets the generated secret")
	digits      = flag.Int("digits", 0, "the number of digits")
	algorithm   = flag.Int("algorithm", 0, "the hash function to use in the HMAC operation")
)

func main() {
	flag.Parse()

	oa, err := newOtpAuth()
	if err != nil {
		panic(err)
	}

	o := totp.NewOption()
	if *option {
		if *period > 0 {
			err = o.SetPeriod(*period)
			if err != nil {
				panic(err)
			}
		}
		if *skew > 0 {
			err = o.SetSkew(*skew)
			if err != nil {
				panic(err)
			}
		}
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

	qr, err := qrcode.New(oa.URL(), qrcode.Medium)
	if err != nil {
		panic(err)
	}
	_ = qr.WriteFile(qrCodeSize, "qrcode.png")

	data, _ := oa.QRCode()
	fmt.Printf("url:         %s\n", oa.URL())
	fmt.Printf("data:        %s\n", data)
	fmt.Printf("issuer:      %s\n", *issuer)
	fmt.Printf("accountName: %s\n", *accountName)
	fmt.Printf("secret:      %s\n", oa.Secret())
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter Passcode: ")
	for scanner.Scan() {
		passcode := scanner.Text()
		ok, err := totp.ValidateWithOption(passcode, oa.Secret(), time.Now(), o)
		if err != nil {
			panic(err)
		}
		fmt.Printf("matched:        %v\n", ok)
		fmt.Print("Enter Passcode: ")
	}

	fmt.Println("finish!")
}

func newOtpAuth() (oa *otpauth.OtpAuth, err error) {
	o, err := otpauth.NewOption()
	if err != nil {
		return nil, err
	}

	if *option {
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
	}

	oa, err = otpauth.GenerateOtpAuthWithOption(*issuer, *accountName, otpauth.HostTOTP, o)
	if err != nil {
		return nil, err
	}

	return oa, nil
}
