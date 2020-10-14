package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	qrcode "github.com/mdp/qrterminal/v3"

	"github.com/istsh/one-time-password/otpauth"
	"github.com/istsh/one-time-password/totp"
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

	o := totp.NewOption()
	if *option {
		o := totp.NewOption()
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

	fmt.Printf("url:         %s\n", oa.URL())
	fmt.Printf("issuer:      %s\n", *issuer)
	fmt.Printf("accountName: %s\n", *accountName)
	fmt.Printf("secret:      %s\n", oa.Secret())
	fmt.Printf("counter:     %d\n", *counter)
	fmt.Println()

	config := qrcode.Config{
		Level:          qrcode.L,
		Writer:         os.Stdout,
		BlackChar:      qrcode.BLACK,
		BlackWhiteChar: qrcode.BLACK,
		WhiteChar:      qrcode.WHITE,
		WhiteBlackChar: qrcode.WHITE,
		QuietZone:      3,
	}
	qrcode.GenerateWithConfig(oa.URL(), config)
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
	if *option {
		o, err := otpauth.NewOption(*issuer, *accountName, otpauth.HostTOTP)
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
		oa, err = otpauth.GenerateOtpAuth(*issuer, *accountName, otpauth.HostTOTP)
		if err != nil {
			return nil, err
		}
	}

	return oa, nil
}
