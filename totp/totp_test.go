package totp_test

import (
	"testing"
	"time"

	"github.com/istsh/one-time-password/otpauth"
	"github.com/istsh/one-time-password/totp"
)

const (
	secret = "3EOJMVMDTXHMHFQ3CK45R6NWIG4VWAQA"
)

func TestValidate_True(t *testing.T) {
	passcode := "662024"
	ti := time.Date(2020, 10, 1, 0, 0, 0, 0, time.UTC)
	got, err := totp.Validate(passcode, secret, ti)
	if err != nil {
		t.Fatalf("Validate(%s, %s, %v)=_, %#v; want nil", passcode, secret, ti, err)
	}
	if !got {
		t.Errorf("Validate(%s, %s, %v)=%v, _; want true", passcode, secret, ti, got)
	}
}

func TestValidate_False(t *testing.T) {
	passcode := "662023"
	ti := time.Date(2020, 10, 1, 0, 0, 0, 0, time.UTC)
	got, err := totp.Validate(passcode, secret, ti)
	if err != nil {
		t.Fatalf("Validate(%s, %s, %v)=_, %#v; want nil", passcode, secret, ti, err)
	}
	if got {
		t.Errorf("Validate(%s, %s, %v)=%v, _; want false", passcode, secret, ti, got)
	}
}

func TestValidateWithOption_True(t *testing.T) {
	passcode := "95662024"
	ti := time.Date(2020, 10, 1, 0, 0, 0, 0, time.UTC)

	o := totp.NewOption()
	_ = o.SetDigits(otpauth.DigitsEight)

	got, err := totp.ValidateWithOption(passcode, secret, ti, o)
	if err != nil {
		t.Fatalf("ValidateWithOption(%s, %s, %v, %v)=_, %#v; want nil", passcode, secret, ti, o, err)
	}
	if !got {
		t.Errorf("ValidateWithOption(%s, %s, %v, %v)=%v, _; want true", passcode, secret, ti, o, got)
	}
}

func TestValidateWithOption_False(t *testing.T) {
	passcode := "95662023"
	ti := time.Date(2020, 10, 1, 0, 0, 0, 0, time.UTC)

	o := totp.NewOption()
	_ = o.SetDigits(otpauth.DigitsEight)

	got, err := totp.ValidateWithOption(passcode, secret, ti, o)
	if err != nil {
		t.Fatalf("ValidateWithOption(%s, %s, %v, %v)=_, %#v; want nil", passcode, secret, ti, o, err)
	}
	if got {
		t.Errorf("ValidateWithOption(%s, %s, %v, %v)=%v, _; want true", passcode, secret, ti, o, got)
	}
}
