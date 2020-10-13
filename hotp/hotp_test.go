package hotp_test

import (
	"testing"

	"github.com/istsh/one-time-password/hotp"
	"github.com/istsh/one-time-password/otpauth"
)

const (
	secret = "3EOJMVMDTXHMHFQ3CK45R6NWIG4VWAQA"
)

func TestGeneratePasscode(t *testing.T) {
	want := "589662"

	counter := uint64(1)
	got, err := hotp.GeneratePasscode(secret, counter)
	if err != nil {
		t.Fatalf("GeneratePasscode(%s, %d)=_, %#v; want nil", secret, counter, err)
	}
	if got != want {
		t.Errorf("GeneratePasscode(%s, %d)=%s, _; want %s", secret, counter, got, want)
	}
}

func TestGeneratePasscodeWithOption(t *testing.T) {
	want := "38589662"

	o := hotp.NewOption()
	_ = o.SetDigits(otpauth.DigitsEight)

	counter := uint64(1)
	got, err := hotp.GeneratePasscodeWithOption(secret, counter, o)
	if err != nil {
		t.Fatalf("GeneratePasscodeWithOption(%s, %d, %v)=_, %#v; want nil", secret, counter, o, err)
	}
	if got != want {
		t.Errorf("GeneratePasscodeWithOption(%s, %d, %v)=%s, _; want %s", secret, counter, o, got, want)
	}
}

func TestValidate_True(t *testing.T) {
	passcode := "589662"
	counter := uint64(1)
	got, err := hotp.Validate(passcode, secret, counter)
	if err != nil {
		t.Fatalf("Validate(%s, %s, %d)=_, %#v; want nil", passcode, secret, counter, err)
	}
	if !got {
		t.Errorf("Validate(%s, %s, %d)=%v, _; want true", passcode, secret, counter, got)
	}
}

func TestValidate_False(t *testing.T) {
	passcode := "589661"
	counter := uint64(1)
	got, err := hotp.Validate(passcode, secret, counter)
	if err != nil {
		t.Fatalf("Validate(%s, %s, %d)=_, %#v; want nil", passcode, secret, counter, err)
	}
	if got {
		t.Errorf("Validate(%s, %s, %d)=%v, _; want false", passcode, secret, counter, got)
	}
}

func TestValidateWithOption_True(t *testing.T) {
	passcode := "38589662"
	counter := uint64(1)

	o := hotp.NewOption()
	_ = o.SetDigits(otpauth.DigitsEight)

	got, err := hotp.ValidateWithOption(passcode, secret, counter, o)
	if err != nil {
		t.Fatalf("ValidateWithOption(%s, %s, %d, %v)=_, %#v; want nil", passcode, secret, counter, o, err)
	}
	if !got {
		t.Errorf("ValidateWithOption(%s, %s, %d, %v)=%v, _; want true", passcode, secret, counter, o, got)
	}
}

func TestValidateWithOption_False(t *testing.T) {
	passcode := "38589661"
	counter := uint64(1)

	o := hotp.NewOption()
	_ = o.SetDigits(otpauth.DigitsEight)

	got, err := hotp.ValidateWithOption(passcode, secret, counter, o)
	if err != nil {
		t.Fatalf("ValidateWithOption(%s, %s, %d, %v)=_, %#v; want nil", passcode, secret, counter, o, err)
	}
	if got {
		t.Errorf("ValidateWithOption(%s, %s, %d, %v)=%v, _; want false", passcode, secret, counter, o, got)
	}
}
