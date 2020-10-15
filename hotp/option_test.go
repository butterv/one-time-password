package hotp_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/istsh/one-time-password/hotp"
	"github.com/istsh/one-time-password/otpauth"
)

func TestOption_SetDigits(t *testing.T) {
	want := otpauth.DigitsSix

	digits := otpauth.DigitsSix
	o := &hotp.Option{}
	err := o.SetDigits(digits)
	if err != nil {
		t.Fatalf("SetDigits(%d)=%#v; want nil, receiver %#v", digits, err, o)
	}
	if got := o.Digits(); got != want {
		t.Errorf("digits: got %d, want %d, receiver %#v", got, want, o)
	}
}

func TestOption_SetDigits_ErrOptionIsNil(t *testing.T) {
	wantErr := hotp.ErrHOTPOptionIsNil

	digits := otpauth.DigitsSix
	var o *hotp.Option
	err := o.SetDigits(digits)
	if err == nil {
		t.Fatalf("SetDigits(%d)=nil; want %v, receiver nil", digits, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetDigits(%d)=%#v; want %v, receiver nil", digits, err, wantErr)
	}
}

func TestOption_SetDigits_InvalidDigits(t *testing.T) {
	wantErr := errors.New("invalid digits. please pass 6 or 8")

	digits := otpauth.Digits(0)
	o := &hotp.Option{}
	err := o.SetDigits(digits)
	if err == nil {
		t.Fatalf("SetDigits(%d)=nil; want %v, receiver nil", digits, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetDigits(%d)=%#v; want %v, receiver nil", digits, err, wantErr)
	}
}

func TestOption_SetAlgorithm(t *testing.T) {
	want := otpauth.AlgorithmSHA1

	a := otpauth.AlgorithmSHA1
	o := &hotp.Option{}
	err := o.SetAlgorithm(a)
	if err != nil {
		t.Fatalf("SetAlgorithm(%d)=%#v; want nil, receiver %#v", a, err, o)
	}
	if got := o.Algorithm(); got != want {
		t.Errorf("algorithm: got %d, want %d, receiver %#v", got, want, o)
	}
}

func TestOption_SetAlgorithm_ErrOptionIsNil(t *testing.T) {
	wantErr := hotp.ErrHOTPOptionIsNil

	a := otpauth.AlgorithmSHA1
	var o *hotp.Option
	err := o.SetAlgorithm(a)
	if err == nil {
		t.Fatalf("SetAlgorithm(%d)=nil; want %v, receiver nil", a, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetAlgorithm(%d)=%#v; want %v, receiver nil", a, err, wantErr)
	}
}

func TestOption_SetAlgorithm_InvalidDigits(t *testing.T) {
	wantErr := errors.New("invalid algorithm. please pass any of 0 to 3")

	a := otpauth.Algorithm(4)
	o := &hotp.Option{}
	err := o.SetAlgorithm(a)
	if err == nil {
		t.Fatalf("SetAlgorithm(%d)=nil; want %v, receiver nil", a, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetAlgorithm(%d)=%#v; want %v, receiver nil", a, err, wantErr)
	}
}

func TestNewOption(t *testing.T) {
	want := hotp.DefaultOption()

	got := hotp.NewOption()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewOption()=%#v; want %v", got, want)
	}
}
