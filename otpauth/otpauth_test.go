package otpauth_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/istsh/one-time-password/otpauth"
)

func TestOtpAuth_URL(t *testing.T) {
	want := "TEST_URL"

	oa := otpauth.DefaultOtpAuth()
	got := oa.URL()
	if got != want {
		t.Errorf("URL()=%s; want %s, receiver %v", got, want, oa)
	}
}

func TestOtpAuth_URL_Empty(t *testing.T) {
	want := ""

	var oa *otpauth.OtpAuth
	got := oa.URL()
	if got != want {
		t.Errorf("URL()=%s; want %s, receiver nil", got, want)
	}
}

func TestOtpAuth_Secret(t *testing.T) {
	want := "TEST_SECRET"

	oa := otpauth.DefaultOtpAuth()
	got := oa.Secret()
	if got != want {
		t.Errorf("Secret()=%s; want %s, receiver %v", got, want, oa)
	}
}

func TestOtpAuth_Secret_Empty(t *testing.T) {
	want := ""

	var oa *otpauth.OtpAuth
	got := oa.Secret()
	if got != want {
		t.Errorf("Secret()=%s; want %s, receiver nil", got, want)
	}
}

func TestGenerateOtpAuth_IssuerIsEmpty(t *testing.T) {
	wantErr := errors.New("issuer is empty")

	issuer := ""
	accountName := "TEST_ACCOUNT_NAME"
	host := otpauth.HostTOTP
	_, err := otpauth.GenerateOtpAuth(issuer, accountName, host)
	if err == nil {
		t.Fatalf("GenerateOtpAuth(%s, %s, %d)=_, nil; want %d", issuer, accountName, host, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("GenerateOtpAuth(%s, %s, %d)=_, %#v; want %d", issuer, accountName, host, err, wantErr)
	}
}

func TestGenerateOtpAuth_AccountNameIsEmpty(t *testing.T) {
	wantErr := errors.New("accountName is empty")

	issuer := "TEST_ISSUER"
	accountName := ""
	host := otpauth.HostTOTP
	_, err := otpauth.GenerateOtpAuth(issuer, accountName, host)
	if err == nil {
		t.Fatalf("GenerateOtpAuth(%s, %s, %d)=_, nil; want %d", issuer, accountName, host, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("GenerateOtpAuth(%s, %s, %d)=_, %#v; want %d", issuer, accountName, host, err, wantErr)
	}
}

func TestGenerateOtpAuth_InvalidHost(t *testing.T) {
	wantErr := fmt.Errorf("invalid host. please pass %d or %d", otpauth.HostHOTP, otpauth.HostTOTP)

	issuer := "TEST_ISSUER"
	accountName := "TEST_ACCOUNT_NAME"
	host := otpauth.Host(2)
	_, err := otpauth.GenerateOtpAuth(issuer, accountName, host)
	if err == nil {
		t.Fatalf("GenerateOtpAuth(%s, %s, %d)=_, nil; want %d", issuer, accountName, host, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("GenerateOtpAuth(%s, %s, %d)=_, %#v; want %d", issuer, accountName, host, err, wantErr)
	}
}
