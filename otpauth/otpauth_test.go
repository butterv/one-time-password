package otpauth_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/butterv/one-time-password/otpauth"
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

func TestOtpAuth_QRCode(t *testing.T) {
	want := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAABFUlEQVR42uyYMW7GIAyFHWXImCNwFI7GfzSOkiMwMlR5lU3apG6JurUK7y0h6Jss3sNGKIqi/rtWNOW4rXiT6fitBDzQlilLKIsC192hgAWApBxRFuwTJAGFQB+QABD4HVBnAjfA4c246ffGvKMDlzC3St6l/cjAKUv7Oz0aWKttJ+SgYS6ClwTnTQJ2ouoM4CURRZ0HkWZCAg6oFkzaHqAakHLwYU6g3Xq7njPVvNvpc5UkcL31kHVpWf691AQuslFuMpvKWmQ04Lz9dULRNE+50yYNDnyZea2S8UfrEficULSSLcxRCPSBQ/1KEmivKNtHp+Cf3Qh4b1p7AKBr3icDZ5ijHrO/m1AIUBRF/Z3eAwAA//97vEDyAafUkQAAAABJRU5ErkJggg=="

	oa := otpauth.DefaultOtpAuth()
	got, err := oa.QRCode()
	if err != nil {
		t.Fatalf("QRCode()=_, %#v; want nil, receiver %v", err, oa)
	}
	if got != want {
		t.Errorf("QRCode()=%s, _; want %s, receiver %v", got, want, oa)
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
