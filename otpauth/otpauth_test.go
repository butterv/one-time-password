package otpauth_test

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

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

func TestNewURL(t *testing.T) {
	want := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/TEST_ISSUER:TEST_ACCOUNT_NAME",
		RawQuery: "algorithm=SHA1&digits=6&issuer=TEST_ISSUER&period=30&secret=TEST_SECRET",
	}

	issuer := "TEST_ISSUER"
	accountName := "TEST_ACCOUNT_NAME"
	o, _ := otpauth.NewOption(issuer, accountName)

	secret := "TEST_SECRET"
	got := otpauth.ExportNewURL(o, secret)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExportNewURL(%v, %s)=%#v; want %v\ndiff=%s", o, secret, got, want, cmp.Diff(got, want))
	}
}

func TestNewURL_WithIconURL(t *testing.T) {
	want := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/TEST_ISSUER:TEST_ACCOUNT_NAME",
		RawQuery: "algorithm=SHA1&digits=6&icon=TEST_ICON_URL&issuer=TEST_ISSUER&period=30&secret=TEST_SECRET",
	}

	issuer := "TEST_ISSUER"
	accountName := "TEST_ACCOUNT_NAME"
	o, _ := otpauth.NewOption(issuer, accountName)

	iconURL := "TEST_ICON_URL"
	_ = o.SetIconURL(iconURL)

	secret := "TEST_SECRET"
	got := otpauth.ExportNewURL(o, secret)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExportNewURL(%v, %s)=%#v; want %v\ndiff=%s", o, secret, got, want, cmp.Diff(got, want))
	}
}
