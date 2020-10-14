package recovery_test

import (
	"errors"
	"testing"

	"github.com/istsh/one-time-password/recovery"
)

func TestGenerateRecoveryCodes_InvalidLength(t *testing.T) {
	wantErr := errors.New("invalid length. please pass greater than 0")

	length := uint(0)
	count := uint(1)
	_, err := recovery.GenerateRecoveryCodes(length, count)
	if err == nil {
		t.Fatalf("GenerateRecoveryCodes(%d, %d)=_, nil; want %v", length, count, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("GenerateRecoveryCodes(%d, %d)=_, %#v; want %v", length, count, err, wantErr)
	}
}

func TestGenerateRecoveryCodes_InvalidCount(t *testing.T) {
	wantErr := errors.New("invalid count. please pass greater than 0")

	length := uint(8)
	count := uint(0)
	_, err := recovery.GenerateRecoveryCodes(length, count)
	if err == nil {
		t.Fatalf("GenerateRecoveryCodes(%d, %d)=_, nil; want %v", length, count, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("GenerateRecoveryCodes(%d, %d)=_, %#v; want %v", length, count, err, wantErr)
	}
}
