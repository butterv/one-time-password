package recovery_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/istsh/one-time-password/recovery"
)

func TestOption_SetLetters(t *testing.T) {
	want := "abcdefg"

	letters := "abcdefg"
	o := &recovery.Option{}
	err := o.SetLetters(letters)
	if err != nil {
		t.Fatalf("SetLetters(%s)=%#v; want nil, receiver %#v", letters, err, o)
	}
	if got := o.Letters(); got != want {
		t.Errorf("letters: got %s, want %s, receiver %#v", got, want, o)
	}
}

func TestOption_SetLetters_ErrOptionIsNil(t *testing.T) {
	wantErr := recovery.ErrRecoveryCodeOptionIsNil

	letters := "abcdefg"
	var o *recovery.Option
	err := o.SetLetters(letters)
	if err == nil {
		t.Fatalf("SetLetters(%s)=nil; want %v, receiver nil", letters, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetLetters(%s)=%#v; want %v, receiver nil", letters, err, wantErr)
	}
}

func TestOption_SetLetters_LettersIsEmpty(t *testing.T) {
	wantErr := errors.New("letters is empty")

	letters := ""
	o := &recovery.Option{}
	err := o.SetLetters(letters)
	if err == nil {
		t.Fatalf("SetLetters(%s)=nil; want %v, receiver nil", letters, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetLetters(%s)=%#v; want %v, receiver nil", letters, err, wantErr)
	}
}

func TestOption_SetLength(t *testing.T) {
	want := uint(8)

	length := uint(8)
	o := &recovery.Option{}
	err := o.SetLength(length)
	if err != nil {
		t.Fatalf("SetLength(%d)=%#v; want nil, receiver %#v", length, err, o)
	}
	if got := o.Length(); got != want {
		t.Errorf("length: got %d, want %d, receiver %#v", got, want, o)
	}
}

func TestOption_SetLength_ErrOptionIsNil(t *testing.T) {
	wantErr := recovery.ErrRecoveryCodeOptionIsNil

	length := uint(8)
	var o *recovery.Option
	err := o.SetLength(length)
	if err == nil {
		t.Fatalf("SetLength(%d)=nil; want %v, receiver nil", length, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetLength(%d)=%#v; want %v, receiver nil", length, err, wantErr)
	}
}

func TestOption_SetLength_InvalidLength(t *testing.T) {
	wantErr := errors.New("invalid length. please pass greater than 0")

	length := uint(0)
	o := &recovery.Option{}
	err := o.SetLength(length)
	if err == nil {
		t.Fatalf("SetLength(%d)=nil; want %v, receiver nil", length, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetLength(%d)=%#v; want %v, receiver nil", length, err, wantErr)
	}
}

func TestOption_SetCount(t *testing.T) {
	want := uint(8)

	count := uint(8)
	o := &recovery.Option{}
	err := o.SetCount(count)
	if err != nil {
		t.Fatalf("SetCount(%d)=%#v; want nil, receiver %#v", count, err, o)
	}
	if got := o.Count(); got != want {
		t.Errorf("count: got %d, want %d, receiver %#v", got, want, o)
	}
}

func TestOption_SetCount_ErrOptionIsNil(t *testing.T) {
	wantErr := recovery.ErrRecoveryCodeOptionIsNil

	count := uint(8)
	var o *recovery.Option
	err := o.SetCount(count)
	if err == nil {
		t.Fatalf("SetCount(%d)=nil; want %v, receiver nil", count, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetCount(%d)=%#v; want %v, receiver nil", count, err, wantErr)
	}
}

func TestOption_SetCount_InvalidCount(t *testing.T) {
	wantErr := errors.New("invalid count. please pass greater than 0")

	count := uint(0)
	o := &recovery.Option{}
	err := o.SetCount(count)
	if err == nil {
		t.Fatalf("SetCount(%d)=nil; want %v, receiver nil", count, wantErr)
	}
	if err.Error() != wantErr.Error() {
		t.Errorf("SetCount(%d)=%#v; want %v, receiver nil", count, err, wantErr)
	}
}

func TestNewOption(t *testing.T) {
	want := recovery.DefaultOption()

	got := recovery.NewOption()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NewOption()=%#v, _; want %v", got, want)
	}
}
