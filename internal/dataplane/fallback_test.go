package dataplane

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	afxdp "github.com/atoonk/go-afxdp"
)

func TestOpenAFXDPNativeFirstReportsFallbackReason(t *testing.T) {
	nativeErr := errors.New("afxdp: could not open eth0 (1 queues): native attach: operation not supported")
	var logs []string
	genericCalls := 0

	got, err := openAFXDPNativeFirst(
		func() (*afxdp.Fleet, error) { return nil, nativeErr },
		func() (*afxdp.Fleet, error) { genericCalls++; return nil, nil },
		func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) },
	)
	if err != nil {
		t.Fatalf("fallback returned an error: %v", err)
	}
	if !errors.Is(got.nativeAttemptError, nativeErr) {
		t.Fatalf("retained native error = %v, want %v", got.nativeAttemptError, nativeErr)
	}
	if genericCalls != 1 {
		t.Fatalf("generic open calls = %d, want 1", genericCalls)
	}
	if len(logs) != 1 {
		t.Fatalf("logs = %q, want one fallback diagnostic", logs)
	}
	for _, want := range []string{"native AF_XDP attempt failed", nativeErr.Error(), "generic XDP copy mode"} {
		if !strings.Contains(logs[0], want) {
			t.Errorf("fallback diagnostic %q does not contain %q", logs[0], want)
		}
	}
}

func TestOpenAFXDPNativeFirstDoesNotRetryModeIndependentFailure(t *testing.T) {
	nativeErr := errors.New("afxdp: look up eth0: no such interface")
	genericCalls := 0
	logCalls := 0

	_, err := openAFXDPNativeFirst(
		func() (*afxdp.Fleet, error) { return nil, nativeErr },
		func() (*afxdp.Fleet, error) { genericCalls++; return new(afxdp.Fleet), nil },
		func(string, ...any) { logCalls++ },
	)
	if !errors.Is(err, nativeErr) {
		t.Fatalf("err = %v, want original non-mode error", err)
	}
	if genericCalls != 0 || logCalls != 0 {
		t.Fatalf("non-mode failure made %d generic calls and %d log calls, want 0/0", genericCalls, logCalls)
	}
}

func TestOpenAFXDPNativeFirstDoesNotMentionFallbackOnSuccess(t *testing.T) {
	want := new(afxdp.Fleet)
	genericCalls := 0
	logCalls := 0

	got, err := openAFXDPNativeFirst(
		func() (*afxdp.Fleet, error) { return want, nil },
		func() (*afxdp.Fleet, error) { genericCalls++; return nil, nil },
		func(string, ...any) { logCalls++ },
	)
	if err != nil || got.fleet != want {
		t.Fatalf("got fleet=%p err=%v, want fleet=%p and no error", got.fleet, err, want)
	}
	if got.nativeAttemptError != nil {
		t.Fatalf("native success retained error %v", got.nativeAttemptError)
	}
	if genericCalls != 0 || logCalls != 0 {
		t.Errorf("native success made %d generic calls and %d log calls, want 0/0", genericCalls, logCalls)
	}
}

func TestOpenAFXDPNativeFirstPreservesBothErrors(t *testing.T) {
	nativeErr := errors.New("afxdp: could not open eth0 (1 queues): native bind: native failed")
	genericErr := errors.New("generic failed")

	_, err := openAFXDPNativeFirst(
		func() (*afxdp.Fleet, error) { return nil, nativeErr },
		func() (*afxdp.Fleet, error) { return nil, genericErr },
		func(string, ...any) {},
	)
	if !errors.Is(err, nativeErr) || !errors.Is(err, genericErr) {
		t.Fatalf("err = %v, want both native and generic causes", err)
	}
}
