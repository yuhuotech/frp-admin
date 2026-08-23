package httpapi

import (
	"testing"
	"time"
)

func TestLoginLimiterBlocksAndExpires(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	key := loginKey("192.0.2.10:1234", " Admin ")
	if key != "192.0.2.10\x00admin" {
		t.Fatalf("unexpected key %q", key)
	}
	for i := 0; i < limiter.maxFailures-1; i++ {
		if limiter.recordFailure(key) {
			t.Fatalf("blocked after only %d failures", i+1)
		}
	}
	if !limiter.recordFailure(key) || limiter.allowed(key) {
		t.Fatal("expected login key to be blocked")
	}
	now = now.Add(limiter.blockFor + time.Second)
	if !limiter.allowed(key) {
		t.Fatal("expected expired block to be removed")
	}
}

func TestLoginLimiterReset(t *testing.T) {
	limiter := newLoginLimiter()
	key := loginKey("192.0.2.10:1234", "admin")
	limiter.recordFailure(key)
	limiter.reset(key)
	if !limiter.allowed(key) {
		t.Fatal("successful login should reset failures")
	}
}
