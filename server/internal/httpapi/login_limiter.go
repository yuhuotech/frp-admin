package httpapi

import (
	"net"
	"strings"
	"sync"
	"time"
)

const overflowLoginKey = "__overflow__"

type loginAttempt struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

type loginLimiter struct {
	mu          sync.Mutex
	attempts    map[string]loginAttempt
	now         func() time.Time
	window      time.Duration
	blockFor    time.Duration
	maxFailures int
	maxKeys     int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		attempts:    make(map[string]loginAttempt),
		now:         time.Now,
		window:      15 * time.Minute,
		blockFor:    15 * time.Minute,
		maxFailures: 5,
		maxKeys:     10_000,
	}
}

func loginKey(remoteAddr, username string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return strings.ToLower(strings.TrimSpace(host)) + "\x00" + strings.ToLower(strings.TrimSpace(username))
}

func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	attempt, ok := l.attempts[key]
	if !ok {
		return true
	}
	if !attempt.blockedUntil.IsZero() && now.Before(attempt.blockedUntil) {
		return false
	}
	if now.Sub(attempt.windowStart) >= l.window {
		delete(l.attempts, key)
	}
	return true
}

func (l *loginLimiter) recordFailure(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if _, ok := l.attempts[key]; !ok && len(l.attempts) >= l.maxKeys {
		key = overflowLoginKey
	}
	attempt := l.attempts[key]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) >= l.window {
		attempt = loginAttempt{windowStart: now}
	}
	attempt.failures++
	if attempt.failures >= l.maxFailures {
		attempt.blockedUntil = now.Add(l.blockFor)
	}
	l.attempts[key] = attempt
	return !attempt.blockedUntil.IsZero() && now.Before(attempt.blockedUntil)
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}
