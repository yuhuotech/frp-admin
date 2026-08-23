package auth

import "testing"

func TestPasswordHashRoundTrip(t *testing.T) {
	h, e := hashPassword("correct horse battery staple")
	if e != nil {
		t.Fatal(e)
	}
	if !verifyPassword("correct horse battery staple", h) {
		t.Fatal("correct password rejected")
	}
	if verifyPassword("wrong password", h) {
		t.Fatal("wrong password accepted")
	}
	if verifyPassword("x", "malformed") {
		t.Fatal("malformed hash accepted")
	}
}
