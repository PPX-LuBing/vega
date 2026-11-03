package portal

import (
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/runtime"
)

func TestMultiUserHandshakeBudget(t *testing.T) {
	t.Setenv(runtime.EnvHandshakeTimeout, "unused")
	if err := os.Unsetenv(runtime.EnvHandshakeTimeout); err != nil {
		t.Fatal(err)
	}
	users := []User{{Name: "alice", SharedKey: keyAlice}, {Name: "bob", SharedKey: keyBob}}
	s, err := New(Config{Users: users, TLS: &tls.Config{}, Upstream: Direct{}})
	if err != nil {
		t.Fatal(err)
	}
	want := runtime.HandshakeTimeout(keyAlice)
	if b := runtime.HandshakeTimeout(keyBob); b > want {
		want = b
	}
	_, _, _, got := s.snapshotUsers()
	if got != want {
		t.Fatalf("multiuser timeout = %v, want %v", got, want)
	}
	if err = s.UpdateUsers(users[:1]); err != nil {
		t.Fatal(err)
	}
	_, _, _, got = s.snapshotUsers()
	if got != runtime.HandshakeTimeout(keyAlice) {
		t.Fatalf("updated timeout = %v", got)
	}
	if _, err = New(Config{Users: users, TLS: &tls.Config{}, Egress: true}); err == nil {
		t.Fatal("multiuser Egress must not share exits across users")
	}
}

func TestHandshakeBudgetOverrideAndValidation(t *testing.T) {
	t.Setenv(runtime.EnvHandshakeTimeout, "75ms")
	s, err := New(Config{Users: []User{{Name: "alice", SharedKey: keyAlice}}, TLS: &tls.Config{}, Upstream: Direct{}})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateUsers([]User{{Name: "bob", SharedKey: keyBob}}); err != nil {
		t.Fatal(err)
	}
	_, _, _, got := s.snapshotUsers()
	if got != 75*time.Millisecond {
		t.Fatalf("explicit timeout lost: %v", got)
	}
	t.Setenv(runtime.EnvHandshakeTimeout, "invalid")
	if _, err = New(Config{SharedKey: keyAlice, TLS: &tls.Config{}, Upstream: Direct{}}); err == nil {
		t.Fatal("invalid timeout accepted")
	}
}
