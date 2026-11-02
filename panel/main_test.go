package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func TestUserAddRejectsInvalidLimits(t *testing.T) {
	for _, args := range [][]string{{"--quota", "NaN"}, {"--quota", "+Inf"}, {"--quota", "-1"}, {"--days", "-1"}, {"--days", "365001"}} {
		path := filepath.Join(t.TempDir(), "panel.db")
		command := append([]string{"add", "alice"}, args...)
		if err := runUser(path, kernel.Paths{}, command); err == nil {
			t.Fatalf("accepted %v", args)
		}
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = st.User("alice")
		st.Close()
		if err == nil {
			t.Fatal("invalid user persisted")
		}
	}
}

func TestSetCommandsPreserveOmittedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	paths := kernel.Paths{}
	if err := runNode(path, paths, []string{"add", "vm", "--proto", "vmess", "--port", "8443", "--tls", "none", "--transport", "ws", "--path", "/proxy"}); err != nil {
		t.Fatal(err)
	}
	if err := runNode(path, paths, []string{"set", "vm", "--remark", "updated"}); err != nil {
		t.Fatal(err)
	}
	if err := runNode(path, paths, []string{"add", "vm", "--proto", "vmess", "--port", "9999", "--tls", "none"}); err == nil {
		t.Fatal("duplicate add overwrote node")
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.Node("vm")
	if err != nil {
		t.Fatal(err)
	}
	if n.Port != 8443 || n.Proto != "vmess" || n.Transport != "ws" || n.Path != "/proxy" || n.Remark != "updated" {
		t.Fatalf("omitted fields changed: %#v", n)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: false, QuotaBytes: 1234, ExpiresAt: time.Now().Add(-time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	before, err := st.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if err := runUser(path, paths, []string{"set", "alice", "--remark", "updated"}); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	after, err := st.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if after.Enabled || after.ExpiresAt != before.ExpiresAt || after.QuotaBytes != before.QuotaBytes || after.UUID != before.UUID || after.Password != before.Password || after.SharedKey != before.SharedKey {
		t.Fatal("user set changed credentials or limits")
	}
}

func TestEnforceRejectsInvalidWatchInterval(t *testing.T) {
	if err := runEnforce(filepath.Join(t.TempDir(), "panel.db"), kernel.Paths{}, []string{"--watch", "--interval", "0s"}); err == nil {
		t.Fatal("zero interval accepted")
	}
}

func TestOperationsValidateAndReadEmptyHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	for _, args := range [][]string{{"traffic", "--hours", "0"}, {"events", "--limit", "1001"}, {"alert"}, {"alert", "--test"}, {"doctor", "unexpected"}} {
		if err := runOperations(path, kernel.Paths{}, args); err == nil {
			t.Fatalf("invalid operation accepted: %v", args)
		}
	}
	for _, args := range [][]string{{"traffic", "--hours", "2", "--json"}, {"events", "--limit", "1", "--json"}} {
		if err := runOperations(path, kernel.Paths{}, args); err != nil {
			t.Fatalf("read %v: %v", args, err)
		}
	}
}
