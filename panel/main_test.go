package main

import (
	"path/filepath"
	"testing"

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

func TestEnforceRejectsInvalidWatchInterval(t *testing.T) {
	if err := runEnforce(filepath.Join(t.TempDir(), "panel.db"), kernel.Paths{}, []string{"--watch", "--interval", "0s"}); err == nil {
		t.Fatal("zero interval accepted")
	}
}
