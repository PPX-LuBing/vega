package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesPrivateDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "panel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode %v", info.Mode())
	}
	first, err := s.ControlSecret()
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ControlSecret()
	if err != nil || first != second || first == "" {
		t.Fatalf("unstable secret: %v", err)
	}
}

func TestSaveUserPreservesCredentials(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveUser(User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	before, err := s.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SaveUser(User{Name: "alice", Enabled: true, QuotaBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	after, err := s.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if before.UUID != after.UUID || before.Password != after.Password || before.SharedKey != after.SharedKey {
		t.Fatal("credentials rotated")
	}
	if after.QuotaBytes != 1024 {
		t.Fatal("quota not updated")
	}
	if err = s.Grant("missing", "alice"); err == nil {
		t.Fatal("orphan grant accepted")
	}
	if err = s.SaveUser(User{Name: "invalid>>>name"}); err == nil {
		t.Fatal("stats delimiter accepted")
	}
}

func TestTrafficSamplesAreRetrySafeAndRestartAware(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	record := func(instance string, up, down, wantUp, wantDown int64) {
		t.Helper()
		u, d, err := s.RecordTraffic("machine", instance, []TrafficSample{{Name: "alice", Up: up, Down: down}})
		if err != nil || u != wantUp || d != wantDown {
			t.Fatalf("delta %d/%d want %d/%d: %v", u, d, wantUp, wantDown, err)
		}
	}
	record("boot-1", 100, 200, 100, 200)
	record("boot-1", 100, 200, 0, 0)
	record("boot-1", 150, 250, 50, 50)
	record("boot-1", 120, 220, 0, 0)
	record("boot-2", 180, 300, 180, 300)
	record("boot-1", 150, 250, 0, 0)
	record("boot-2", 180, 300, 0, 0)
	u, d, err := s.Usage("alice")
	if err != nil || u != 330 || d != 550 {
		t.Fatalf("usage %d/%d: %v", u, d, err)
	}
	if _, _, err = s.RecordTraffic("machine", "", nil); err == nil {
		t.Fatal("missing instance accepted")
	}
	if _, _, err = s.RecordTraffic("machine", "boot-2", []TrafficSample{{Name: "alice", Up: 190}, {Name: "bad", Up: -1}}); err == nil {
		t.Fatal("negative sample accepted")
	}
	u, d, _ = s.Usage("alice")
	if u != 330 || d != 550 {
		t.Fatal("failed batch partially committed")
	}
}

func TestDeleteUserRollsBackRelatedRowsOnFailure(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveUser(User{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveNode(Node{Tag: "node", Proto: ProtoNowhere, Port: 8443}); err != nil {
		t.Fatal(err)
	}
	if err = s.Grant("node", "alice"); err != nil {
		t.Fatal(err)
	}
	if err = s.AddTraffic("alice", 100, 200, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER prevent_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteUser("alice"); err == nil {
		t.Fatal("delete failure hidden")
	}
	users, err := s.UsersForNode("node")
	if err != nil || len(users) != 1 {
		t.Fatal("grants not rolled back")
	}
	up, down, err := s.Usage("alice")
	if err != nil || up != 100 || down != 200 {
		t.Fatal("usage not rolled back")
	}
}
