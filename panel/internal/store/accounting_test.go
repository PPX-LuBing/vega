package store

import (
	"math"
	"path/filepath"
	"testing"
	"time"
)

func accountingStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestScaledDeltaExactAndBounded(t *testing.T) {
	for _, delta := range []int64{0, 1, 1<<53 + 1, math.MaxInt64} {
		got, remainder, err := scaledDelta(delta, rateScale, 0)
		if err != nil || got != delta || remainder != 0 {
			t.Fatalf("%d -> %d/%d: %v", delta, got, remainder, err)
		}
	}
	if _, _, err := scaledDelta(math.MaxInt64, 2*rateScale, 0); err == nil {
		t.Fatal("overflow accepted")
	}
	if got, r, err := scaledDelta(1, 500_000, 500_000); err != nil || got != 1 || r != 0 {
		t.Fatalf("fraction: %d %d %v", got, r, err)
	}
}

func TestBillingRateOnlyAppliesToNewDeltas(t *testing.T) {
	s := accountingStore(t)
	record := func(counter, want int64) {
		t.Helper()
		got, _, err := s.RecordTraffic("local", "boot", []TrafficSample{{Name: "alice", Up: counter}})
		if err != nil || got != want {
			t.Fatalf("counter=%d got=%d want=%d: %v", counter, got, want, err)
		}
	}
	if err := s.SetSetting("traffic_rate", "0.5"); err != nil {
		t.Fatal(err)
	}
	record(1, 0)
	record(1, 0)
	record(2, 1)
	record(3, 0)
	if err := s.SetSetting("traffic_rate", "1.5"); err != nil {
		t.Fatal(err)
	}
	record(3, 0)
	record(4, 2)
	up, _, err := s.Usage("alice")
	if err != nil || up != 3 {
		t.Fatalf("usage %d: %v", up, err)
	}
	points, err := s.TrafficHistory(time.Now(), 3)
	if err != nil || len(points) != 3 || points[0].Up != 0 || points[2].Up != 3 {
		t.Fatalf("history %#v: %v", points, err)
	}
	if err := s.ResetTraffic("alice"); err != nil {
		t.Fatal(err)
	}
	record(4, 0)
	record(6, 3)
}

func TestMonthlyResetPreservesCheckpointsAndUserState(t *testing.T) {
	s := accountingStore(t)
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	if err := s.SaveUser(User{Name: "alice", Enabled: false, ExpiresAt: 1, QuotaBytes: 100}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("quota_reset_day", "5"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordTraffic("local", "boot", []TrafficSample{{Name: "alice", Up: 120}}); err != nil {
		t.Fatal(err)
	}
	if reset, err := s.ResetMonthly(now); err != nil || reset {
		t.Fatalf("activation resets usage: %v %v", reset, err)
	}
	if up, _, _ := s.Usage("alice"); up != 120 {
		t.Fatal("activation lost usage")
	}
	if reset, err := s.ResetMonthly(now.AddDate(0, 1, 0)); err != nil || !reset {
		t.Fatalf("next cycle: %v %v", reset, err)
	}
	if reset, err := s.ResetMonthly(now.AddDate(0, 1, 0)); err != nil || reset {
		t.Fatalf("double reset: %v %v", reset, err)
	}
	if up, _, _ := s.Usage("alice"); up != 0 {
		t.Fatal("usage not reset")
	}
	u, _ := s.User("alice")
	if u.Enabled || u.ExpiresAt != 1 {
		t.Fatal("reset reenabled user")
	}
	if up, _, err := s.RecordTraffic("local", "boot", []TrafficSample{{Name: "alice", Up: 130}}); err != nil || up != 10 {
		t.Fatalf("checkpoint lost: %d %v", up, err)
	}
	points, err := s.TrafficHistory(time.Now(), 1)
	if err != nil || points[0].Up != 130 {
		t.Fatalf("history lost: %#v %v", points, err)
	}
	if err := s.SetSetting("quota_reset_day", "0"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("quota_reset_day", "5"); err != nil {
		t.Fatal(err)
	}
	if reset, err := s.ResetMonthly(now.AddDate(0, 3, 0)); err != nil || reset {
		t.Fatalf("reenabling reset old usage: %v %v", reset, err)
	}
}

func TestUpgradePreservesExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveUser(User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	before, err := s.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNode(Node{Tag: "old", Proto: ProtoVLESS, Port: 443, TLSMode: "none", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant("old", "alice"); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"entry_sni", "transport", "path", "host", "grpc_service", "fingerprint"} {
		if _, err := s.db.Exec("ALTER TABLE nodes DROP COLUMN " + column); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"traffic_hourly", "traffic_remainders", "events", "usage_state"} {
		if _, err := s.db.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	after, err := s.User("alice")
	if err != nil || after.UUID != before.UUID || after.Password != before.Password || after.SharedKey != before.SharedKey {
		t.Fatal("upgrade changed credentials")
	}
	n, err := s.Node("old")
	if err != nil || n.Transport != "" || n.Port != 443 {
		t.Fatalf("node migration: %#v %v", n, err)
	}
	grants, err := s.NodesForUser("alice")
	if err != nil || len(grants) != 1 {
		t.Fatal("upgrade lost grants")
	}
}

func TestUsageEventsOnlyOnTransitions(t *testing.T) {
	s := accountingStore(t)
	if err := s.SaveUser(User{Name: "alice", Enabled: true, QuotaBytes: 100}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		delta int64
		kind  string
	}{{0, ""}, {80, "warning"}, {0, ""}, {20, "over_quota"}, {0, ""}} {
		if err := s.AddTraffic("alice", tc.delta, 0, ""); err != nil {
			t.Fatal(err)
		}
		events, err := s.UsageEvents(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if tc.kind == "" {
			if len(events) != 0 {
				t.Fatal("duplicate event")
			}
		} else if len(events) != 1 || events[0].Kind != tc.kind {
			t.Fatalf("events %#v", events)
		}
	}
	events, err := s.Events(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("persisted events %#v %v", events, err)
	}
}

func TestSettingValidation(t *testing.T) {
	s := accountingStore(t)
	for _, tc := range [][2]string{{"traffic_rate", "NaN"}, {"traffic_rate", "+Inf"}, {"traffic_rate", "0"}, {"traffic_rate", "1001"}, {"traffic_rate", "0.0000001"}, {"quota_reset_day", "29"}, {"quota_reset_day", "-1"}, {"alert_webhook", "file:///tmp/x"}, {"alert_webhook", "https://user:password@example.com"}, {"extra_config", "[]"}, {"typo_setting", "1"}} {
		if err := s.SetSetting(tc[0], tc[1]); err == nil {
			t.Errorf("accepted %v", tc)
		}
	}
}

func TestHourlyOverflowRollsBackCheckpoints(t *testing.T) {
	s := accountingStore(t)
	if _, _, err := s.RecordTraffic("local", "boot", []TrafficSample{{Name: "alice", Up: math.MaxInt64}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ResetTraffic("alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordTraffic("local", "new-boot", []TrafficSample{{Name: "alice", Up: 1}}); err == nil {
		t.Fatal("hourly overflow accepted")
	}
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM traffic_samples WHERE instance='new-boot'").Scan(&count); err != nil || count != 0 {
		t.Fatal("checkpoint committed on failure")
	}
}
