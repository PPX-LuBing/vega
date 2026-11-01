package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

const sampleStats = `{"instance":"boot-1","stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"100"},{"name":"user>>>alice>>>traffic>>>downlink","value":"200"}]}`

func TestCollectAllSeparatesMachinesAndReportsPartialFailure(t *testing.T) {
	st := testStore(t)
	for _, name := range []string{"hk", "tw", "failed"} {
		if err := st.SaveMachine(store.Machine{Name: name, Host: name + ".invalid"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SAMPLE_STATS", sampleStats)
	fakeCommand(t, "ssh", `for arg; do case "$arg" in *failed.invalid) exit 1;; esac; done; printf '%s' "$SAMPLE_STATS"`)
	for iteration := 0; iteration < 2; iteration++ {
		results := CollectAll(context.Background(), st, testPaths())
		if len(results) != 3 {
			t.Fatalf("unexpected results: %+v", results)
		}
		var up, down int64
		failed := 0
		for _, r := range results {
			if r.Err != nil {
				failed++
				continue
			}
			up += r.Up
			down += r.Down
		}
		wantUp, wantDown := int64(200), int64(400)
		if iteration == 1 {
			wantUp, wantDown = 0, 0
		}
		if failed != 1 || up != wantUp || down != wantDown {
			t.Fatalf("%d/%d failed=%d", up, down, failed)
		}
	}
	up, down, err := st.Usage("alice")
	if err != nil || up != 200 || down != 400 {
		t.Fatalf("usage %d/%d: %v", up, down, err)
	}
}

func TestCollectAllUsesRegisteredLocalPaths(t *testing.T) {
	st := testStore(t)
	stats := fakeCommand(t, "stats", `printf '%s' "$SAMPLE_STATS"`)
	t.Setenv("SAMPLE_STATS", sampleStats)
	if err := st.SaveMachine(store.Machine{Name: store.LocalMachine, StatsBin: stats, APIAddr: "127.0.0.1:23456"}); err != nil {
		t.Fatal(err)
	}
	results := CollectAll(context.Background(), st, Paths{StatsBin: "/must-not-be-called"})
	if len(results) != 1 || results[0].Err != nil || results[0].Up != 100 {
		t.Fatalf("%+v", results)
	}
}

func TestObserveAllReadsLocalAndRemoteSnapshots(t *testing.T) {
	st := testStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			fmt.Fprint(w, `{"version":"local-version"}`)
			return
		}
		fmt.Fprint(w, `{"uploadTotal":10,"connections":[{"metadata":{"host":"local.test"}}]}`)
	}))
	defer server.Close()
	fakeSystemctl(t, "echo active")
	fakeCommand(t, "ssh", `for arg; do script=$arg; done
case "$script" in *is-active*) echo active;; */version*) printf '{"version":"remote-version"}';; */connections*) printf '{"downloadTotal":20,"connections":[]}' ;; *) exit 1;; esac`)
	if err := st.SaveMachine(store.Machine{Name: store.LocalMachine, ClashAddr: strings.TrimPrefix(server.URL, "http://")}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveMachine(store.Machine{Name: "remote", Host: "remote.invalid"}); err != nil {
		t.Fatal(err)
	}
	results := ObserveAll(context.Background(), st, testPaths())
	if len(results) != 2 || results[0].Err != nil || results[1].Err != nil || results[0].Version != "local-version" || results[1].Version != "remote-version" || results[1].DownloadTotal != 20 {
		t.Fatalf("%+v", results)
	}
}

func TestEnforceRestartsOnlyWhenQuotaOrExpiryChangesConfig(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			st := testStore(t)
			paths := testPaths()
			dir := t.TempDir()
			paths.Config = filepath.Join(dir, "config.json")
			paths.Bin = fakeCommand(t, "kernel", "exit 0")
			paths.StatsBin = fakeCommand(t, "stats", `printf '%s' "$SAMPLE_STATS"`)
			t.Setenv("SAMPLE_STATS", sampleStats)
			log := filepath.Join(dir, "restarts")
			t.Setenv("RESTART_LOG", log)
			fakeSystemctl(t, `echo restart >> "$RESTART_LOG"`)
			u := store.User{Name: "alice", Enabled: true, QuotaBytes: 300}
			if err := st.SaveUser(u); err != nil {
				t.Fatal(err)
			}
			if err := st.SaveNode(store.Node{Tag: "node", Proto: store.ProtoAnyTLS, Port: 8443, Enabled: true}); err != nil {
				t.Fatal(err)
			}
			if err := st.Grant("node", "alice"); err != nil {
				t.Fatal(err)
			}
			cfg, err := BuildConfig(st, paths)
			if err != nil {
				t.Fatal(err)
			}
			if err = WriteConfig(paths, cfg); err != nil {
				t.Fatal(err)
			}
			if expired {
				u.QuotaBytes, u.ExpiresAt = 0, time.Now().Add(-time.Minute).Unix()
				if err = st.SaveUser(u); err != nil {
					t.Fatal(err)
				}
			}
			for _, changed := range []bool{true, false} {
				results := Enforce(context.Background(), st, paths)
				if len(results) != 1 || results[0].Err != nil || results[0].Changed != changed {
					t.Fatalf("%+v", results)
				}
			}
			body, err := os.ReadFile(paths.Config)
			if err != nil {
				t.Fatal(err)
			}
			var installed struct {
				Inbounds []any `json:"inbounds"`
			}
			if err = json.Unmarshal(body, &installed); err != nil || len(installed.Inbounds) != 0 {
				t.Fatalf("ineligible user retained: %s: %v", body, err)
			}
			body, err = os.ReadFile(log)
			if err != nil || strings.Count(string(body), "restart") != 1 {
				t.Fatalf("unexpected restarts %q: %v", body, err)
			}
		})
	}
}

func TestEnforceDoesNotDeployWithIncompleteFleetUsage(t *testing.T) {
	st := testStore(t)
	paths := testPaths()
	paths.StatsBin = fakeCommand(t, "stats", "exit 1")
	paths.Config = filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(paths.Config, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	results := Enforce(context.Background(), st, paths)
	if len(results) != 1 || results[0].Err == nil || results[0].Changed {
		t.Fatalf("%+v", results)
	}
	body, _ := os.ReadFile(paths.Config)
	if string(body) != "unchanged" {
		t.Fatal("deployed despite missing usage")
	}
}

func TestEnforceUsesCombinedQuotaAcrossMachines(t *testing.T) {
	st := testStore(t)
	dir := t.TempDir()
	paths := testPaths()
	paths.Bin = fakeCommand(t, "kernel", "exit 0")
	paths.StatsBin = fakeCommand(t, "stats", `printf '%s' "$SAMPLE_STATS"`)
	paths.Config = filepath.Join(dir, "local.json")
	t.Setenv("SAMPLE_STATS", sampleStats)
	remote := store.Machine{Name: "remote", Host: "remote.invalid", KernelPath: paths.Bin, ConfigPath: filepath.Join(dir, "remote.json")}
	if err := st.SaveMachine(remote); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: true, QuotaBytes: 500}); err != nil {
		t.Fatal(err)
	}
	for _, machine := range []string{store.LocalMachine, "remote"} {
		if err := st.SaveNode(store.Node{Tag: machine, Machine: machine, Proto: store.ProtoAnyTLS, Port: 8443, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		if err := st.Grant(machine, "alice"); err != nil {
			t.Fatal(err)
		}
		m, _ := st.Machine(machine)
		mp := MachinePaths(m)
		if machine == store.LocalMachine {
			mp = paths
		}
		cfg, err := BuildConfigFor(st, mp, machine)
		if err != nil {
			t.Fatal(err)
		}
		if err = WriteConfig(mp, cfg); err != nil {
			t.Fatal(err)
		}
	}
	fakeCommand(t, "ssh", `for arg; do script=$arg; done
case "$script" in *-pattern*) printf '%s' "$SAMPLE_STATS";; *) exec sh -c "$script";; esac`)
	fakeCommand(t, "scp", `previous=; last=; for arg; do previous=$last; last=$arg; done; cp "$previous" "${last#*:}"`)
	if runtime.GOOS != "linux" {
		fakeCommand(t, "flock", "exit 0")
	}
	log := filepath.Join(dir, "restart.log")
	t.Setenv("RESTART_LOG", log)
	fakeSystemctl(t, `echo restart >> "$RESTART_LOG"`)
	results := Enforce(context.Background(), st, paths)
	if len(results) != 2 {
		t.Fatalf("%+v", results)
	}
	for _, r := range results {
		if r.Err != nil || !r.Changed {
			t.Fatalf("%+v", results)
		}
	}
	up, down, err := st.Usage("alice")
	if err != nil || up+down != 600 {
		t.Fatalf("combined usage %d/%d: %v", up, down, err)
	}
	for _, path := range []string{paths.Config, remote.ConfigPath} {
		body, _ := os.ReadFile(path)
		if strings.Contains(string(body), `"name": "alice"`) {
			t.Fatalf("over-quota user retained on %s", path)
		}
	}
}
