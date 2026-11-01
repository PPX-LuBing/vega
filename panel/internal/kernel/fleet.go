package kernel

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

type CollectResult struct {
	Machine  string
	Up, Down int64
	Err      error
}

// CollectAll keeps machine checkpoints independent even when API addresses match.
func CollectAll(ctx context.Context, st *store.Store, paths Paths) []CollectResult {
	machines, err := ManagedMachines(st, paths)
	if err != nil {
		return []CollectResult{{Err: err}}
	}
	results := make([]CollectResult, len(machines))
	forEachMachine(machines, func(i int, m store.Machine) {
		r := CollectResult{Machine: m.Name}
		var body []byte
		if m.Name == store.LocalMachine {
			body, r.Err = fetchStatsBodyContext(ctx, MachinePaths(m), false)
		} else {
			body, r.Err = sshOutput(ctx, m, shellQuote(m.StatsBin)+" "+shellQuote("--server="+m.APIAddr)+" -pattern 'user>>>'", "")
		}
		if r.Err == nil {
			r.Up, r.Down, r.Err = recordStats(st, m.Name, body)
		}
		results[i] = r
	})
	return results
}

type MachineStatus struct {
	Machine store.Machine
	State   string
	Snapshot
	Err error
}

func ObserveAll(ctx context.Context, st *store.Store, paths Paths) []MachineStatus {
	machines, err := ManagedMachines(st, paths)
	if err != nil {
		return []MachineStatus{{Err: err}}
	}
	results := make([]MachineStatus, len(machines))
	forEachMachine(machines, func(i int, m store.Machine) {
		r := MachineStatus{Machine: m, State: "unknown"}
		if m.Name == store.LocalMachine {
			r.State = serviceStateContext(ctx, m.Service)
			r.Snapshot, r.Err = observeWithGetter(func(path string) ([]byte, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+m.ClashAddr+path, nil)
				if err != nil {
					return nil, err
				}
				return httpReadJSON(req)
			})
		} else {
			state, err := sshOutput(ctx, m, "systemctl is-active "+shellQuote(m.Service)+" || true", "")
			if err == nil {
				r.State = strings.TrimSpace(string(state))
			}
			r.Snapshot, r.Err = observeWithGetter(func(path string) ([]byte, error) {
				return sshOutput(ctx, m, "curl --silent --show-error --fail --max-time 5 "+shellQuote("http://"+m.ClashAddr+path), "")
			})
		}
		results[i] = r
	})
	return results
}

// Bound concurrent external operations so one slow host does not stall the fleet.
func forEachMachine(machines []store.Machine, run func(int, store.Machine)) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for i, m := range machines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			run(i, m)
		}()
	}
	wg.Wait()
}

func sshOutput(ctx context.Context, m store.Machine, script, input string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	port := m.SSHPort
	if port == 0 {
		port = 22
	}
	cmd := exec.CommandContext(ctx, "ssh", "-p", fmt.Sprint(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", m.SSHUser+"@"+m.Host, script)
	cmd.Stdin = strings.NewReader(input)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), nil
}
