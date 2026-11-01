package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

type EnforceResult struct {
	Machine string
	Changed bool
	Err     error
}

// Enforce collects the entire fleet before evaluating shared user quotas.
// A changed config restarts that machine, closing existing sessions as well.
func Enforce(ctx context.Context, st *store.Store, paths Paths) []EnforceResult {
	var failures []EnforceResult
	for _, r := range CollectAll(ctx, st, paths) {
		if r.Err != nil {
			failures = append(failures, EnforceResult{Machine: r.Machine, Err: fmt.Errorf("collect before enforcement: %w", r.Err)})
		}
	}
	if len(failures) != 0 {
		return failures
	}
	machines, err := ManagedMachines(st, paths)
	if err != nil {
		return []EnforceResult{{Err: err}}
	}
	results := make([]EnforceResult, len(machines))
	forEachMachine(machines, func(i int, m store.Machine) {
		r := EnforceResult{Machine: m.Name}
		config, err := BuildConfigFor(st, MachinePaths(m), m.Name)
		if err != nil {
			r.Err = err
		} else {
			var current []byte
			if m.Name == store.LocalMachine {
				current, err = os.ReadFile(m.ConfigPath)
			} else {
				current, err = sshOutput(ctx, m, "cat "+shellQuote(m.ConfigPath), "")
			}
			if err != nil {
				r.Err = fmt.Errorf("read deployed config: %w", err)
			} else {
				desired, marshalErr := json.Marshal(config)
				if marshalErr != nil {
					r.Err = marshalErr
				} else if !sameConfig(current, desired) {
					push := PushToMachine(ctx, m, config)
					r.Err, r.Changed = push.Err, push.Err == nil
				}
			}
		}
		results[i] = r
	})
	return results
}

func sameConfig(left, right []byte) bool {
	var a, b any
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return false
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
