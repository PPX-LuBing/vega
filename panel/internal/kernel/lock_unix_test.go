//go:build unix

package kernel

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestConfigLockReleasedWhenProcessExits(t *testing.T) {
	if path := os.Getenv("VEGA_TEST_LOCK"); path != "" {
		if _, err := lockConfig(path); err != nil {
			t.Fatal(err)
		}
		os.Exit(0) // Skip unlock to simulate a terminated deploy process.
	}
	path := filepath.Join(t.TempDir(), "config.lock")
	unlock, err := lockConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := lockConfig(path); err == nil {
		other()
		t.Fatal("concurrent deployment lock acquired")
	}
	unlock()
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigLockReleasedWhenProcessExits$")
	cmd.Env = append(os.Environ(), "VEGA_TEST_LOCK="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v: %s", err, out)
	}
	unlock, err = lockConfig(path)
	if err != nil {
		t.Fatalf("stale lock after process exit: %v", err)
	}
	unlock()
}
