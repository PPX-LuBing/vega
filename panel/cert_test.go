package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/cert"
	"github.com/PPX-LuBing/vega/panel/internal/kernel"
)

func TestCertChangeDoesNotRestartKernel(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "restarted")
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf restarted > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	logCertChange(cert.Change{Domain: "test.example", NotAfter: time.Now().Add(90 * 24 * time.Hour)})
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("certificate callback restarted kernel")
	}
}
func TestCertCheckMissingFails(t *testing.T) {
	if err := runCert(kernel.Paths{CertDir: t.TempDir()}, []string{"status", "--check", "--domain", "test.example"}); err == nil {
		t.Fatal("missing certificate check succeeded")
	}
}
