package sub

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Opt in explicitly: native config check alone never validates remote content.
func TestNativeRuleDownloadsWithRealKernel(t *testing.T) {
	bin := os.Getenv("VEGA_TEST_KERNEL")
	if bin == "" || os.Getenv("VEGA_TEST_RULE_DOWNLOADS") != "1" {
		t.Skip("set VEGA_TEST_KERNEL and VEGA_TEST_RULE_DOWNLOADS=1 for live asset validation")
	}
	for _, raw := range singboxRuleSets() {
		set := raw.(map[string]any)
		t.Run(set["tag"].(string), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, set["url"].(string), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("HTTP %d", response.StatusCode)
			}
			const maxSize = 16 << 20
			body, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
			if err != nil {
				t.Fatal(err)
			}
			if len(body) == 0 || len(body) > maxSize {
				t.Fatalf("unexpected rule-set size: %d", len(body))
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			if err := os.WriteFile(input, body, 0600); err != nil {
				t.Fatal(err)
			}
			operation := "compile"
			if set["format"] == "binary" {
				operation = "decompile"
			}
			out, err := exec.CommandContext(ctx, bin, "rule-set", operation, "--output", filepath.Join(dir, "output"), input).CombinedOutput()
			if err != nil {
				t.Fatalf("core cannot parse remote %s asset: %v: %s", set["format"], err, out)
			}
			t.Logf("HTTP 200, %d bytes, native %s passed", len(body), operation)
		})
	}
}
