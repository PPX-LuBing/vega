package kernel

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func TestNowhereEgressRoutedAfterPolicy(t *testing.T) {
	st := testStore(t)
	if err := st.SaveNode(store.Node{Tag: "nw", Proto: store.ProtoNowhere, Port: 8446, Enabled: true, NowhereCarrier: "both", NowhereEgress: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("nw", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("extra_config", `{"route":{"rules":[{"port":[25],"action":"reject"}]},"services":[{"type":"nowhere-egress","tag":"remote","server":"portal.example","server_port":443,"shared_key":"0123456789abcdef0123456789abcdef","tls":{"enabled":true}}]}`); err != nil {
		t.Fatal(err)
	}
	cfg, err := BuildConfig(st, testPaths())
	if err != nil {
		t.Fatal(err)
	}
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["carrier"] != "both" || in["egress"] != true {
		t.Fatal(in)
	}
	obs := cfg["outbounds"].([]any)
	exit := obs[len(obs)-1].(map[string]any)
	if exit["type"] != "nowhere-egress" || exit["portal"] != "nw" {
		t.Fatal(exit)
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if rules[len(rules)-2].(map[string]any)["action"] != "reject" || rules[len(rules)-1].(map[string]any)["outbound"] != "egress-nw" {
		t.Fatal(rules)
	}
	if len(cfg["services"].([]any)) != 1 {
		t.Fatal("Egress service lost")
	}
	if bin := os.Getenv("VEGA_TEST_KERNEL"); bin != "" {
		// Check wiring without relying on externally issued certificate files.
		in["tls"] = map[string]any{"enabled": true, "insecure": true}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "egress.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(bin, "check", "-c", path).CombinedOutput(); err != nil {
			t.Fatalf("generated Egress config: %s: %v", output, err)
		}
	}
}
