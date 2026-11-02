package kernel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func TestAlertsDoNotFollowRedirectsOrLeakURL(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("webhook followed redirect") }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Events []store.Event `json:"events"`
		}
		if r.Method != "POST" || json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload.Events) != 1 {
			t.Error("invalid payload")
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	events := []store.Event{{Kind: "warning", User: "alice", Message: "80 / 100 bytes"}}
	err := SendAlert(context.Background(), server.URL+"/?token=private-value", events)
	if err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatalf("unsafe error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = SendAlert(ctx, server.URL+"/?token=private-value", events)
	if err == nil || strings.Contains(err.Error(), "private-value") {
		t.Fatalf("unsafe transport error: %v", err)
	}
}
