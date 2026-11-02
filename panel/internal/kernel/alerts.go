package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func SendAlert(ctx context.Context, address string, events []store.Event) error {
	if address == "" || len(events) == 0 {
		return nil
	}
	var lines []string
	for _, e := range events {
		lines = append(lines, e.User+": "+e.Message)
	}
	body, err := json.Marshal(map[string]any{"text": strings.Join(lines, "\n"), "events": events})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("invalid webhook request")
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed (check endpoint and connectivity)")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook HTTP %d", resp.StatusCode)
	}
	return nil
}

func notifyUsage(ctx context.Context, st *store.Store) {
	events, err := st.UsageEvents(time.Now())
	if err == nil {
		err = SendAlert(ctx, st.Setting("alert_webhook", ""), events)
	}
	if err != nil {
		log.Printf("usage notification: %v", err)
		if recordErr := st.Event("alert_error", "", err.Error()); recordErr != nil {
			log.Printf("record alert failure: %v", recordErr)
		}
	}
}
