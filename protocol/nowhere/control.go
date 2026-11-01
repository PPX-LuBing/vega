package nowhere

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

var (
	controlMu       sync.Mutex
	controlInbounds = map[string]*Inbound{}
	controlServer   *http.Server
	controlListen   string
	controlSecret   string
)

type controlUser struct {
	Name      string `json:"name"`
	SharedKey string `json:"shared_key"`
}

type controlRequest struct {
	Inbound string         `json:"inbound,omitempty"`
	Users   *[]controlUser `json:"users"`
}

type controlResponse struct {
	OK      bool     `json:"ok"`
	Updated []string `json:"updated,omitempty"`
	Users   int      `json:"users"`
	Error   string   `json:"error,omitempty"`
}

func (h *Inbound) registerControl(addr string) error {
	if addr == "off" {
		return nil
	}
	secret := h.options.ControlSecret
	if !isLoopback(addr) || strings.TrimSpace(secret) == "" {
		return fmt.Errorf("nowhere: control endpoint requires a loopback address and control_secret")
	}
	// Resolve localhost ourselves rather than trusting hostname resolution.
	if host, port, _ := net.SplitHostPort(addr); host == "localhost" {
		addr = net.JoinHostPort("127.0.0.1", port)
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	if _, exists := controlInbounds[h.Tag()]; exists {
		return fmt.Errorf("nowhere: duplicate control inbound %q", h.Tag())
	}
	if controlServer != nil {
		if controlListen != addr || controlSecret != secret {
			return fmt.Errorf("nowhere: control address and secret must match across inbounds")
		}
		controlInbounds[h.Tag()] = h
		return nil
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("nowhere: listen control endpoint: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/users", handleControlUsers)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeControl(w, http.StatusOK, controlResponse{OK: true, Updated: controlTags()})
	})
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+secret)) != 1 {
				writeControl(w, http.StatusUnauthorized, controlResponse{Error: "unauthorized"})
				return
			}
			mux.ServeHTTP(w, r)
		}),
	}
	controlServer, controlListen, controlSecret = server, addr, secret
	controlInbounds[h.Tag()] = h
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (h *Inbound) unregisterControl() error {
	controlMu.Lock()
	defer controlMu.Unlock()
	if controlInbounds[h.Tag()] != h {
		return nil
	}
	delete(controlInbounds, h.Tag())
	if len(controlInbounds) != 0 || controlServer == nil {
		return nil
	}
	err := controlServer.Close()
	controlServer, controlListen, controlSecret = nil, "", ""
	return err
}

func controlTags() []string {
	controlMu.Lock()
	defer controlMu.Unlock()
	return controlTagsLocked()
}

func controlTagsLocked() []string {
	out := make([]string, 0, len(controlInbounds))
	for tag := range controlInbounds {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func handleControlUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeControl(w, http.StatusMethodNotAllowed, controlResponse{Error: "POST or PUT required"})
		return
	}
	var request controlRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeControl(w, http.StatusBadRequest, controlResponse{Error: "invalid JSON: " + err.Error()})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF || request.Users == nil {
		writeControl(w, http.StatusBadRequest, controlResponse{Error: "users must be an explicit array; only one JSON object is allowed"})
		return
	}
	users, err := parseControlUsers(*request.Users)
	if err != nil {
		writeControl(w, http.StatusBadRequest, controlResponse{Error: err.Error()})
		return
	}
	controlMu.Lock()
	defer controlMu.Unlock()
	targets := make([]*Inbound, 0, len(controlInbounds))
	if request.Inbound != "" {
		target, ok := controlInbounds[request.Inbound]
		if !ok {
			writeControl(w, http.StatusNotFound, controlResponse{Error: "unknown inbound: " + request.Inbound})
			return
		}
		targets = append(targets, target)
	} else {
		for _, target := range controlInbounds {
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 {
		writeControl(w, http.StatusServiceUnavailable, controlResponse{Error: "no registered nowhere inbounds"})
		return
	}
	// Validate every target before changing any of them.
	for _, target := range targets {
		if len(target.options.Users) == 0 {
			writeControl(w, http.StatusBadRequest, controlResponse{Error: "user updates require multi-user mode"})
			return
		}
	}
	updated := make([]string, 0, len(targets))
	for _, target := range targets {
		if api := service.FromContext[adapter.V2RayServer](target.ctx); api != nil {
			if stats, ok := api.StatsService().(interface{ RegisterUsers([]string) }); ok {
				names := make([]string, 0, len(users))
				for _, user := range users {
					names = append(names, user.Name)
				}
				stats.RegisterUsers(names)
			}
		}
		if err = target.server.UpdateUsers(users); err != nil {
			writeControl(w, http.StatusBadRequest, controlResponse{Error: err.Error(), Updated: updated})
			return
		}
		updated = append(updated, target.Tag())
	}
	sort.Strings(updated)
	writeControl(w, http.StatusOK, controlResponse{OK: true, Updated: updated, Users: len(users)})
}

func parseControlUsers(items []controlUser) ([]portal.User, error) {
	users := make([]portal.User, 0, len(items))
	names, keys := map[string]bool{}, map[string]bool{}
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" || names[name] || keys[item.SharedKey] {
			return nil, fmt.Errorf("users require unique nonempty names and keys")
		}
		if err := wire.ValidateServiceKey(item.SharedKey); err != nil {
			return nil, err
		}
		names[name], keys[item.SharedKey] = true, true
		users = append(users, portal.User{Name: name, SharedKey: item.SharedKey})
	}
	return users, nil
}

func writeControl(w http.ResponseWriter, status int, payload controlResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
