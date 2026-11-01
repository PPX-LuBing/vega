package v2rayapi

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

type statsTestOutbound struct{ adapter.Outbound }

func (statsTestOutbound) Tag() string { return "direct" }

func TestRegisterUsersEnablesAccounting(t *testing.T) {
	s := NewStatsService(option.V2RayStatsServiceOptions{Enabled: true, Users: []string{"alice"}})
	s.RegisterUsers([]string{"bob"})
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	counted := s.RoutedConnection(context.Background(), left, adapter.InboundContext{User: "bob"}, nil, statsTestOutbound{})
	go func() { _, _ = right.Write([]byte("ping")) }()
	if _, err := counted.Read(make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	response, err := s.GetStats(context.Background(), &GetStatsRequest{Name: "user>>>bob>>>traffic>>>uplink"})
	if err != nil || response.Stat.Value != 4 {
		t.Fatalf("counter: %v %v", response, err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.RegisterUsers([]string{"bob"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			s.RoutedConnection(context.Background(), left, adapter.InboundContext{User: "bob"}, nil, statsTestOutbound{})
		}
	}()
	wg.Wait()
}

func TestRegisterUsersWithStatsDisabled(t *testing.T) {
	s := NewStatsService(option.V2RayStatsServiceOptions{})
	s.RegisterUsers([]string{"alice"})
}
