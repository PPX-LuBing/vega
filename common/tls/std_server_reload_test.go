package tls

import (
	"crypto/tls"
	"net"
	"sync"
	"testing"
)

func TestServerConfigConcurrentPublication(t *testing.T) {
	c := &STDServerConfig{config: &tls.Config{}}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			c.SetServerName("example.com")
			c.SetNextProtos([]string{"nw3"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			config, _ := c.STDConfig()
			_ = config.Clone()
			_, _ = c.Client(a)
			_, _ = c.Server(b)
			_ = c.Clone()
		}
	}()
	wg.Wait()
}
