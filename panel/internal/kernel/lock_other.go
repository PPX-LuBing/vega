//go:build !unix

package kernel

import "fmt"

func lockConfig(string) (func(), error) {
	return nil, fmt.Errorf("local systemd deployment requires a Unix host; use SSH for Linux targets")
}
