package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func runOperations(dbPath string, paths kernel.Paths, args []string) error {
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var asJSON, test bool
	var count int
	switch args[0] {
	case "traffic":
		fs.IntVar(&count, "hours", 24, "history window, 1..720 hours")
		fs.BoolVar(&asJSON, "json", false, "JSON output")
	case "events":
		fs.IntVar(&count, "limit", 50, "latest events, 1..1000")
		fs.BoolVar(&asJSON, "json", false, "JSON output")
	case "alert":
		fs.BoolVar(&test, "test", false, "send a test to the configured webhook")
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	switch args[0] {
	case "traffic":
		points, err := st.TrafficHistory(time.Now(), count)
		if err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(points)
		}
		for _, p := range points {
			fmt.Printf("%s  up=%s down=%s\n", time.Unix(p.Hour, 0).Format("2006-01-02 15:00"), kernel.HumanBytes(p.Up), kernel.HumanBytes(p.Down))
		}
	case "events":
		events, err := st.Events(count)
		if err != nil {
			return err
		}
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(events)
		}
		for _, e := range events {
			fmt.Printf("%s %-12s %q %s\n", time.Unix(e.At, 0).Format(time.RFC3339), e.Kind, e.User, e.Message)
		}
	case "alert":
		if !test {
			return fmt.Errorf("usage: alert --test")
		}
		address := st.Setting("alert_webhook", "")
		if address == "" {
			return fmt.Errorf("configure alert_webhook first")
		}
		if err := kernel.SendAlert(context.Background(), address, []store.Event{{At: time.Now().Unix(), Kind: "test", Message: "Vega alert test"}}); err != nil {
			return err
		}
		fmt.Println("Test alert delivered.")
	case "doctor":
		return doctor(st, paths)
	}
	return nil
}

// Doctor checks local configuration without replacing it or restarting services.
// Remote certificate paths must be checked on their host during apply.
func doctor(st *store.Store, paths kernel.Paths) error {
	nodes, err := st.Nodes()
	if err != nil {
		return err
	}
	failures := 0
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		if err := store.ValidateNode(n); err != nil {
			fmt.Printf("FAIL node %s: %v\n", n.Tag, err)
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d invalid nodes", failures)
	}
	machines, err := kernel.ManagedMachines(st, paths)
	if err != nil {
		return err
	}
	for _, m := range machines {
		cfg, err := kernel.BuildConfigFor(st, kernel.MachinePaths(m), m.Name)
		if err != nil {
			return err
		}
		if m.Name != store.LocalMachine {
			fmt.Printf("SKIP %s: configuration generated; remote files/kernel not checked\n", m.Name)
			continue
		}
		dir, err := os.MkdirTemp("", "vega-doctor-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		check := kernel.MachinePaths(m)
		check.Config = filepath.Join(dir, "config.json")
		body, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if err := os.WriteFile(check.Config, body, 0600); err != nil {
			return err
		}
		if err := kernel.Check(check); err != nil {
			return err
		}
		fmt.Println("OK local: kernel check passed; service was not changed")
	}
	checkEnforceCollector()
	return nil
}

// checkEnforceCollector 提醒 vega-enforce 是否在跑。
//
// 它不参与配置生成，所以以前完全不在体检范围里——结果就是「配置全对、
// 服务也 active，但流量统计恒为 0」这种问题能拖两周没被发现。
// 这里只提示，不让 doctor 失败：没有 systemd 的环境（容器、开发机）本来就没有它。
func checkEnforceCollector() {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return // 不是 systemd 环境，跳过
	}
	out, err := exec.Command("systemctl", "is-active", "vega-enforce").Output()
	state := strings.TrimSpace(string(out))
	if err == nil && state == "active" {
		fmt.Println("OK enforce: 流量采集服务在跑")
		return
	}
	fmt.Printf("WARN enforce: vega-enforce 当前 %q —— 流量统计不会更新\n", orUnknown(state))
	fmt.Println("     修法: systemctl enable --now vega-enforce")
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "未安装或未启动"
	}
	return s
}
