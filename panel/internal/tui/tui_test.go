package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func TestViewUsesOnlyCachedState(t *testing.T) {
	m := testModel(t)
	if err := m.store.SaveMachine(store.Machine{Name: "slow", Host: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	m.reload()
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		marker := filepath.Join(dir, "called")
		t.Setenv("VIEW_MARKER", marker)
		if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\necho called > \"$VIEW_MARKER\"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir)
		for tab := 0; tab < tabCount; tab++ {
			m.tab = tab
			_ = m.View()
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("View started an external process")
		}
	}
	// Database access in View would now panic; all grant counts must be cached.
	st := m.store
	m.store = nil
	defer func() { m.store = st }()
	start := time.Now()
	for tab := 0; tab < tabCount; tab++ {
		m.tab = tab
		_ = m.View()
	}
	if time.Since(start) > time.Second {
		t.Fatal("View blocked on a probe")
	}
}

func TestBackgroundActionLeavesNavigationResponsive(t *testing.T) {
	m := testModel(t)
	started, release := make(chan struct{}), make(chan struct{})
	_, cmd := m.action("testing", func() actionMsg { close(started); <-release; return actionMsg{text: "done"} })
	if cmd == nil || !m.busy {
		t.Fatal("action was not queued")
	}
	finished := make(chan tea.Msg, 1)
	go func() { finished <- cmd() }()
	<-started
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	if m.tab != tabUsers {
		t.Fatal("navigation blocked by action")
	}
	if _, duplicate := m.collect(); duplicate != nil {
		t.Fatal("duplicate action accepted")
	}
	close(release)
	_, refresh := m.Update(<-finished)
	if m.busy || m.status != "done" || refresh == nil {
		t.Fatal("completion did not update UI")
	}
	// A command queued before shutdown must not access the closed store later.
	m.Close()
	if got := refresh(); got != nil {
		t.Fatalf("command ran after close: %v", got)
	}
}

func TestFormAcceptsUnicodePasteAndDeletesWholeRune(t *testing.T) {
	m := testModel(t)
	m.tab = tabUsers
	m.startAdd()
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("香港用户alice")})
	if got := m.form.values[0]; got != "香港用户alice" {
		t.Fatal(got)
	}
	m.form.values[0] = "香港"
	m.handleKey(tea.KeyMsg{Type: tea.KeyBackspace})
	if got := m.form.values[0]; got != "香" || !utf8.ValidString(got) {
		t.Fatal(got)
	}
}

func TestInvalidFormLimitsDoNotBecomeUnlimited(t *testing.T) {
	for _, limits := range [][2]string{{"abc", "0"}, {"NaN", "0"}, {"0", "-1"}, {"0", "forever"}} {
		t.Run(fmt.Sprint(limits), func(t *testing.T) {
			m := testModel(t)
			if err := m.submitUserForm([]string{"invalid", limits[0], limits[1]}); err == nil {
				t.Fatal("invalid limits accepted")
			}
			if _, err := m.store.User("invalid"); err == nil {
				t.Fatal("invalid user saved")
			}
		})
	}
}

func TestNodeFormCanCreateTLSAndRealityNodes(t *testing.T) {
	m := testModel(t)
	for _, n := range []store.Node{
		{Tag: "tls-form", Proto: store.ProtoNowhere, Port: 8443, TLSMode: "tls", CertPath: "cert.pem", KeyPath: "key.pem", Machine: store.LocalMachine},
		{Tag: "reality-form", Proto: store.ProtoVLESS, Port: 8444, TLSMode: "reality", SNI: "example.com", Dest: "example.com:443", Machine: store.LocalMachine},
	} {
		fields := nodeFields(n)
		values := make([]string, len(fields))
		for i, f := range fields {
			values[i] = f.def
		}
		if err := m.submitNodeForm(values); err != nil {
			t.Fatal(err)
		}
		saved, err := m.store.Node(n.Tag)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ValidateNode(saved); err != nil {
			t.Fatal(err)
		}
		if n.TLSMode == "reality" && (saved.PrivKey == "" || saved.PubKey == "") {
			t.Fatal("REALITY keys not generated")
		}
	}
	m.height = 24
	m.form = newForm("node", nodeFields(store.Node{}), nil)
	m.form.cursor = len(m.form.fields) - 1
	view := m.viewForm()
	if !strings.Contains(view, "18") || strings.Count(view, "\n") > 18 {
		t.Fatal("form does not scroll to last field")
	}
}

func TestEditRemarkPreservesExpiry(t *testing.T) {
	for _, delta := range []time.Duration{-time.Hour, time.Hour, 30 * 24 * time.Hour} {
		m := testModel(t)
		u, err := m.store.User("alice")
		if err != nil {
			t.Fatal(err)
		}
		u.ExpiresAt = time.Now().Add(delta).Unix()
		if err = m.store.SaveUser(u); err != nil {
			t.Fatal(err)
		}
		m.reload()
		m.tab = tabUsers
		for i, user := range m.users {
			if user.Name == "alice" {
				m.cursor = i
			}
		}
		m.startEdit()
		m.form.values[2] = "new remark"
		if err = m.form.submit(m.form.values); err != nil {
			t.Fatal(err)
		}
		after, err := m.store.User("alice")
		if err != nil {
			t.Fatal(err)
		}
		if after.ExpiresAt != u.ExpiresAt {
			t.Fatalf("expiry changed: %d -> %d", u.ExpiresAt, after.ExpiresAt)
		}
	}
}

func testModel(t *testing.T) *Model {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err = st.SaveNode(store.Node{Tag: "hk-nw", Proto: store.ProtoNowhere, Port: 8443,
		TLSMode: "tls", Enabled: true, Morph: true}); err != nil {
		t.Fatal(err)
	}
	if err = st.SaveNode(store.Node{Tag: "hk-off", Proto: store.ProtoAnyTLS, Port: 8444,
		TLSMode: "tls", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err = st.SaveUser(store.User{Name: "alice", Enabled: true, QuotaBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if err = st.SaveUser(store.User{Name: "bob", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err = st.Grant("hk-nw", "alice"); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTraffic("alice", 1<<28, 1<<29, ""); err != nil {
		t.Fatal(err)
	}
	m := New(st, kernel.Paths{Service: "sbx", Bin: "/usr/local/bin/sbx",
		Config: "/etc/sbx/config.json", APIAddr: "127.0.0.1:10085"})
	t.Cleanup(m.Close)
	return m
}

// 每一页都要能渲染出内容，且带上关键信息。
func TestViewRendersEveryTab(t *testing.T) {
	m := testModel(t)
	for tab := 0; tab < tabCount; tab++ {
		m.tab = tab
		out := m.View()
		if strings.TrimSpace(out) == "" {
			t.Fatalf("第 %d 页渲染为空", tab)
		}
		if !strings.Contains(out, tabNames[tab]) {
			t.Errorf("第 %d 页标题缺失", tab)
		}
	}
}

func TestNodeTabShowsNodes(t *testing.T) {
	m := testModel(t)
	m.tab = tabNodes
	out := m.View()
	for _, want := range []string{"hk-nw", "nowhere", "8443", "hk-off"} {
		if !strings.Contains(out, want) {
			t.Errorf("节点页缺少 %q", want)
		}
	}
}

func TestUserTabShowsUsageAndQuota(t *testing.T) {
	m := testModel(t)
	m.tab = tabUsers
	out := m.View()
	// alice 用了 768MB / 配额 1GB -> 应当显示用量与配额
	if !strings.Contains(out, "alice") {
		t.Error("用户页缺少 alice")
	}
	if !strings.Contains(out, "1.00 GB") {
		t.Error("用户页缺少配额显示")
	}
	if !strings.Contains(out, "停用") {
		t.Error("用户页应标出 bob 是停用状态")
	}
}

func TestTrafficTabShowsProgress(t *testing.T) {
	m := testModel(t)
	m.tab = tabTraffic
	out := m.View()
	if !strings.Contains(out, "█") {
		t.Error("流量页缺少进度条")
	}
	if !strings.Contains(out, "不限") {
		t.Error("无配额用户应显示「不限」")
	}
}

// 新增用户：走表单提交，落库后应出现在列表里。
func TestAddUserThroughForm(t *testing.T) {
	m := testModel(t)
	m.tab = tabUsers

	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = model.(*Model)
	if m.mode != modeForm || m.form == nil {
		t.Fatal("按 a 应当进入表单")
	}

	// 填名字（配额与天数用默认值 0）
	for _, ch := range "carol" {
		model, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = model.(*Model)
	}
	model, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	m = model.(*Model)

	if m.mode != modeGrants {
		t.Fatalf("提交后应进入授权模式，实际 %v", m.mode)
	}
	user, err := m.store.User("carol")
	if err != nil {
		t.Fatalf("用户没有落库: %v", err)
	}
	// 凭据要自动生成，尤其是 nowhere 密钥的格式
	if len(user.SharedKey) != 32 {
		t.Errorf("Nowhere 密钥长度应为 32，实际 %d (%q)", len(user.SharedKey), user.SharedKey)
	}
	if user.UUID == "" || user.Password == "" {
		t.Error("UUID 与口令应当自动生成")
	}
}

// 删除需要二次确认，且取消后不能真删。
func TestDeleteRequiresConfirmation(t *testing.T) {
	m := testModel(t)
	m.tab = tabNodes
	m.cursor = 0
	tag := m.nodes[0].Tag

	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = model.(*Model)
	if m.mode != modeConfirm {
		t.Fatal("按 d 应当进入确认模式")
	}

	model, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = model.(*Model)
	if _, err := m.store.Node(tag); err != nil {
		t.Fatal("取消后节点不应被删除")
	}

	// 再来一次并确认
	model, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = model.(*Model)
	model, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	m = model.(*Model)
	if _, err := m.store.Node(tag); err == nil {
		t.Fatal("确认后节点应当被删除")
	}
}

// 空格切换启停。
func TestSpaceTogglesEnabled(t *testing.T) {
	m := testModel(t)
	m.tab = tabNodes
	m.cursor = 0
	before := m.nodes[0].Enabled

	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeySpace})
	m = model.(*Model)
	after, err := m.store.Node(m.nodes[0].Tag)
	if err != nil {
		t.Fatal(err)
	}
	if after.Enabled == before {
		t.Fatalf("启停没有切换: %v -> %v", before, after.Enabled)
	}
}

func TestFormEscCancels(t *testing.T) {
	m := testModel(t)
	m.tab = tabUsers
	model, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = model.(*Model)

	model, _ = m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	m = model.(*Model)
	if m.mode != modeBrowse || m.form != nil {
		t.Fatal("Esc 应当退出表单且不落库")
	}
	if _, err := m.store.User(""); err == nil {
		t.Fatal("不应创建空用户")
	}
}

func TestProgressBar(t *testing.T) {
	if got := progressBar(0, 0, 10); !strings.Contains(got, "不限") {
		t.Errorf("无配额应显示不限，实际 %q", got)
	}
	full := progressBar(100, 100, 10)
	if !strings.Contains(full, "100%") {
		t.Errorf("满额应显示 100%%，实际 %q", full)
	}
	// 超额不能画出超过宽度的条
	over := progressBar(999, 100, 10)
	if strings.Count(over, "█") > 10 {
		t.Errorf("超额时进度条超宽: %q", over)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 10); got != "abcdef" {
		t.Errorf("不该截断: %q", got)
	}
	if got := truncate("abcdefghij", 5); got != "abcd…" {
		t.Errorf("截断结果错误: %q", got)
	}
	// 多字节字符按 rune 截，不能切坏
	if got := truncate("香港台湾日本", 3); got != "香港…" {
		t.Errorf("中文截断错误: %q", got)
	}
}

func TestParseGBAndDays(t *testing.T) {
	if got, err := kernel.ParseQuotaGB("2"); err != nil || got != 2<<30 {
		t.Errorf("parseGB(2) = %d", got)
	}
	if got, err := kernel.ParseQuotaGB("0.5"); err != nil || got != 1<<29 {
		t.Errorf("parseGB(0.5) = %d", got)
	}
	for _, bad := range []string{"", "abc", "-1", "NaN", "Inf", "1e100", "1e-20"} {
		if _, err := kernel.ParseQuotaGB(bad); err == nil {
			t.Errorf("accepted invalid quota %q", bad)
		}
	}
	if got, err := kernel.ParseExpiryDays("0"); err != nil || got != 0 {
		t.Errorf("parseDays(0) 应为 0，实际 %d", got)
	}
	if expires, err := kernel.ParseExpiryDays("30"); err != nil || expires == 0 {
		t.Error("parseDays(30) 不该是 0")
	}
	for _, bad := range []string{"", "-1", "abc", "365001", "1e100"} {
		if _, err := kernel.ParseExpiryDays(bad); err == nil {
			t.Errorf("accepted invalid days %q", bad)
		}
	}
}

// 回归：lipgloss 会把多行字符串的每一行补齐到最宽行的宽度。
// 一旦把 \n 塞进 Render()，后面的内容就会被空格推到右边，
// 表格看起来「选中行跑偏」。这里量表头与数据行的可见宽度是否一致。
func TestTableRowsAligned(t *testing.T) {
	m := testModel(t)
	for _, tc := range []struct {
		tab    int
		header string
	}{{tabNodes, "TAG"}, {tabUsers, "已用"}} {
		m.tab = tc.tab
		lines := strings.Split(m.View(), "\n")

		// 定位表头，然后一直取到空行为止——只量表格区域，不把帮助行算进来
		start := -1
		for i, line := range lines {
			if strings.Contains(line, tc.header) {
				start = i
				break
			}
		}
		if start < 0 {
			t.Fatalf("第 %d 页找不到表头 %q", tc.tab, tc.header)
		}
		var widths []int
		for _, line := range lines[start:] {
			if strings.TrimSpace(line) == "" {
				break
			}
			widths = append(widths, lipgloss.Width(strings.TrimRight(line, " ")))
		}
		if len(widths) < 2 {
			t.Fatalf("第 %d 页表格行不足: %v", tc.tab, widths)
		}
		for i, w := range widths {
			if w != widths[0] {
				t.Errorf("第 %d 页第 %d 行宽度 %d，与表头 %d 不一致（表格没对齐）",
					tc.tab, i, w, widths[0])
			}
		}
	}
}

func TestDeleteEnterMeansNo(t *testing.T) {
	for _, tab := range []int{tabNodes, tabUsers} {
		m := testModel(t)
		m.tab = tab
		m.startDelete()
		m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
		if m.mode != modeBrowse {
			t.Fatal("confirmation remained open")
		}
		if tab == tabNodes {
			if _, err := m.store.Node(m.nodes[0].Tag); err != nil {
				t.Fatal("Enter deleted node")
			}
		} else {
			if _, err := m.store.User(m.users[0].Name); err != nil {
				t.Fatal("Enter deleted user")
			}
		}
	}
}

func TestUserGrantWorkflow(t *testing.T) {
	m := testModel(t)
	m.tab = tabUsers
	m.startAdd()
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("new-user")})
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.mode != modeGrants {
		t.Fatal("new user did not enter grants")
	}
	tags, _ := m.store.NodesForUser("new-user")
	if len(tags) != 0 {
		t.Fatal("implicit grants")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeySpace})
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	tags, err := m.store.NodesForUser("new-user")
	if err != nil || len(tags) != 1 || tags[0] != m.nodes[0].Tag {
		t.Fatalf("grants: %v %v", tags, err)
	}
	m.startGrants("new-user")
	m.handleKey(tea.KeyMsg{Type: tea.KeySpace})
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	tags, _ = m.store.NodesForUser("new-user")
	if len(tags) != 1 {
		t.Fatal("cancel changed grants")
	}
	m.startGrants("new-user")
	m.handleKey(tea.KeyMsg{Type: tea.KeySpace})
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	tags, _ = m.store.NodesForUser("new-user")
	if len(tags) != 0 {
		t.Fatal("revoke failed")
	}
}

func TestViewFitsAndSelectionStaysVisible(t *testing.T) {
	m := testModel(t)
	for i := 0; i < 40; i++ {
		m.nodes = append(m.nodes, store.Node{Tag: fmt.Sprintf("node-%02d", i), Proto: "nowhere", Port: 8446, TLSMode: "tls", Enabled: true})
		m.users = append(m.users, store.User{Name: fmt.Sprintf("user-%02d", i)})
		m.machines = append(m.machines, store.Machine{Name: fmt.Sprintf("host-%02d", i)})
	}
	for _, size := range [][2]int{{80, 24}, {120, 36}, {40, 16}} {
		m.width, m.height = size[0], size[1]
		for tab := 0; tab < tabCount; tab++ {
			m.tab = tab
			m.cursor = 30
			out := m.View()
			if lipgloss.Width(out) > m.width || lipgloss.Height(out) > m.height {
				t.Fatalf("tab %d size=%v rendered %dx%d", tab, size, lipgloss.Width(out), lipgloss.Height(out))
			}
			if tab != tabOverview && !strings.Contains(out, "▸") {
				t.Fatal("selected row invisible")
			}
		}
	}
	m.tab = tabUsers
	m.showHelp = false
	before := m.View()
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	if before == m.View() {
		t.Fatal("help did nothing")
	}
}

func TestFormCursorEditingAndEnums(t *testing.T) {
	m := testModel(t)
	m.tab = tabUsers
	m.startAdd()
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("香港")})
	m.handleKey(tea.KeyMsg{Type: tea.KeyLeft})
	m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("新")})
	if m.form.values[0] != "香新港" {
		t.Fatal(m.form.values[0])
	}
	m.handleFormKey("delete")
	m.handleFormKey("backspace")
	if m.form.values[0] != "香" {
		t.Fatal(m.form.values[0])
	}
	m.handleFormKey("ctrl+u")
	if m.form.values[0] != "" {
		t.Fatal("clear failed")
	}
	m.tab = tabNodes
	m.startAdd()
	m.form.cursor = 1
	m.handleFormKey("right")
	if m.form.values[1] != store.ProtoAnyTLS {
		t.Fatal("protocol picker failed")
	}
}

func TestHelpBlocksHiddenActions(t *testing.T) {
	m := testModel(t)
	m.tab = tabNodes
	m.showHelp = true
	for _, key := range []string{"d", "a", "e", "r", " "} {
		_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		if cmd != nil || m.mode != modeBrowse || !m.showHelp {
			t.Fatalf("help allowed hidden action %q", key)
		}
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.showHelp {
		t.Fatal("help did not close")
	}
}
