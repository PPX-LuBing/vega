package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
)

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
	return New(st, kernel.Paths{Service: "sbx", Bin: "/usr/local/bin/sbx",
		Config: "/etc/sbx/config.json", APIAddr: "127.0.0.1:10085"})
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

	if m.mode != modeBrowse {
		t.Fatalf("提交后应回到浏览模式，实际 %v", m.mode)
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
	if got := parseGB("2"); got != 2<<30 {
		t.Errorf("parseGB(2) = %d", got)
	}
	if got := parseGB("0.5"); got != 1<<29 {
		t.Errorf("parseGB(0.5) = %d", got)
	}
	for _, bad := range []string{"", "abc", "-1", "0"} {
		if got := parseGB(bad); got != 0 {
			t.Errorf("parseGB(%q) 应为 0，实际 %d", bad, got)
		}
	}
	if got := parseDays("0"); got != 0 {
		t.Errorf("parseDays(0) 应为 0，实际 %d", got)
	}
	if parseDays("30") == 0 {
		t.Error("parseDays(30) 不该是 0")
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
			widths = append(widths, len([]rune(strings.TrimRight(line, " "))))
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
