// Package tui 是面板的终端界面。
//
// 设计取向：面板要展示的是「内核原生看不到的东西」——按用户的配额与用量、
// 跨节点的授权关系、Nowhere 这类自有协议的管理。所以首屏是概览与用量，
// 而不是内核配置本身。
package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// 配色：深色终端下可读，不用背景色避免和终端主题打架。
var (
	styleTitle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	styleTabOn    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("16")).Background(lipgloss.Color("205")).Padding(0, 1)
	styleTabOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)
	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleErr      = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleHelp     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleCursor   = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
)

const (
	tabOverview = iota
	tabNodes
	tabUsers
	tabTraffic
	tabMachines
	tabCount
)

var tabNames = []string{"概览", "节点", "用户", "流量", "机器"}

// mode 是界面当前所处的交互模式。
type mode int

const (
	modeBrowse mode = iota
	modeForm
	modeConfirm
)

// Model 是 TUI 的状态。
type Model struct {
	store *store.Store
	paths kernel.Paths

	tab    int
	cursor int
	mode   mode

	nodes    []store.Node
	users    []store.User
	machines []store.Machine
	usage    map[string][2]int64
	snapshot kernel.Snapshot
	snapErr  error

	// 表单
	form      *form
	confirm   string
	confirmFn func() error

	status  string
	isError bool

	width, height int
	quit          bool
}

// New 构造面板模型。
func New(st *store.Store, paths kernel.Paths) *Model {
	m := &Model{store: st, paths: paths, usage: map[string][2]int64{}}
	m.reload()
	m.setStatus("就绪。按 ? 看帮助。")
	return m
}

// reload 从数据库重新读取全部状态。
func (m *Model) reload() {
	if nodes, err := m.store.Nodes(); err == nil {
		m.nodes = nodes
	}
	if users, err := m.store.Users(); err == nil {
		m.users = users
	}
	if machines, err := m.store.Machines(); err == nil {
		m.machines = machines
	}
	if usage, err := m.store.AllUsage(); err == nil {
		m.usage = usage
	}
	m.clampCursor()
}

func (m *Model) clampCursor() {
	limit := m.rowCount()
	if m.cursor >= limit {
		m.cursor = limit - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// rowCount 返回当前页面的可选行数。
func (m *Model) rowCount() int {
	switch m.tab {
	case tabNodes:
		return len(m.nodes)
	case tabUsers:
		return len(m.users)
	case tabTraffic:
		return len(m.users)
	case tabMachines:
		return len(m.machines)
	}
	return 0
}

func (m *Model) setStatus(format string, args ...any) {
	m.status = fmt.Sprintf(format, args...)
	m.isError = false
}

func (m *Model) setError(format string, args ...any) {
	m.status = fmt.Sprintf(format, args...)
	m.isError = true
}

// Init 实现 tea.Model。启动时拉一次内核可观测数据。
func (m *Model) Init() tea.Cmd { return fetchSnapshotCmd(m.paths) }

// snapshotMsg 是异步拉取内核状态的结果。
type snapshotMsg struct {
	snapshot kernel.Snapshot
	err      error
}

// fetchSnapshotCmd 异步读 clash_api。
//
// 必须异步：Observe 有 5 秒超时，同步调用会让整个界面卡住。
func fetchSnapshotCmd(paths kernel.Paths) tea.Cmd {
	return func() tea.Msg {
		snapshot, err := kernel.Observe(paths.ClashAddr)
		return snapshotMsg{snapshot: snapshot, err: err}
	}
}

// Update 实现 tea.Model。
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case snapshotMsg:
		m.snapshot, m.snapErr = msg.snapshot, msg.err
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// 表单模式独占按键
	if m.mode == modeForm && m.form != nil {
		return m.handleFormKey(key)
	}
	// 确认模式
	if m.mode == modeConfirm {
		switch key {
		case "y", "Y", "enter":
			if m.confirmFn != nil {
				if err := m.confirmFn(); err != nil {
					m.setError("失败: %v", err)
				} else {
					m.setStatus("已完成。")
				}
			}
			m.reload()
		case "n", "N", "esc", "q":
			m.setStatus("已取消。")
		}
		m.mode = modeBrowse
		m.confirmFn = nil
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		m.quit = true
		return m, tea.Quit
	case "1", "2", "3", "4", "5":
		m.tab = int(key[0] - '1')
		m.cursor = 0
	case "u":
		// 手动刷新内核状态
		m.setStatus("正在读取内核状态…")
		return m, fetchSnapshotCmd(m.paths)
	case "tab":
		m.tab = (m.tab + 1) % tabCount
		m.cursor = 0
	case "shift+tab":
		m.tab = (m.tab + tabCount - 1) % tabCount
		m.cursor = 0
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < m.rowCount()-1 {
			m.cursor++
		}
	case "a":
		return m.startAdd()
	case "e":
		return m.startEdit()
	case "d":
		return m.startDelete()
	case "space", " ":
		// bubbletea 对空格返回的 key 名在不同版本里是 "space" 或 " "，两个都接
		return m.toggleEnabled()
	case "r":
		return m.apply()
	case "c":
		return m.collect()
	case "s":
		return m.syncUsers()
	}
	return m, nil
}

// ---------------------------------------------------------------- 动作

func (m *Model) apply() (tea.Model, tea.Cmd) {
	// 下发到所有登记的机器；一台失败不影响其它机器，所以逐个汇报
	results := kernel.ApplyAll(context.Background(), m.store, m.paths)
	var okCount, nodeTotal int
	var failures []string
	for _, r := range results {
		if r.Err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", r.Machine, r.Err))
			continue
		}
		okCount++
		nodeTotal += r.Nodes
	}
	if len(failures) > 0 {
		m.setError("下发 %d/%d 台成功（%d 个入站）；失败：%s",
			okCount, len(results), nodeTotal, strings.Join(failures, "；"))
		return m, nil
	}
	m.setStatus("已下发 %d 台机器、共 %d 个入站。", okCount, nodeTotal)
	return m, nil
}

// syncUsers 把用户名单推给运行中的内核，不重启。
//
// 这是 sing-box 原生没有的能力：配额摘人、加人都不用断线。
// 只有 nowhere 协议支持（自有协议才有运行期换名单的接口）。
func (m *Model) syncUsers() (tea.Model, tea.Cmd) {
	results := kernel.SyncNowhereNodes(m.store, m.paths)
	if len(results) == 0 {
		m.setStatus("没有启用的 nowhere 节点，无需同步。")
		return m, nil
	}
	var okCount, failed int
	var failures []string
	for _, r := range results {
		if r.Err != nil {
			failed++
			failures = append(failures, fmt.Sprintf("%s: %v", r.Inbound, r.Err))
			continue
		}
		okCount++
	}
	if failed > 0 {
		m.setError("同步 %d/%d 个节点成功；失败：%s", okCount, len(results), strings.Join(failures, "；"))
		return m, nil
	}
	m.setStatus("已运行期更新 %d 个 nowhere 节点的用户（未重启）。", okCount)
	return m, nil
}

func (m *Model) collect() (tea.Model, tea.Cmd) {
	up, down, err := kernel.Collect(m.store, m.paths)
	if err != nil {
		m.setError("采集失败: %v", err)
		return m, nil
	}
	m.reload()
	m.setStatus("采集完成：↑ %s / ↓ %s。", kernel.HumanBytes(up), kernel.HumanBytes(down))
	return m, nil
}

func (m *Model) toggleEnabled() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabNodes:
		if m.cursor < len(m.nodes) {
			node := m.nodes[m.cursor]
			node.Enabled = !node.Enabled
			if err := m.store.SaveNode(node); err != nil {
				m.setError("保存失败: %v", err)
			} else {
				m.setStatus("节点 %s 已%s。", node.Tag, enabledText(node.Enabled))
			}
		}
	case tabUsers:
		if m.cursor < len(m.users) {
			user := m.users[m.cursor]
			user.Enabled = !user.Enabled
			if err := m.store.SaveUser(user); err != nil {
				m.setError("保存失败: %v", err)
			} else {
				m.setStatus("用户 %s 已%s。", user.Name, enabledText(user.Enabled))
			}
		}
	}
	m.reload()
	return m, nil
}

func (m *Model) startDelete() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabNodes:
		if m.cursor < len(m.nodes) {
			tag := m.nodes[m.cursor].Tag
			m.confirm = fmt.Sprintf("删除节点 %s？它的授权关系也会一并删除。", tag)
			m.confirmFn = func() error { return m.store.DeleteNode(tag) }
			m.mode = modeConfirm
		}
	case tabUsers:
		if m.cursor < len(m.users) {
			name := m.users[m.cursor].Name
			m.confirm = fmt.Sprintf("删除用户 %s？授权与流量记录都会删除。", name)
			m.confirmFn = func() error { return m.store.DeleteUser(name) }
			m.mode = modeConfirm
		}
	}
	return m, nil
}

func (m *Model) startAdd() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabNodes:
		m.form = newForm("新增节点", []field{
			{label: "tag", hint: "唯一标识，如 hk-nowhere"},
			{label: "协议", hint: "nowhere/anytls/hysteria2/vless/trojan/shadowsocks", def: store.ProtoNowhere},
			{label: "端口", hint: "1-65535"},
			{label: "TLS 模式", hint: "tls/reality/none", def: "tls"},
			{label: "SNI", hint: "证书域名或 REALITY 伪装域名"},
			{label: "备注", hint: "给人看的名字"},
		}, m.submitNodeForm)
		m.mode = modeForm
	case tabUsers:
		m.form = newForm("新增用户", []field{
			{label: "用户名", hint: "不能含空格"},
			{label: "配额(GB)", hint: "0 表示不限", def: "0"},
			{label: "有效期(天)", hint: "0 表示永久", def: "0"},
		}, m.submitUserForm)
		m.mode = modeForm
	}
	return m, nil
}

func (m *Model) startEdit() (tea.Model, tea.Cmd) {
	switch m.tab {
	case tabNodes:
		if m.cursor >= len(m.nodes) {
			return m, nil
		}
		node := m.nodes[m.cursor]
		m.form = newForm("编辑节点 "+node.Tag, []field{
			{label: "端口", def: strconv.Itoa(node.Port)},
			{label: "TLS 模式", def: node.TLSMode},
			{label: "SNI", def: node.SNI},
			{label: "备注", def: node.Remark},
		}, func(values []string) error {
			node.Port, _ = strconv.Atoi(strings.TrimSpace(values[0]))
			node.TLSMode = strings.TrimSpace(values[1])
			node.SNI = strings.TrimSpace(values[2])
			node.Remark = strings.TrimSpace(values[3])
			return m.store.SaveNode(node)
		})
		m.mode = modeForm
	case tabUsers:
		if m.cursor >= len(m.users) {
			return m, nil
		}
		user := m.users[m.cursor]
		m.form = newForm("编辑用户 "+user.Name, []field{
			{label: "配额(GB)", def: gbText(user.QuotaBytes)},
			{label: "有效期(天)", def: daysText(user.ExpiresAt)},
			{label: "备注", def: user.Remark},
		}, func(values []string) error {
			user.QuotaBytes = parseGB(values[0])
			user.ExpiresAt = parseDays(values[1])
			user.Remark = strings.TrimSpace(values[2])
			return m.store.SaveUser(user)
		})
		m.mode = modeForm
	}
	return m, nil
}

func (m *Model) submitNodeForm(values []string) error {
	tag := strings.TrimSpace(values[0])
	proto := strings.TrimSpace(values[1])
	port, err := strconv.Atoi(strings.TrimSpace(values[2]))
	if err != nil {
		return fmt.Errorf("端口不是数字")
	}
	node := store.Node{
		Tag: tag, Proto: proto, Port: port,
		TLSMode: strings.TrimSpace(values[3]),
		SNI:     strings.TrimSpace(values[4]),
		Remark:  strings.TrimSpace(values[5]),
		Listen:  "0.0.0.0",
		Enabled: true,
		Morph:   true,
	}
	if node.Remark == "" {
		node.Remark = tag
	}
	if proto == store.ProtoShadowsocks && node.SSPassword == "" {
		node.SSPassword = store.NewSecret()
	}
	return m.store.SaveNode(node)
}

func (m *Model) submitUserForm(values []string) error {
	user := store.User{
		Name:       strings.TrimSpace(values[0]),
		QuotaBytes: parseGB(values[1]),
		ExpiresAt:  parseDays(values[2]),
		Enabled:    true,
	}
	if user.Name == "" {
		return fmt.Errorf("用户名不能为空")
	}
	return m.store.SaveUser(user)
}

// ---------------------------------------------------------------- 表单

type field struct {
	label string
	hint  string
	def   string
}

type form struct {
	title   string
	fields  []field
	values  []string
	cursor  int
	submit  func([]string) error
	message string
}

func newForm(title string, fields []field, submit func([]string) error) *form {
	values := make([]string, len(fields))
	for i, f := range fields {
		values[i] = f.def
	}
	return &form{title: title, fields: fields, values: values, submit: submit}
}

func (m *Model) handleFormKey(key string) (tea.Model, tea.Cmd) {
	f := m.form
	switch key {
	case "esc":
		m.mode = modeBrowse
		m.form = nil
		m.setStatus("已取消。")
		return m, nil
	case "tab", "down":
		f.cursor = (f.cursor + 1) % len(f.fields)
		return m, nil
	case "shift+tab", "up":
		f.cursor = (f.cursor + len(f.fields) - 1) % len(f.fields)
		return m, nil
	case "enter":
		if err := f.submit(f.values); err != nil {
			f.message = err.Error()
			return m, nil
		}
		m.mode = modeBrowse
		m.form = nil
		m.reload()
		m.setStatus("已保存。")
		return m, nil
	case "backspace":
		if len(f.values[f.cursor]) > 0 {
			f.values[f.cursor] = f.values[f.cursor][:len(f.values[f.cursor])-1]
		}
		return m, nil
	}
	// 可打印字符直接进当前字段
	if len(key) == 1 && key[0] >= 32 && key[0] < 127 {
		f.values[f.cursor] += key
	}
	return m, nil
}

// ---------------------------------------------------------------- 渲染

// View 实现 tea.Model。
func (m *Model) View() string {
	if m.quit {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.viewHeader())
	b.WriteString("\n\n")

	if m.mode == modeForm && m.form != nil {
		b.WriteString(m.viewForm())
	} else {
		switch m.tab {
		case tabOverview:
			b.WriteString(m.viewOverview())
		case tabNodes:
			b.WriteString(m.viewNodes())
		case tabUsers:
			b.WriteString(m.viewUsers())
		case tabTraffic:
			b.WriteString(m.viewTraffic())
		case tabMachines:
			b.WriteString(m.viewMachines())
		}
	}

	b.WriteString("\n")
	if m.mode == modeConfirm {
		b.WriteString(styleWarn.Render("  " + m.confirm + "  [y/N]"))
		b.WriteString("\n")
	}
	b.WriteString(m.viewStatus())
	b.WriteString("\n")
	b.WriteString(m.viewHelp())
	return b.String()
}

func (m *Model) viewHeader() string {
	tabs := make([]string, tabCount)
	for i := 0; i < tabCount; i++ {
		label := fmt.Sprintf("%d %s", i+1, tabNames[i])
		if i == m.tab {
			tabs[i] = styleTabOn.Render(label)
		} else {
			tabs[i] = styleTabOff.Render(label)
		}
	}
	state := kernel.ServiceState(m.paths.Service)
	stateText := styleOK.Render(state)
	if state != "active" {
		stateText = styleErr.Render(state)
	}
	return styleTitle.Render("sbx-panel") + styleDim.Render("  内核 ") + stateText +
		styleDim.Render("  ") + strings.Join(tabs, " ")
}

func (m *Model) viewStatus() string {
	if m.status == "" {
		return ""
	}
	style := styleOK
	if m.isError {
		style = styleErr
	}
	return "  " + style.Render(m.status)
}

func (m *Model) viewHelp() string {
	if m.mode == modeForm {
		return styleHelp.Render("  Tab/↑↓ 切换字段 · Enter 保存 · Esc 取消 · 直接打字输入")
	}
	return styleHelp.Render("  1-5/Tab 切换页 · ↑↓ 选择 · a 新增 · e 编辑 · d 删除 · 空格 启停 · r 下发全部 · c 采集 · s 改用户 · u 刷新状态 · q 退出")
}

func (m *Model) viewOverview() string {
	var b strings.Builder
	var totalUp, totalDown int64
	activeUsers := 0
	for _, u := range m.users {
		usage := m.usage[u.Name]
		totalUp += usage[0]
		totalDown += usage[1]
		if u.Enabled {
			activeUsers++
		}
	}
	enabledNodes := 0
	for _, n := range m.nodes {
		if n.Enabled {
			enabledNodes++
		}
	}

	row := func(k, v string) {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", styleDim.Render(k), v))
	}
	row("节点", fmt.Sprintf("%d 个（启用 %d）", len(m.nodes), enabledNodes))
	row("用户", fmt.Sprintf("%d 个（启用 %d）", len(m.users), activeUsers))
	row("总用量", fmt.Sprintf("↑ %s   ↓ %s   合计 %s",
		kernel.HumanBytes(totalUp), kernel.HumanBytes(totalDown),
		kernel.HumanBytes(totalUp+totalDown)))
	row("内核", fmt.Sprintf("%s   服务 %s", m.paths.Bin, m.paths.Service))
	row("配置", m.paths.Config)

	// 可观测性：数据来自 clash_api，按 u 刷新
	switch {
	case m.snapErr != nil:
		row("内核状态", styleErr.Render("读取失败: "+m.snapErr.Error()))
	case m.snapshot.Version != "":
		row("内核版本", m.snapshot.Version)
		row("活动连接", fmt.Sprintf("%d", m.snapshot.ActiveConnections))
		row("进程流量", fmt.Sprintf("↑ %s   ↓ %s",
			kernel.HumanBytes(m.snapshot.UploadTotal), kernel.HumanBytes(m.snapshot.DownloadTotal)))
		row("内存占用", kernel.HumanBytes(m.snapshot.Memory))
	default:
		row("内核状态", styleDim.Render("未读取（按 u 刷新）"))
	}
	if len(m.snapshot.TopHosts) > 0 {
		parts := make([]string, 0, len(m.snapshot.TopHosts))
		for _, item := range m.snapshot.TopHosts {
			parts = append(parts, fmt.Sprintf("%s×%d", truncate(item.Host, 28), item.Count))
		}
		row("活跃目标", strings.Join(parts, "  "))
	}

	b.WriteString("\n")
	// 注意：\n 必须放在 Render 外面。lipgloss 会把多行字符串的每一行
	// 补齐到最宽行的宽度，把换行符塞进去会让后续内容被空格推开。
	b.WriteString(styleDim.Render("  提示：配额与到期是在「下发」时生效的——sing-box 没有热重载，"))
	b.WriteString("\n")
	b.WriteString(styleDim.Render("        停用/超额的用户会在下一次 r 之后从配置里消失。"))
	b.WriteString("\n")
	return b.String()
}

func (m *Model) viewNodes() string {
	if len(m.nodes) == 0 {
		return styleDim.Render("  还没有节点。按 a 新增。") + "\n"
	}
	var b strings.Builder
	b.WriteString(styleDim.Render(fmt.Sprintf("  %-18s %-13s %-7s %-9s %-7s %s",
		"TAG", "协议", "端口", "TLS", "用户", "状态")))
	b.WriteString("\n")
	for i, node := range m.nodes {
		users, _ := m.store.UsersForNode(node.Tag)
		state := styleOK.Render("启用")
		if !node.Enabled {
			state = styleDim.Render("停用")
		}
		line := fmt.Sprintf("  %-18s %-13s %-7d %-9s %-7d ",
			truncate(node.Tag, 18), node.Proto, node.Port, node.TLSMode, len(users))
		if i == m.cursor {
			b.WriteString(styleCursor.Render("▸") + styleSelected.Render(line[1:]) + state + "\n")
		} else {
			b.WriteString(line + state + "\n")
		}
	}
	return b.String()
}

func (m *Model) viewUsers() string {
	if len(m.users) == 0 {
		return styleDim.Render("  还没有用户。按 a 新增。") + "\n"
	}
	var b strings.Builder
	b.WriteString(styleDim.Render(fmt.Sprintf("  %-16s %-11s %-11s %-12s %-6s %s",
		"用户", "已用", "配额", "到期", "节点", "状态")))
	b.WriteString("\n")
	for i, user := range m.users {
		usage := m.usage[user.Name]
		used := usage[0] + usage[1]
		quota := "不限"
		if user.QuotaBytes > 0 {
			quota = kernel.HumanBytes(user.QuotaBytes)
		}
		nodes, _ := m.store.NodesForUser(user.Name)

		state := string(kernel.EvaluateUser(user, used, time.Now()))
		stateStyle := styleOK
		switch kernel.EvaluateUser(user, used, time.Now()) {
		case kernel.UserStateDisabled:
			stateStyle = styleDim
		case kernel.UserStateExpired, kernel.UserStateOverQuota:
			stateStyle = styleErr
		case kernel.UserStateNearQuota:
			stateStyle = styleWarn
		}

		line := fmt.Sprintf("  %-16s %-11s %-11s %-12s %-6d ",
			truncate(user.Name, 16), kernel.HumanBytes(used), quota,
			expiryText(user.ExpiresAt), len(nodes))
		if i == m.cursor {
			b.WriteString(styleCursor.Render("▸") + styleSelected.Render(line[1:]) + stateStyle.Render(state) + "\n")
		} else {
			b.WriteString(line + stateStyle.Render(state) + "\n")
		}
	}
	return b.String()
}

func (m *Model) viewTraffic() string {
	if len(m.users) == 0 {
		return styleDim.Render("  还没有用户。") + "\n"
	}
	var b strings.Builder
	b.WriteString(styleDim.Render(fmt.Sprintf("  %-16s %-11s %-11s %s", "用户", "上行", "下行", "配额占用")))
	b.WriteString("\n")
	for i, user := range m.users {
		usage := m.usage[user.Name]
		used := usage[0] + usage[1]
		bar := progressBar(used, user.QuotaBytes, 24)
		line := fmt.Sprintf("  %-16s %-11s %-11s %s",
			truncate(user.Name, 16), kernel.HumanBytes(usage[0]), kernel.HumanBytes(usage[1]), bar)
		if i == m.cursor {
			b.WriteString(styleCursor.Render("▸") + styleSelected.Render(line[1:]) + "\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func (m *Model) viewMachines() string {
	if len(m.machines) == 0 {
		return styleDim.Render("  只管理本机。用 `sbx-panel machine add` 登记其它机器。") + "\n"
	}
	var b strings.Builder
	b.WriteString(styleDim.Render(fmt.Sprintf("  %-12s %-22s %-6s %-24s %-6s %s",
		"NAME", "HOST", "SSH", "内核路径", "节点", "状态")))
	b.WriteString("\n")
	for i, machine := range m.machines {
		host := machine.Host
		sshPort := strconv.Itoa(machine.SSHPort)
		if machine.Name == store.LocalMachine || host == "" {
			host, sshPort = "(本机)", "-"
		}
		nodeCount := 0
		for _, node := range m.nodes {
			if orLocal(node.Machine) == machine.Name {
				nodeCount++
			}
		}
		state, stateStyle := "在线", styleOK
		if !kernel.Reachable(machine) {
			state, stateStyle = "不可达", styleErr
		}
		line := fmt.Sprintf("  %-12s %-22s %-6s %-24s %-6d ",
			truncate(machine.Name, 12), truncate(host, 22), sshPort,
			truncate(machine.KernelPath, 24), nodeCount)
		if i == m.cursor {
			b.WriteString(styleCursor.Render("▸") + styleSelected.Render(line[1:]) + stateStyle.Render(state) + "\n")
		} else {
			b.WriteString(line + stateStyle.Render(state) + "\n")
		}
	}
	return b.String()
}

func (m *Model) viewForm() string {
	f := m.form
	var b strings.Builder
	b.WriteString(styleTitle.Render("  " + f.title))
	b.WriteString("\n\n")
	for i, fd := range f.fields {
		label := fmt.Sprintf("  %-12s", fd.label)
		value := f.values[i]
		if i == f.cursor {
			b.WriteString(styleSelected.Render(label) + styleCursor.Render("["+value+"_]"))
		} else {
			b.WriteString(styleDim.Render(label) + "[" + value + "]")
		}
		if fd.hint != "" {
			b.WriteString(styleHelp.Render("  " + fd.hint))
		}
		b.WriteString("\n")
	}
	if f.message != "" {
		b.WriteString("\n" + styleErr.Render("  "+f.message) + "\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- 小工具

func progressBar(used, quota int64, width int) string {
	if quota <= 0 {
		return styleDim.Render("不限")
	}
	ratio := float64(used) / float64(quota)
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio * float64(width))
	style := styleOK
	if ratio >= 0.8 {
		style = styleWarn
	}
	if ratio >= 1 {
		style = styleErr
	}
	return style.Render(strings.Repeat("█", filled)) +
		styleDim.Render(strings.Repeat("░", width-filled)) +
		fmt.Sprintf(" %3.0f%%", ratio*100)
}

// orLocal 把空机器名归一成 local（与 store 侧同一约定）。
func orLocal(name string) string {
	if strings.TrimSpace(name) == "" {
		return store.LocalMachine
	}
	return name
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 1 {
		return string(runes[:n])
	}
	return string(runes[:n-1]) + "…"
}

func enabledText(v bool) string {
	if v {
		return "启用"
	}
	return "停用"
}

func expiryText(ts int64) string {
	if ts == 0 {
		return "永久"
	}
	return time.Unix(ts, 0).Format("2006-01-02")
}

func gbText(bytes int64) string {
	if bytes <= 0 {
		return "0"
	}
	return strconv.FormatFloat(float64(bytes)/(1<<30), 'f', -1, 64)
}

func daysText(ts int64) string {
	if ts == 0 {
		return "0"
	}
	days := int((ts - time.Now().Unix()) / 86400)
	if days < 0 {
		return "0"
	}
	return strconv.Itoa(days)
}

// parseGB 把 "100" / "100.5" 解析成字节；空或非法返回 0。
func parseGB(text string) int64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
	if err != nil || value <= 0 {
		return 0
	}
	return int64(value * float64(int64(1)<<30))
}

// parseDays 把天数解析成到期时间戳；0 或非法表示永久。
func parseDays(text string) int64 {
	days, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || days <= 0 {
		return 0
	}
	return time.Now().AddDate(0, 0, days).Unix()
}
