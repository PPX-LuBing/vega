package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *Model) startGrants(user string) {
	tags, err := m.store.NodesForUser(user)
	if err != nil {
		m.setError("读取授权失败: %v", err)
		return
	}
	m.grantUser, m.grantCursor, m.grantSelected = user, 0, map[string]bool{}
	for _, tag := range tags {
		m.grantSelected[tag] = true
	}
	m.mode = modeGrants
	m.setStatus("选择允许访问的节点；不默认授权。Enter 保存，Esc 保留原授权。")
}

func (m *Model) handleGrantKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.mode = modeBrowse
		m.setStatus("授权未修改；新用户尚无授权时不能使用节点，按 g 配置。")
	case "up", "k":
		m.grantCursor = max(0, m.grantCursor-1)
	case "down", "j":
		m.grantCursor = min(max(0, len(m.nodes)-1), m.grantCursor+1)
	case "space", " ":
		if m.grantCursor < len(m.nodes) {
			tag := m.nodes[m.grantCursor].Tag
			m.grantSelected[tag] = !m.grantSelected[tag]
		}
	case "enter":
		var tags []string
		for _, node := range m.nodes {
			if m.grantSelected[node.Tag] {
				tags = append(tags, node.Tag)
			}
		}
		if err := m.store.SetUserNodes(m.grantUser, tags); err != nil {
			m.setError("保存授权失败: %v", err)
			return m, nil
		}
		m.mode = modeBrowse
		m.reload()
		m.setStatus("%s 已授权 %d 个节点；按 r 下发后内核生效。", m.grantUser, len(tags))
	}
	return m, nil
}

func (m *Model) viewGrants() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s 的节点授权（空格勾选）\n", m.grantUser)
	start, end := m.rowWindow(len(m.nodes), m.grantCursor)
	for i := start; i < end; i++ {
		node := m.nodes[i]
		mark := "[ ]"
		if m.grantSelected[node.Tag] {
			mark = "[x]"
		}
		line := fmt.Sprintf("  %s %s (%s / %s)", mark, node.Tag, node.Proto, enabledText(node.Enabled))
		if i == m.grantCursor {
			line = styleCursor.Render("▸") + styleSelected.Render(line[1:])
		}
		b.WriteString(line + "\n")
	}
	if len(m.nodes) == 0 {
		b.WriteString("  暂无节点；先新增节点，再到用户页按 g 授权。\n")
	}
	return b.String()
}
