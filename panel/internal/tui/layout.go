package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func (m *Model) rowWindow(count, cursor int) (int, int) {
	visible := count
	if m.height > 0 {
		visible = min(count, max(1, m.height-lipgloss.Height(m.viewHeader())-7))
	}
	start := min(max(0, cursor-visible/2), count-visible)
	return start, start + visible
}

func (m *Model) fitView(view string) string {
	lines := strings.Split(view, "\n")
	if m.height > 0 && len(lines) > m.height {
		// Keep status/help visible even for unusually small terminals.
		if m.height >= 3 {
			lines = append(lines[:m.height-2], lines[len(lines)-2:]...)
		} else {
			lines = lines[len(lines)-m.height:]
		}
	}
	if m.width > 0 {
		for i, line := range lines {
			lines[i] = ansi.Truncate(line, m.width, "…")
		}
	}
	return strings.Join(lines, "\n")
}

func cell(text string, width int) string {
	text = ansi.Truncate(text, width, "…")
	return text + strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
}
