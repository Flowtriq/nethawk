package ui

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Flowtriq/nethawk/internal/capture"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tickMsg capture.Snapshot

type model struct {
	src      capture.Source
	snap     capture.Snapshot
	width    int
	height   int
	quitting bool
}

type App struct {
	program *tea.Program
}

func New(src capture.Source) *App {
	m := &model{
		src:   src,
		width: 80,
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	return &App{program: p}
}

func (a *App) Run() error {
	_, err := a.program.Run()
	return err
}

func (a *App) Quit() {
	a.program.Quit()
}

func (m *model) Init() tea.Cmd {
	return waitForTick(m.src)
}

func waitForTick(src capture.Source) tea.Cmd {
	return func() tea.Msg {
		snap := <-src.Ticker()
		return tickMsg(snap)
	}
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			m.src.Stop()
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		m.snap = capture.Snapshot(msg)
		return m, waitForTick(m.src)
	}
	return m, nil
}

func (m *model) View() string {
	if m.quitting {
		return ""
	}

	w := m.width
	if w < 40 {
		w = 80
	}
	if w > 120 {
		w = 120
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader(w))
	b.WriteString("\n")

	// Sparkline
	b.WriteString(m.renderSparkline(w))
	b.WriteString("\n")

	// Three-column panel
	b.WriteString(m.renderPanels(w))
	b.WriteString("\n")

	// Status bar
	b.WriteString(m.renderStatus(w))

	return b.String()
}

func (m *model) renderHeader(w int) string {
	logo := titleStyle.Render("◆ NetHawk")
	iface := dimStyle.Render(" ") + valueStyle.Render(m.snap.Interface)
	uptime := dimStyle.Render(" "+formatDuration(m.src.Uptime()))

	bps := formatBits(m.snap.BPS)
	pps := formatCount(m.snap.PPS)
	traffic := valueStyle.Render("▲ "+bps) +
		dimStyle.Render(" ") + valueStyle.Render(pps+"pps")

	left := logo + iface + uptime
	right := traffic

	// panel border(2) + padding(2) = 4 chars consumed
	innerWidth := w - 6
	gap := innerWidth - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}

	header := left + strings.Repeat(" ", gap) + right
	return panelStyle.Width(w - 2).Render(header)
}

func (m *model) renderSparkline(w int) string {
	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	hist := m.snap.History
	chartWidth := w - 6

	if len(hist) == 0 {
		line := dimStyle.Render(strings.Repeat("▁", chartWidth))
		return panelStyle.Width(w - 2).Render(
			panelTitleStyle.Render("Traffic") + "\n" + line,
		)
	}

	var maxVal uint64
	for _, v := range hist {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	// pad or trim to fit width
	display := hist
	if len(display) > chartWidth {
		display = display[len(display)-chartWidth:]
	}

	var spark strings.Builder
	for _, v := range display {
		idx := int(float64(v) / float64(maxVal) * float64(len(blocks)-1))
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		color := colorGreen
		ratio := float64(v) / float64(maxVal)
		if ratio > 0.8 {
			color = colorRed
		} else if ratio > 0.6 {
			color = colorOrange
		} else if ratio > 0.4 {
			color = colorYellow
		} else if ratio > 0.2 {
			color = colorCyan
		}
		spark.WriteString(lipgloss.NewStyle().Foreground(color).Render(string(blocks[idx])))
	}

	// pad left if less than chartWidth
	pad := chartWidth - len(display)
	if pad > 0 {
		spark.WriteString(dimStyle.Render(strings.Repeat("▁", pad)))
	}

	return panelStyle.Width(w - 2).Render(
		panelTitleStyle.Render("Traffic (last 60s)") + "\n" + spark.String(),
	)
}

func (m *model) renderPanels(w int) string {
	colWidth := (w - 8) / 3

	// Protocol panel
	proto := m.renderProtocols(colWidth)

	// Top Sources panel
	sources := m.renderTopSources(colWidth)

	// Top Ports panel
	ports := m.renderTopPorts(colWidth)

	return lipgloss.JoinHorizontal(lipgloss.Top,
		panelStyle.Width(colWidth).Render(proto),
		panelStyle.Width(colWidth).Render(sources),
		panelStyle.Width(colWidth).Render(ports),
	)
}

func (m *model) renderProtocols(w int) string {
	var b strings.Builder
	b.WriteString(panelTitleStyle.Render("Protocols"))
	b.WriteString("\n\n")

	barWidth := w - 16

	protocols := []struct {
		name  string
		pct   float64
		color lipgloss.Color
	}{
		{"TCP ", m.snap.TCP, colorTCP},
		{"UDP ", m.snap.UDP, colorUDP},
		{"ICMP", m.snap.ICMP, colorICMP},
		{"Other", m.snap.Other, colorOther},
	}

	for _, p := range protocols {
		if p.pct < 0.1 && p.name == "Other" {
			continue
		}
		pctStr := fmt.Sprintf("%5.1f%%", p.pct)
		filled := int(math.Round(p.pct / 100 * float64(barWidth)))
		if filled > barWidth {
			filled = barWidth
		}
		empty := barWidth - filled

		bar := lipgloss.NewStyle().Foreground(p.color).Render(strings.Repeat("█", filled)) +
			barEmpty.Render(strings.Repeat("░", empty))

		b.WriteString(fmt.Sprintf("  %s %s %s\n",
			labelStyle.Render(p.name),
			dimStyle.Render(pctStr),
			bar,
		))
	}

	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s  %s %s",
		labelStyle.Render("unique IPs"),
		valueStyle.Render(formatCount(uint64(m.snap.UniqueIPs))),
		labelStyle.Render("avg pkt"),
		valueStyle.Render(fmt.Sprintf("%dB", m.snap.AvgPktSize)),
	))

	return b.String()
}

func (m *model) renderTopSources(w int) string {
	var b strings.Builder
	b.WriteString(panelTitleStyle.Render("Top Sources"))
	b.WriteString("\n\n")

	if len(m.snap.TopSources) == 0 {
		b.WriteString(dimStyle.Render("  waiting for data..."))
		return b.String()
	}

	for i, src := range m.snap.TopSources {
		ip := src.IP
		if len(ip) > 18 {
			ip = ip[:18]
		}
		count := formatCount(src.Count) + " pkts"

		prefix := dimStyle.Render(fmt.Sprintf("  %d ", i+1))
		b.WriteString(fmt.Sprintf("%s%-18s %s\n",
			prefix,
			valueStyle.Render(ip),
			dimStyle.Render(count),
		))
	}

	return b.String()
}

func (m *model) renderTopPorts(w int) string {
	var b strings.Builder
	b.WriteString(panelTitleStyle.Render("Top Ports"))
	b.WriteString("\n\n")

	if len(m.snap.TopPorts) == 0 {
		b.WriteString(dimStyle.Render("  waiting for data..."))
		return b.String()
	}

	for _, p := range m.snap.TopPorts {
		portStr := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		pctStr := fmt.Sprintf("%.1f%%", p.Percent)

		b.WriteString(fmt.Sprintf("  %-12s %s\n",
			valueStyle.Render(portStr),
			dimStyle.Render(pctStr),
		))
	}

	return b.String()
}

func (m *model) renderStatus(w int) string {
	s := m.snap
	sev := s.Severity
	if sev == "" {
		sev = "NORMAL"
	}

	style := severityStyle(sev)

	var status string
	switch sev {
	case "NORMAL":
		status = style.Render("✓ NORMAL") + dimStyle.Render(" — No threats detected")
	case "MEDIUM", "HIGH", "CRITICAL":
		icon := "⚠"
		if sev == "CRITICAL" {
			icon = "✖"
		}
		status = style.Render(icon+" "+sev) + " — " +
			valueStyle.Render(s.AttackType) +
			dimStyle.Render(fmt.Sprintf("  %s pps from %d sources",
				formatCount(s.PPS), s.UniqueIPs))
	}

	footer := dimStyle.Render("q: quit")

	innerWidth := w - 6
	gap := innerWidth - lipgloss.Width(status) - lipgloss.Width(footer)
	if gap < 1 {
		gap = 1
	}

	line := status + strings.Repeat(" ", gap) + footer

	return panelStyle.Width(w - 2).Render(line)
}

// Formatting helpers

func formatBits(bps uint64) string {
	switch {
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%.2f Gbps", float64(bps)/1_000_000_000)
	case bps >= 1_000_000:
		return fmt.Sprintf("%.1f Mbps", float64(bps)/1_000_000)
	case bps >= 1_000:
		return fmt.Sprintf("%.0f Kbps", float64(bps)/1_000)
	default:
		return fmt.Sprintf("%d bps", bps)
	}
}

func formatCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
