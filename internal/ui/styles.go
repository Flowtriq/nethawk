package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	colorPrimary   = lipgloss.Color("#00D4AA")
	colorSecondary = lipgloss.Color("#7C7CFF")
	colorDim       = lipgloss.Color("#555555")
	colorWhite     = lipgloss.Color("#FFFFFF")
	colorRed       = lipgloss.Color("#FF4444")
	colorOrange    = lipgloss.Color("#FF8C00")
	colorYellow    = lipgloss.Color("#FFD700")
	colorGreen     = lipgloss.Color("#00FF88")
	colorCyan      = lipgloss.Color("#00CED1")
	colorTCP       = lipgloss.Color("#7C7CFF")
	colorUDP       = lipgloss.Color("#00D4AA")
	colorICMP      = lipgloss.Color("#FFD700")
	colorOther     = lipgloss.Color("#555555")

	// Base styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colorDim)

	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorDim).
			Padding(0, 1)

	panelTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan)

	valueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorDim)

	dimStyle = lipgloss.NewStyle().
			Foreground(colorDim)

	normalStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen)

	mediumStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorYellow)

	highStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorOrange)

	criticalStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorRed)

	barFull  = lipgloss.NewStyle().Foreground(colorPrimary)
	barEmpty = lipgloss.NewStyle().Foreground(colorDim)
)

func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return criticalStyle
	case "HIGH":
		return highStyle
	case "MEDIUM":
		return mediumStyle
	default:
		return normalStyle
	}
}
