package service

import (
	"fmt"
	"os"
	"strings"

	"napscan-be/internal/models"

	"github.com/go-pdf/fpdf"
)

type ReportService struct{}

func NewReportService() *ReportService {
	return &ReportService{}
}

/*
==========================
MAIN GENERATOR
==========================
*/

func (s *ReportService) GeneratePDF(data *models.ReportData) (string, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	// pdf.AddFont("JetBrains Mono", "", "internal/assets/ttf/JetBrainsMono-Regular.ttf")
	// pdf.AddFont("JetBrains Mono", "B", "internal/assets/ttf/JetBrainsMono-Bold.ttf")
	pdf.SetAutoPageBreak(true, 15)
	pdf.SetFont("Arial", "", 12)

	// Pages
	s.drawCoverPage(pdf, data)
	s.drawExecutivePage(pdf, data)
	s.drawDetailPage(pdf, data)

	// Ensure folder
	if _, err := os.Stat("reports"); os.IsNotExist(err) {
		_ = os.Mkdir("reports", 0755)
	}

	filename := fmt.Sprintf("reports/batch_%s.pdf", data.BatchID)
	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		return "", err
	}

	return filename, nil
}

/*
==========================
COVER PAGE
==========================
*/

func (s *ReportService) drawCoverPage(pdf *fpdf.Fpdf, data *models.ReportData) {
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 40)
	pdf.SetXY(25, 40)
	pdf.Cell(0, 12, "NapScan Security")

	pdf.SetTextColor(45, 85, 210)
	pdf.SetXY(25, 55)
	pdf.SetFont("Arial", "B", 32)
	pdf.Cell(0, 12, "Report")
	pdf.SetTextColor(0, 0, 0)

	// Icon (optional)
	pdf.Image("internal/assets/IoBugSharp.png", 30, 90, 70, 0, false, "", 0, "")

	pdf.SetFont("Arial", "", 20)
	pdf.SetXY(25, 200)
	pdf.Cell(0, 10, data.GeneratedAt.Format("02 Jan 2006"))

	drawBottomBar(pdf)
}

/*
==========================
EXECUTIVE SUMMARY
==========================
*/

func (s *ReportService) drawExecutivePage(pdf *fpdf.Fpdf, data *models.ReportData) {
	pdf.AddPage()

	// ===== Title =====
	pdf.SetFont("Arial", "B", 20)
	pdf.CellFormat(0, 15, "Executive Summary", "", 1, "C", false, 0, "")
	pdf.Ln(5)

	// ===== Target =====
	pdf.SetFont("Arial", "B", 11)
	pdf.SetLeftMargin(25)
	pdf.Cell(25, 7, "Target:")
	pdf.SetFont("Arial", "", 11)
	pdf.Cell(0, 7, data.TargetInfo)
	pdf.Ln(6)

	// ===== Overall Risk =====
	pdf.SetFont("Arial", "B", 11)
	pdf.SetLeftMargin(25)
	pdf.Cell(25, 7, "Overall Risk:")
	pdf.SetFont("Arial", "", 11)
	pdf.Cell(0, 7, data.RiskSummary.RiskLevel)
	pdf.Ln(10)

	// ===== Vulnerability Summary =====
	pdf.SetFont("Arial", "", 11)
	pdf.SetLeftMargin(25)
	pdf.MultiCell(0, 7,
		fmt.Sprintf(
			"A total of %d vulnerabilities were identified across %d scanner(s).",
			len(data.Vulnerabilities),
			len(data.ScannersUsed),
		),
		"", "", false)
	pdf.Ln(5)

	// ===== Total Risk =====
	pdf.SetFont("Arial", "B", 12)
	pdf.SetLeftMargin(25)
	pdf.Cell(0, 8, "Total Risk")
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 11)
	pdf.SetLeftMargin(25)
	pdf.MultiCell(0, 7,
		fmt.Sprintf(
			"The overall risk level is calculated as %s (Score: %.1f/100).",
			data.RiskSummary.RiskLevel,
			data.RiskSummary.OverallRiskScore,
		),
		"", "", false)

	pdf.SetFont("Arial", "B", 14)
	pdf.SetXY(25, 75)
	pdf.Cell(0, 10, "Total Risk")

	y := 95.0
	s.riskBox(pdf, 25, y, "Critical", data.RiskSummary.CriticalCount, []int{200, 0, 0})
	s.riskBox(pdf, 60, y, "High", data.RiskSummary.HighCount, []int{255, 120, 0})
	s.riskBox(pdf, 95, y, "Medium", data.RiskSummary.MediumCount, []int{255, 200, 0})
	s.riskBox(pdf, 130, y, "Low", data.RiskSummary.LowCount, []int{60, 90, 200})
	s.riskBox(pdf, 165, y, "Info", data.RiskSummary.InfoCount, []int{160, 160, 160})

	drawBottomBar(pdf)
}

/*
==========================
DETAILED RESULT
==========================
*/

func (s *ReportService) drawDetailPage(pdf *fpdf.Fpdf, data *models.ReportData) {
	// Group vulnerabilities by scanner
	vulnsByScanner := make(map[string][]models.UnifiedVulnerability)
	for _, v := range data.Vulnerabilities {
		// Normalize scanner name to handle case variations if necessary,
		// though usually they come normalized.
		vulnsByScanner[v.Scanner] = append(vulnsByScanner[v.Scanner], v)
	}

	// Defined list order or just map iteration?
	// Map iteration is random. Let's try to grab keys and sort them,
	// or just iterate the ScannersUsed list from the data if available/reliable.
	// data.ScannersUsed seems to be populated in RiskService.

	// If ScannersUsed is empty or not matching, we'll derive from map.
	scanners := data.ScannersUsed
	if len(scanners) == 0 {
		for k := range vulnsByScanner {
			scanners = append(scanners, k)
		}
	}

	// Remove duplicates and sort if needed?
	// Assuming ScannersUsed is reliable from risk_service.

	for _, scannerName := range scanners {
		vulns, exists := vulnsByScanner[scannerName]
		if !exists || len(vulns) == 0 {
			continue // Skip scanners with no vulns in the report
		}

		pdf.AddPage()

		// --- Header Section ---
		pdf.SetFont("Arial", "B", 20)
		pdf.SetXY(25, 30)
		pdf.Cell(0, 12, "Detailed Result")

		pdf.SetFont("Arial", "B", 16)
		pdf.SetTextColor(45, 85, 210)
		pdf.SetXY(25, 45)
		pdf.Cell(0, 10, "["+data.TargetInfo+"]")

		pdf.SetXY(25, 55)
		pdf.SetFont("Arial", "B", 14)
		pdf.SetTextColor(45, 85, 210) // Blue-ish
		// Proper Case Scanner Name
		pdf.Cell(0, 10, scannerName)
		pdf.SetTextColor(0, 0, 0)

		// Scanner Description
		pdf.SetXY(25, 65)
		pdf.SetFont("Arial", "", 10)
		pdf.SetTextColor(100, 100, 100)
		description := s.getToolDescription(scannerName)
		pdf.MultiCell(160, 5, description, "", "", false)
		pdf.SetTextColor(0, 0, 0)

		// --- Content ---
		// Adjust starting Y based on description length
		// A simple way is to check GetY()
		y := pdf.GetY() + 10
		pageBottom := 270.0

		for _, v := range vulns {
			// 1. Calculate Heights
			// Title
			pdf.SetFont("Arial", "B", 11)
			_, lineHtTitle := pdf.GetFontSize()
			contentWidth := 160.0 // 210 - 36 - 14(approx)
			titleLines := pdf.SplitLines([]byte(v.Title), contentWidth)
			hTitle := float64(len(titleLines)) * (lineHtTitle + 2) // +2 for spacing/leading

			// Severity
			pdf.SetFont("Arial", "", 10)
			_, lineHtSev := pdf.GetFontSize()
			sevText := fmt.Sprintf("%s | CVSS %.1f", v.Severity, v.CVSSScore)
			sevLines := pdf.SplitLines([]byte(sevText), contentWidth)
			hSev := float64(len(sevLines)) * (lineHtSev + 2)

			// Description
			pdf.SetFont("Arial", "", 10)
			_, lineHtDesc := pdf.GetFontSize()
			descLines := pdf.SplitLines([]byte(v.Description), contentWidth)
			hDesc := float64(len(descLines)) * (lineHtDesc + 1) // slightly tighter

			// Total Block Height
			// Padding Top (2) + Title + Gap (2) + Sev + Gap (2) + Desc + Padding Bottom (4)
			totalBlockHeight := 2.0 + hTitle + 2.0 + hSev + 2.0 + hDesc + 4.0

			// 2. Check Page Break
			if y+totalBlockHeight > pageBottom {
				drawBottomBar(pdf)
				pdf.AddPage()
				y = 40
			}

			// 3. Draw Strip
			color := s.severityColor(v.Severity)
			pdf.SetFillColor(color[0], color[1], color[2])
			// Strip is drawn at X=25, Width=6. Height = totalBlockHeight
			pdf.Rect(25, y, 6, totalBlockHeight, "F")

			// 4. Draw Content
			currentY := y + 2.0 // padding top

			// Title
			pdf.SetXY(36, currentY)
			pdf.SetFont("Arial", "B", 11)
			pdf.MultiCell(contentWidth, lineHtTitle+2, v.Title, "", "", false)
			// Reset currentY based on calculation to ensure exact alignment with the strip
			currentY = y + 2.0 + hTitle + 2.0

			// Severity
			pdf.SetXY(36, currentY)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(contentWidth, lineHtSev+2, sevText, "", "", false)
			currentY += hSev + 2.0

			// Description
			pdf.SetXY(36, currentY)
			pdf.SetFont("Arial", "", 10)
			pdf.MultiCell(contentWidth, lineHtDesc+1, v.Description, "", "", false)

			// Move Y for next item
			y += totalBlockHeight + 10.0 // 10mm gap between vulnerabilities
		}

		drawBottomBar(pdf)
	}
}

func (s *ReportService) getToolDescription(toolName string) string {
	switch strings.ToLower(toolName) {
	case "nmap":
		return "Nmap (Network Mapper) is a network enumeration tool commonly used to find unintentional open ports on web application. It can also be used to determine what services are running inside a web server."
	case "owasp zap", "zap", "owasp-zap":
		return "OWASP ZAP is an automatic pentesting tool made by the OWASP Foundation. It actively and automatically tests for vulnerable queries such as XSS, SQLi, and Local File Disclosure."
	case "openvas":
		return "OpenVAS is a vulnerability assessment tool commonly used to scan for known CVEs on a variety of target, including web apps."
	case "nuclei":
		return "Nuclei is a fast, customizable vulnerability scanner powered by the global security community. It can test from many different presets."
	case "sslyze":
		return "SSLyze is a simple tool to check the maturity and quality of SSL certificates."
	case "ffuf":
		return "FFUF is a fast web fuzzer written in Go."
	case "mobsf":
		return "MobSF (Mobile Security Framework) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework."
	case "frida":
		return "Frida is a dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers."
	default:
		return "Security scanning tool."
	}
}

/*
==========================
HELPERS
==========================
*/

func (s *ReportService) riskBox(pdf *fpdf.Fpdf, x, y float64, label string, val int, c []int) {
	pdf.SetXY(x, y)
	pdf.SetFillColor(c[0], c[1], c[2])
	pdf.Rect(x, y, 28, 22, "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Arial", "B", 14)
	pdf.SetXY(x, y+6)
	pdf.CellFormat(28, 6, fmt.Sprintf("%d", val), "", 0, "C", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetXY(x, y+14)
	pdf.CellFormat(28, 6, label, "", 0, "C", false, 0, "")

	pdf.SetTextColor(0, 0, 0)
}

func drawBottomBar(pdf *fpdf.Fpdf) {
	pdf.SetFillColor(255, 120, 0)
	pdf.Rect(0, 290, 70, 7, "F")

	pdf.SetFillColor(255, 200, 0)
	pdf.Rect(70, 290, 70, 7, "F")

	pdf.SetFillColor(45, 85, 210)
	pdf.Rect(140, 290, 70, 7, "F")
}

func (s *ReportService) severityColor(sev string) []int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return []int{200, 0, 0}
	case "HIGH":
		return []int{255, 120, 0}
	case "MEDIUM":
		return []int{255, 190, 0}
	case "LOW":
		return []int{60, 90, 200}
	default:
		return []int{160, 160, 160}
	}
}
