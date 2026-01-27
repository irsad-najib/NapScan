package service

import (
	"fmt"
	"napscan-be/internal/models"
	"os"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

type ReportService struct{}

func NewReportService() *ReportService {
	return &ReportService{}
}

func (s *ReportService) GeneratePDF(data *models.ReportData) (string, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetFont("Arial", "", 12)
	pdf.AddPage()

	// 1. Cover Page
	s.drawCoverPage(pdf, data)

	// 2. Executive Summary
	pdf.AddPage()
	s.drawHeader(pdf, "Executive Summary")
	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 10, data.ExecutiveSummary, "", "", false)
	pdf.Ln(10)

	// 3. Scan Scope & Tools
	s.drawHeader(pdf, "Scan Scope & Tools")
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Target:")
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, data.TargetInfo)
	pdf.Ln(10)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Duration:")
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(0, 10, data.ScanDuration)
	pdf.Ln(15)

	// 4. Risk Summary Table
	s.drawHeader(pdf, "Risk Summary")
	s.drawRiskTable(pdf, data.RiskSummary)
	pdf.Ln(10)

	// 5. Vulnerability Details
	pdf.AddPage()
	s.drawHeader(pdf, "Vulnerability Details")
	for _, v := range data.Vulnerabilities {
		s.drawVulnerability(pdf, v)
		pdf.Ln(5)
	}

	// Ensure directory exists
	if _, err := os.Stat("reports"); os.IsNotExist(err) {
		os.Mkdir("reports", 0755)
	}

	filename := fmt.Sprintf("reports/batch_%s.pdf", data.BatchID)
	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func (s *ReportService) drawCoverPage(pdf *fpdf.Fpdf, data *models.ReportData) {
	pdf.SetFont("Arial", "B", 24)
	pdf.CellFormat(0, 40, "Security Scan Report", "", 1, "C", false, 0, "")
	
	pdf.Ln(20)
	pdf.SetFont("Arial", "", 16)
	pdf.CellFormat(0, 10, fmt.Sprintf("Batch ID: %s", data.BatchID), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 10, fmt.Sprintf("Date: %s", data.GeneratedAt.Format(time.RFC1123)), "", 1, "C", false, 0, "")
	
	pdf.Ln(20)
	pdf.SetFont("Arial", "B", 18)
	r, g, b := s.getRiskColor(data.RiskSummary.RiskLevel)
	pdf.SetTextColor(r, g, b)
	pdf.CellFormat(0, 10, fmt.Sprintf("Overall Risk: %s", data.RiskSummary.RiskLevel), "", 1, "C", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
}

func (s *ReportService) drawHeader(pdf *fpdf.Fpdf, title string) {
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, title)
	pdf.Ln(12)
	pdf.Line(pdf.GetX(), pdf.GetY(), 190, pdf.GetY()) // Underline
	pdf.Ln(5)
}

func (s *ReportService) drawRiskTable(pdf *fpdf.Fpdf, summary models.RiskSummary) {
	pdf.SetFont("Arial", "B", 12)
	pdf.SetFillColor(240, 240, 240)
	pdf.CellFormat(80, 10, "Category", "1", 0, "", true, 0, "")
	pdf.CellFormat(40, 10, "Count", "1", 1, "C", true, 0, "")

	pdf.SetFont("Arial", "", 12)
	pdf.CellFormat(80, 10, "Critical", "1", 0, "", false, 0, "")
	pdf.CellFormat(40, 10, fmt.Sprintf("%d", summary.CriticalCount), "1", 1, "C", false, 0, "")
	
	pdf.CellFormat(80, 10, "High", "1", 0, "", false, 0, "")
	pdf.CellFormat(40, 10, fmt.Sprintf("%d", summary.HighCount), "1", 1, "C", false, 0, "")

	pdf.CellFormat(80, 10, "Medium", "1", 0, "", false, 0, "")
	pdf.CellFormat(40, 10, fmt.Sprintf("%d", summary.MediumCount), "1", 1, "C", false, 0, "")

	pdf.CellFormat(80, 10, "Low", "1", 0, "", false, 0, "")
	pdf.CellFormat(40, 10, fmt.Sprintf("%d", summary.LowCount), "1", 1, "C", false, 0, "")
}

func (s *ReportService) drawVulnerability(pdf *fpdf.Fpdf, v models.UnifiedVulnerability) {
	// ===== Title Bar =====
	r, g, b := s.getRiskColor(v.Severity)
	pdf.SetFillColor(r, g, b)
	pdf.CellFormat(6, 10, "", "", 0, "", true, 0, "")
	pdf.SetFont("Arial", "B", 12)
	pdf.MultiCell(0, 10, " "+v.Title, "", "L", false)

	pdf.Ln(1)

	// ===== Meta Info =====
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(25, 6, "Severity:")
	pdf.Cell(40, 6, v.Severity)
	pdf.Cell(20, 6, "CVSS:")
	pdf.Cell(0, 6, fmt.Sprintf("%.1f", v.CVSSScore))
	pdf.Ln(6)

	// ===== Description =====
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(25, 6, "Description:")
	pdf.Ln(6)

	pdf.SetFont("Arial", "", 10)
	pdf.SetX(20)
	pdf.MultiCell(170, 6, v.Description, "", "L", false)

	// ===== Recommendation =====
	if v.Recommendation != "" {
		pdf.Ln(2)
		pdf.SetFont("Arial", "B", 10)
		pdf.Cell(25, 6, "Recommendation:")
		pdf.Ln(6)

		pdf.SetFont("Arial", "", 10)
		pdf.SetX(20)
		pdf.MultiCell(170, 6, v.Recommendation, "", "L", false)
	}

	pdf.Ln(6)
}

func (s *ReportService) getRiskColor(level string) (int, int, int) {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return 200, 0, 0
	case "HIGH":
		return 255, 100, 0
	case "MEDIUM":
		return 255, 200, 0
	case "LOW":
		return 0, 150, 255
	default:
		return 100, 100, 100
	}
}
