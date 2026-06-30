package main

import (
	"strings"
	"testing"
)

func TestNormalizeDraftCVSSAndAttachments(t *testing.T) {
	report := normalizeDraft(ReportDraft{
		Title:       "  ",
		CVSSVersion: "4.0",
		CVSSScore:   "11.72",
		CVSSVector:  "  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H  ",
		Status:      "submitted",
		ReportURL:   "  https://hackerone.com/reports/12345  ",
		Tags:        []string{"#xss", " XSS ", "", "api"},
		PocFiles: []PocFile{
			{Name: " poc.py ", Type: " text/x-python ", Size: -1, Data: " data:text/plain;base64,abc "},
			{Name: "", Data: "data:text/plain;base64,ignored"},
		},
	})

	if report.Title != "Untitled report" {
		t.Fatalf("Title = %q, want Untitled report", report.Title)
	}
	if report.CVSSVersion != "4.0" {
		t.Fatalf("CVSSVersion = %q, want 4.0", report.CVSSVersion)
	}
	if report.CVSSScore != "10.0" {
		t.Fatalf("CVSSScore = %q, want 10.0", report.CVSSScore)
	}
	if report.CVSSVector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" {
		t.Fatalf("CVSSVector was not trimmed: %q", report.CVSSVector)
	}
	if report.Status != "Submitted" {
		t.Fatalf("Status = %q, want Submitted", report.Status)
	}
	if report.ReportURL != "https://hackerone.com/reports/12345" {
		t.Fatalf("ReportURL = %q, want trimmed HackerOne URL", report.ReportURL)
	}
	if got := strings.Join(report.Tags, ","); got != "xss,api" {
		t.Fatalf("Tags = %q, want xss,api", got)
	}
	if len(report.PocFiles) != 1 {
		t.Fatalf("len(PocFiles) = %d, want 1", len(report.PocFiles))
	}
	if report.PocFiles[0].Size != 0 {
		t.Fatalf("PocFiles[0].Size = %d, want 0", report.PocFiles[0].Size)
	}
}

func TestNormalizeDraftAllowsBlankReportURL(t *testing.T) {
	report := normalizeDraft(ReportDraft{
		Title:     "Blank URL",
		ReportURL: "   ",
	})

	if report.ReportURL != "" {
		t.Fatalf("ReportURL = %q, want blank", report.ReportURL)
	}
}

func TestMigrateReportsLegacyFields(t *testing.T) {
	reports, hadReportContent := migrateReports([]storedReport{
		{
			Report: Report{
				ID:    "legacy",
				Title: "Legacy report",
				Tags:  []string{"auth", "AUTH"},
			},
			Severity: "High",
			Summary:  "Short summary",
			Impact:   "Account takeover",
			Steps:    "1. Open endpoint",
		},
	})

	if len(reports) != 1 {
		t.Fatalf("len(reports) = %d, want 1", len(reports))
	}

	report := reports[0]
	if report.CVSSVersion != "3.1" {
		t.Fatalf("CVSSVersion = %q, want 3.1", report.CVSSVersion)
	}
	if report.CVSSScore != "7.0" {
		t.Fatalf("CVSSScore = %q, want 7.0", report.CVSSScore)
	}
	if !hadReportContent {
		t.Fatal("hadReportContent = false, want true")
	}
	if got := strings.Join(report.Tags, ","); got != "auth" {
		t.Fatalf("Tags = %q, want auth", got)
	}
}

func TestNormalizeCVSSScore(t *testing.T) {
	tests := []struct {
		name  string
		score string
		want  string
	}{
		{name: "empty", score: " ", want: ""},
		{name: "invalid", score: "high", want: ""},
		{name: "rounds to one decimal", score: "7.94", want: "7.9"},
		{name: "clamps low", score: "-1", want: "0.0"},
		{name: "clamps high", score: "12", want: "10.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCVSSScore(tt.score); got != tt.want {
				t.Fatalf("normalizeCVSSScore(%q) = %q, want %q", tt.score, got, tt.want)
			}
		})
	}
}
