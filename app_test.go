package main

import (
	"strings"
	"testing"
)

func TestNormalizeDraftCVSSAndAttachments(t *testing.T) {
	report := normalizeDraft(ReportDraft{
		Title:          "  ",
		CVSSVersion:    "4.0",
		CVSSScore:      "11.72",
		CVSSVector:     "  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H  ",
		Status:         "submitted",
		NextActionAt:   "  2026-07-08  ",
		RewardStatus:   "paid",
		RewardAmount:   "  500.00  ",
		RewardCurrency: " usd ",
		RewardPaidAt:   "  2026-07-10  ",
		RewardNote:     "  初回報奨金  ",
		ReportURL:      "  https://hackerone.com/reports/12345  ",
		MaintainerLog:  "  2026-06-30: メンテナーへ再現手順を共有  ",
		ConversationLogs: []ConversationEntry{
			{From: "maintainer", To: "maintainer", CommunicatedAt: "  2026-06-30T10:30  ", Body: "  修正予定を共有  "},
			{From: "自分", To: "メンテナー", Body: "  "},
		},
		Tags: []string{"#xss", " XSS ", "", "api"},
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
	if report.NextActionAt != "2026-07-08" {
		t.Fatalf("NextActionAt = %q, want trimmed next action date", report.NextActionAt)
	}
	if report.RewardStatus != "Paid" {
		t.Fatalf("RewardStatus = %q, want Paid", report.RewardStatus)
	}
	if report.RewardAmount != "500.00" {
		t.Fatalf("RewardAmount = %q, want trimmed amount", report.RewardAmount)
	}
	if report.RewardCurrency != "USD" {
		t.Fatalf("RewardCurrency = %q, want uppercased currency", report.RewardCurrency)
	}
	if report.RewardPaidAt != "2026-07-10" {
		t.Fatalf("RewardPaidAt = %q, want trimmed paid date", report.RewardPaidAt)
	}
	if report.RewardNote != "初回報奨金" {
		t.Fatalf("RewardNote = %q, want trimmed note", report.RewardNote)
	}
	if report.ReportURL != "https://hackerone.com/reports/12345" {
		t.Fatalf("ReportURL = %q, want trimmed HackerOne URL", report.ReportURL)
	}
	if report.MaintainerLog != "" {
		t.Fatalf("MaintainerLog = %q, want migrated blank legacy field", report.MaintainerLog)
	}
	if len(report.ConversationLogs) != 1 {
		t.Fatalf("len(ConversationLogs) = %d, want 1", len(report.ConversationLogs))
	}
	log := report.ConversationLogs[0]
	if log.From != "メンテナー" || log.To != "自分" {
		t.Fatalf("ConversationLog direction = %q -> %q, want メンテナー -> 自分", log.From, log.To)
	}
	if log.CommunicatedAt != "2026-06-30T10:30" {
		t.Fatalf("ConversationLog CommunicatedAt = %q, want trimmed datetime", log.CommunicatedAt)
	}
	if log.Body != "修正予定を共有" {
		t.Fatalf("ConversationLog Body = %q, want trimmed body", log.Body)
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

func TestNormalizeDraftMigratesLegacyMaintainerLog(t *testing.T) {
	report := normalizeDraft(ReportDraft{
		Title:         "Legacy log",
		MaintainerLog: "  2026-06-30 メンテナーへ影響範囲を共有  ",
	})

	if len(report.ConversationLogs) != 1 {
		t.Fatalf("len(ConversationLogs) = %d, want 1", len(report.ConversationLogs))
	}
	log := report.ConversationLogs[0]
	if log.From != "自分" || log.To != "メンテナー" {
		t.Fatalf("ConversationLog direction = %q -> %q, want 自分 -> メンテナー", log.From, log.To)
	}
	if log.Body != "2026-06-30 メンテナーへ影響範囲を共有" {
		t.Fatalf("ConversationLog Body = %q, want legacy body", log.Body)
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
	if report.NextActionAt != "" {
		t.Fatalf("NextActionAt = %q, want blank for legacy report", report.NextActionAt)
	}
	if report.RewardStatus != "Unknown" {
		t.Fatalf("RewardStatus = %q, want Unknown for legacy report", report.RewardStatus)
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
