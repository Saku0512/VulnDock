package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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
		Memo:           "  再現時は管理者ロールで確認する  ",
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
	if report.Memo != "再現時は管理者ロールで確認する" {
		t.Fatalf("Memo = %q, want trimmed memo", report.Memo)
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
	if report.Memo != "" {
		t.Fatalf("Memo = %q, want blank for legacy report", report.Memo)
	}
	if !hadReportContent {
		t.Fatal("hadReportContent = false, want true")
	}
	if got := strings.Join(report.Tags, ","); got != "auth" {
		t.Fatalf("Tags = %q, want auth", got)
	}
}

func TestListReportsMigratesLegacyPocDataURLsToFiles(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")

	legacy := []Report{
		{
			ID:    "legacy",
			Title: "Legacy report",
			PocFiles: []PocFile{
				{Name: " poc.txt ", Type: " text/plain ", Size: 12, Data: "data:text/plain;base64,YWJj"},
			},
		},
	}
	content, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(app.storePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.storePath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	reports, err := app.ListReports()
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || len(reports[0].PocFiles) != 1 {
		t.Fatalf("reports = %#v, want one report with one PoC file", reports)
	}

	file := reports[0].PocFiles[0]
	if file.Data != "" {
		t.Fatalf("PocFile.Data = %q, want empty after migration", file.Data)
	}
	if file.ID == "" || file.Path == "" {
		t.Fatalf("PocFile did not get storage metadata: %#v", file)
	}
	if file.Name != "poc.txt" {
		t.Fatalf("PocFile.Name = %q, want trimmed name", file.Name)
	}
	if file.Size != 3 {
		t.Fatalf("PocFile.Size = %d, want decoded size", file.Size)
	}

	storedPath, err := app.attachmentAbsolutePath(file)
	if err != nil {
		t.Fatal(err)
	}
	storedContent, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedContent) != "abc" {
		t.Fatalf("stored attachment = %q, want abc", storedContent)
	}

	savedJSON, err := os.ReadFile(app.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(savedJSON), "data:text/plain") || strings.Contains(string(savedJSON), `"data"`) {
		t.Fatalf("reports.json still contains embedded data URL: %s", savedJSON)
	}
}

func TestSaveReportStoresPocDataOutsideJSON(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")

	report, err := app.SaveReport(ReportDraft{
		Title: "Externalized attachment",
		PocFiles: []PocFile{
			{Name: " poc.txt ", Type: " text/plain ", Data: "data:text/plain;base64,YWJj"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PocFiles) != 1 {
		t.Fatalf("len(PocFiles) = %d, want 1", len(report.PocFiles))
	}
	file := report.PocFiles[0]
	if file.Data != "" {
		t.Fatalf("PocFile.Data = %q, want empty after save", file.Data)
	}
	if file.ID == "" || file.Path == "" {
		t.Fatalf("PocFile missing storage metadata: %#v", file)
	}

	storedPath, err := app.attachmentAbsolutePath(file)
	if err != nil {
		t.Fatal(err)
	}
	storedContent, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedContent) != "abc" {
		t.Fatalf("stored attachment = %q, want abc", storedContent)
	}

	openURL, err := app.OpenPocFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(openURL, "file://") {
		t.Fatalf("OpenPocFile = %q, want file URL", openURL)
	}

	savedJSON, err := os.ReadFile(app.storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(savedJSON), "data:text/plain") || strings.Contains(string(savedJSON), `"data"`) {
		t.Fatalf("reports.json still contains embedded data URL: %s", savedJSON)
	}
}

func TestOpenPocFileRejectsPathOutsideAttachments(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	if err := os.WriteFile(app.storePath, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := app.OpenPocFile(PocFile{Name: "reports.json", Path: "reports.json"}); err == nil {
		t.Fatal("OpenPocFile accepted a path outside the attachments directory")
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

func FuzzNormalizeDraft(f *testing.F) {
	f.Add(
		"  Stored XSS  ",
		"4.0",
		"7.94",
		"submitted",
		"paid",
		"#xss",
		" XSS ",
		" poc.py ",
		" data:text/plain;base64,abc ",
		"maintainer",
		"maintainer",
		"  fix planned  ",
		int64(-1),
	)
	f.Add("", "", "high", "", "", "", "api", "", "data", "", "", "", int64(128))

	f.Fuzz(func(
		t *testing.T,
		title string,
		cvssVersion string,
		cvssScore string,
		status string,
		rewardStatus string,
		tagA string,
		tagB string,
		pocName string,
		pocData string,
		from string,
		to string,
		body string,
		pocSize int64,
	) {
		if len(title)+len(cvssVersion)+len(cvssScore)+len(status)+len(rewardStatus)+len(tagA)+len(tagB)+len(pocName)+len(pocData)+len(from)+len(to)+len(body) > 8192 {
			t.Skip()
		}

		report := normalizeDraft(ReportDraft{
			Title:         title,
			CVSSVersion:   cvssVersion,
			CVSSScore:     cvssScore,
			Status:        status,
			RewardStatus:  rewardStatus,
			MaintainerLog: "  ",
			ConversationLogs: []ConversationEntry{
				{From: from, To: to, Body: body},
			},
			Tags: []string{tagA, tagB},
			PocFiles: []PocFile{
				{Name: pocName, Size: pocSize, Data: pocData},
			},
		})

		if report.Title == "" {
			t.Fatal("normalized title must not be empty")
		}
		if strings.TrimSpace(title) == "" && report.Title != "Untitled report" {
			t.Fatalf("blank title normalized to %q, want Untitled report", report.Title)
		}
		if report.CVSSVersion != "3.1" && report.CVSSVersion != "4.0" {
			t.Fatalf("unexpected CVSSVersion %q", report.CVSSVersion)
		}
		if report.CVSSScore != "" {
			value, err := strconv.ParseFloat(report.CVSSScore, 64)
			if err != nil {
				t.Fatalf("normalized CVSSScore is not numeric: %q", report.CVSSScore)
			}
			if value < 0 || value > 10 {
				t.Fatalf("normalized CVSSScore out of range: %q", report.CVSSScore)
			}
		}
		if report.MaintainerLog != "" {
			t.Fatalf("MaintainerLog = %q, want blank after migration", report.MaintainerLog)
		}
		for _, log := range report.ConversationLogs {
			if strings.TrimSpace(log.Body) == "" {
				t.Fatalf("blank conversation log was kept: %#v", log)
			}
			if log.From == log.To {
				t.Fatalf("conversation participants match: %#v", log)
			}
		}
		for _, tag := range report.Tags {
			if tag == "" || strings.HasPrefix(tag, "#") || strings.HasSuffix(tag, "#") {
				t.Fatalf("tag was not normalized: %q", tag)
			}
		}
		for _, file := range report.PocFiles {
			if file.Name == "" || file.Data == "" {
				t.Fatalf("blank PoC file fields were kept: %#v", file)
			}
			if file.Size < 0 {
				t.Fatalf("negative PoC file size was kept: %#v", file)
			}
		}
	})
}
