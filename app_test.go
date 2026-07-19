package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestNormalizeDraftAcceptsPublishedStatus(t *testing.T) {
	report := normalizeDraft(ReportDraft{Status: " published "})

	if report.Status != "Published" {
		t.Fatalf("Status = %q, want Published", report.Status)
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

func TestOpenPocFileRejectsSymlinkedAttachmentPath(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(filepath.Dir(app.StorePath()), "attachments", "attachment_link")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := app.OpenPocFile(PocFile{
		Name: "outside.txt",
		Path: "attachments/attachment_link/outside.txt",
	})
	if err == nil {
		t.Fatal("OpenPocFile followed a symlinked attachment path")
	}
}

func TestSaveReportRejectsInvalidStoredPocMetadata(t *testing.T) {
	tests := []struct {
		name string
		file PocFile
	}{
		{
			name: "path outside attachments",
			file: PocFile{Name: "poc.txt", Path: "attachments/../reports.json"},
		},
		{
			name: "absolute path",
			file: PocFile{Name: "poc.txt", Path: "/tmp/poc.txt"},
		},
		{
			name: "id only metadata",
			file: PocFile{ID: "attachment_1", Name: "poc.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := NewApp()
			app.storePath = filepath.Join(t.TempDir(), "reports.json")

			if _, err := app.SaveReport(ReportDraft{
				Title:    "Invalid metadata",
				PocFiles: []PocFile{tt.file},
			}); err == nil {
				t.Fatal("SaveReport accepted invalid stored PoC metadata")
			}
		})
	}
}

func TestSaveReportWithDataIgnoresCallerSuppliedAttachmentID(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "poc.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(filepath.Dir(app.StorePath()), "attachments", "attachment_attacker")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	report, err := app.SaveReport(ReportDraft{
		Title: "Data attachment",
		PocFiles: []PocFile{{
			ID:   "attachment_attacker",
			Name: "poc.txt",
			Type: "text/plain",
			Data: "data:text/plain;base64,aW5zaWRl",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.PocFiles[0].ID == "attachment_attacker" {
		t.Fatal("SaveReport reused caller-supplied attachment id for data upload")
	}
	outsideContent, err := os.ReadFile(outsideFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(outsideContent) != "outside" {
		t.Fatalf("outside symlink target was modified: %q", outsideContent)
	}
}

func TestNormalizePocFilesDropsInvalidStoredMetadata(t *testing.T) {
	files := normalizePocFiles([]PocFile{
		{Name: "valid.txt", Path: "attachments/attachment_1/valid.txt"},
		{Name: "bad.txt", Path: "attachments/../reports.json"},
		{Name: "id-only.txt", ID: "attachment_2"},
		{Name: "new.txt", Data: "data:text/plain;base64,YWJj"},
	})

	if len(files) != 2 {
		t.Fatalf("len(files) = %d, want 2 valid files: %#v", len(files), files)
	}
	if files[0].Name != "valid.txt" || files[1].Name != "new.txt" {
		t.Fatalf("normalized files = %#v, want valid stored file and new data file", files)
	}
}

func TestEncryptedBackupRoundTripRestoresReportsAndAttachments(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	report, err := source.SaveReport(ReportDraft{
		Title: "Secret report",
		PocFiles: []PocFile{
			{Name: "poc.txt", Type: "text/plain", Data: "data:text/plain;base64,YWJj"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	backup, err := source.CreateEncryptedBackup("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(backup.FileName, ".zip") {
		t.Fatalf("backup.FileName = %q, want .zip suffix", backup.FileName)
	}
	if strings.Contains(backup.FileName, time.Now().UTC().Format("20060102")) {
		t.Fatalf("backup.FileName = %q leaks creation date", backup.FileName)
	}
	archive, err := base64.StdEncoding.DecodeString(backup.Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(archive), "Secret report") || strings.Contains(string(archive), "abc") {
		t.Fatalf("encrypted backup archive leaked plaintext: %q", archive)
	}

	target := NewApp()
	target.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := target.RestoreEncryptedBackup(backup.Data, "wrong password"); err == nil {
		t.Fatal("RestoreEncryptedBackup accepted the wrong password")
	}

	restored, err := target.RestoreEncryptedBackup("data:application/zip;base64,"+backup.Data, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 {
		t.Fatalf("len(restored) = %d, want 1", len(restored))
	}
	if restored[0].Title != report.Title {
		t.Fatalf("restored title = %q, want %q", restored[0].Title, report.Title)
	}
	if len(restored[0].PocFiles) != 1 {
		t.Fatalf("len(restored[0].PocFiles) = %d, want 1", len(restored[0].PocFiles))
	}

	restoredPath, err := target.attachmentAbsolutePath(restored[0].PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "abc" {
		t.Fatalf("restored attachment = %q, want abc", content)
	}
}

func TestEncryptedBackupZipContainsOnlyManifestAndCiphertext(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{
		Title: "Sensitive backup title",
		PocFiles: []PocFile{
			{Name: "secret-poc.txt", Type: "text/plain", Data: "data:text/plain;base64,c2VjcmV0LXBvYw=="},
		},
	}); err != nil {
		t.Fatal(err)
	}

	backup, err := source.CreateEncryptedBackup("strong backup password")
	if err != nil {
		t.Fatal(err)
	}
	archive := decodeBackupDataForTest(t, backup.Data)
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}

	names := map[string]bool{}
	secrets := []string{
		"Sensitive backup title",
		"secret-poc.txt",
		"secret-poc",
		"c2VjcmV0LXBvYw==",
		"strong backup password",
	}
	for _, file := range reader.File {
		names[file.Name] = true
		content, err := readZipFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(content, []byte(secret)) {
				t.Fatalf("backup zip entry %q leaked secret %q", file.Name, secret)
			}
		}
	}
	if len(names) != 2 || !names[encryptedBackupManifestName] || !names[encryptedBackupPayloadName] {
		t.Fatalf("backup zip entries = %#v, want only manifest and encrypted payload", names)
	}

	manifest, ciphertext, err := readEncryptedBackupZip(archive)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Algorithm != encryptedBackupAlgorithm {
		t.Fatalf("manifest.Algorithm = %q, want %q", manifest.Algorithm, encryptedBackupAlgorithm)
	}
	if manifest.KDF != encryptedBackupKDF {
		t.Fatalf("manifest.KDF = %q, want %q", manifest.KDF, encryptedBackupKDF)
	}
	if manifest.KDFParams != defaultBackupKDFParams() {
		t.Fatalf("manifest.KDFParams = %#v, want %#v", manifest.KDFParams, defaultBackupKDFParams())
	}
	if strings.Contains(string(ciphertext), "Sensitive backup title") || strings.Contains(string(ciphertext), "secret-poc") {
		t.Fatalf("ciphertext leaked plaintext: %q", ciphertext)
	}
}

func TestCreateEncryptedBackupFailsWhenReferencedAttachmentIsMissing(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	report, err := app.SaveReport(ReportDraft{
		Title: "Missing file backup",
		PocFiles: []PocFile{
			{Name: "poc.txt", Type: "text/plain", Data: "data:text/plain;base64,YWJj"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	attachmentPath, err := app.attachmentAbsolutePath(report.PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(attachmentPath); err != nil {
		t.Fatal(err)
	}

	if _, err := app.CreateEncryptedBackup("backup password"); err == nil {
		t.Fatal("CreateEncryptedBackup succeeded with a missing referenced attachment")
	}
}

func TestCreateEncryptedBackupRejectsSymlinkedAttachmentPath(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	outsideDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outsideDir, "poc.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(filepath.Dir(app.StorePath()), "attachments", "attachment_link")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(app.StorePath()), 0o755); err != nil {
		t.Fatal(err)
	}
	reports := []Report{{
		ID:       "report_1",
		Title:    "Symlink report",
		PocFiles: []PocFile{{ID: "attachment_link", Name: "poc.txt", Path: "attachments/attachment_link/poc.txt"}},
	}}
	content, err := json.Marshal(reports)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app.StorePath(), content, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := app.CreateEncryptedBackup("backup password"); err == nil {
		t.Fatal("CreateEncryptedBackup followed a symlinked attachment path")
	}
}

func TestRestoreEncryptedBackupRejectsTamperedCiphertextWithoutChangingExistingData(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{
		Title: "New backup data",
		PocFiles: []PocFile{
			{Name: "new.txt", Type: "text/plain", Data: "data:text/plain;base64,bmV3"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	backup, err := source.CreateEncryptedBackup("backup password")
	if err != nil {
		t.Fatal(err)
	}

	target := NewApp()
	target.storePath = filepath.Join(t.TempDir(), "reports.json")
	existing, err := target.SaveReport(ReportDraft{
		Title: "Existing local data",
		PocFiles: []PocFile{
			{Name: "existing.txt", Type: "text/plain", Data: "data:text/plain;base64,b2xk"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	existingPath, err := target.attachmentAbsolutePath(existing.PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}

	tamperedArchive := tamperBackupCiphertextForTest(t, backup.Data)
	if _, err := target.RestoreEncryptedBackup(tamperedArchive, "backup password"); err == nil {
		t.Fatal("RestoreEncryptedBackup accepted tampered ciphertext")
	}

	reports, err := target.ListReports()
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Title != "Existing local data" {
		t.Fatalf("reports after failed restore = %#v, want existing local data preserved", reports)
	}
	content, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old" {
		t.Fatalf("existing attachment after failed restore = %q, want old", content)
	}
}

func TestRestoreEncryptedBackupRejectsUnsupportedKDFParams(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{Title: "KDF test"}); err != nil {
		t.Fatal(err)
	}
	backup, err := source.CreateEncryptedBackup("backup password")
	if err != nil {
		t.Fatal(err)
	}

	archive := decodeBackupDataForTest(t, backup.Data)
	manifest, ciphertext, err := readEncryptedBackupZip(archive)
	if err != nil {
		t.Fatal(err)
	}
	manifest.KDFParams.Memory = manifest.KDFParams.Memory * 2
	rebuilt, err := buildEncryptedBackupZip(manifest, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	target := NewApp()
	target.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := target.RestoreEncryptedBackup(base64.StdEncoding.EncodeToString(rebuilt), "backup password"); err == nil {
		t.Fatal("RestoreEncryptedBackup accepted unsupported KDF params")
	}
}

func TestRestoreEncryptedBackupRejectsTamperedManifestWithoutChangingExistingData(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{Title: "Manifest source"}); err != nil {
		t.Fatal(err)
	}
	backup, err := source.CreateEncryptedBackup("backup password")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*encryptedBackupManifest)
	}{
		{
			name: "format",
			mutate: func(manifest *encryptedBackupManifest) {
				manifest.Format = "vulndock.encrypted-backup.v999"
			},
		},
		{
			name: "algorithm",
			mutate: func(manifest *encryptedBackupManifest) {
				manifest.Algorithm = "AES-CBC"
			},
		},
		{
			name: "kdf",
			mutate: func(manifest *encryptedBackupManifest) {
				manifest.KDF = "pbkdf2"
			},
		},
		{
			name: "salt",
			mutate: func(manifest *encryptedBackupManifest) {
				salt, err := base64.StdEncoding.DecodeString(manifest.Salt)
				if err != nil {
					t.Fatal(err)
				}
				salt[0] ^= 0xff
				manifest.Salt = base64.StdEncoding.EncodeToString(salt)
			},
		},
		{
			name: "nonce",
			mutate: func(manifest *encryptedBackupManifest) {
				nonce, err := base64.StdEncoding.DecodeString(manifest.Nonce)
				if err != nil {
					t.Fatal(err)
				}
				nonce[0] ^= 0xff
				manifest.Nonce = base64.StdEncoding.EncodeToString(nonce)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, existingPath := appWithExistingRestoreDataForTest(t)
			mutatedBackup := mutateBackupManifestForTest(t, backup.Data, tt.mutate)

			if _, err := target.RestoreEncryptedBackup(mutatedBackup, "backup password"); err == nil {
				t.Fatal("RestoreEncryptedBackup accepted a tampered manifest")
			}
			assertExistingRestoreDataPreservedForTest(t, target, existingPath)
		})
	}
}

func TestRestoreEncryptedBackupRejectsMissingZipEntriesWithoutChangingExistingData(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{Title: "ZIP source"}); err != nil {
		t.Fatal(err)
	}
	backup, err := source.CreateEncryptedBackup("backup password")
	if err != nil {
		t.Fatal(err)
	}

	archive := decodeBackupDataForTest(t, backup.Data)
	manifest, ciphertext, err := readEncryptedBackupZip(archive)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		archive []byte
	}{
		{
			name:    "missing manifest",
			archive: buildBackupZipForTest(t, nil, ciphertext),
		},
		{
			name:    "missing payload",
			archive: buildBackupZipForTest(t, &manifest, nil),
		},
		{
			name:    "not a zip",
			archive: []byte("not-a-zip"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, existingPath := appWithExistingRestoreDataForTest(t)
			encoded := base64.StdEncoding.EncodeToString(tt.archive)

			if _, err := target.RestoreEncryptedBackup(encoded, "backup password"); err == nil {
				t.Fatal("RestoreEncryptedBackup accepted an invalid zip archive")
			}
			assertExistingRestoreDataPreservedForTest(t, target, existingPath)
		})
	}
}

func TestRestoreEncryptedBackupRejectsEncryptedUnsafePayloadWithoutChangingExistingData(t *testing.T) {
	tests := []struct {
		name    string
		payload encryptedBackupPayload
	}{
		{
			name: "report points outside attachments",
			payload: encryptedBackupPayload{
				Format: encryptedBackupFormat,
				Reports: []Report{{
					Title:    "Malicious payload",
					PocFiles: []PocFile{{Name: "poc.txt", Path: "attachments/../reports.json"}},
				}},
				Attachments: []backupAttachment{{Path: "attachments/attachment_1/poc.txt", Data: base64.StdEncoding.EncodeToString([]byte("x"))}},
			},
		},
		{
			name: "attachment content path escapes",
			payload: encryptedBackupPayload{
				Format: encryptedBackupFormat,
				Reports: []Report{{
					Title:    "Malicious payload",
					PocFiles: []PocFile{{Name: "poc.txt", Path: "attachments/attachment_1/poc.txt"}},
				}},
				Attachments: []backupAttachment{{Path: "attachments/attachment_1/../../reports.json", Data: base64.StdEncoding.EncodeToString([]byte("x"))}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, existingPath := appWithExistingRestoreDataForTest(t)
			backup := encryptedBackupFromPayloadForTest(t, tt.payload, "backup password")

			if _, err := target.RestoreEncryptedBackup(backup, "backup password"); err == nil {
				t.Fatal("RestoreEncryptedBackup accepted an encrypted unsafe payload")
			}
			assertExistingRestoreDataPreservedForTest(t, target, existingPath)
			if _, err := os.Stat(filepath.Join(filepath.Dir(target.StorePath()), "reports.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRestoreEncryptedBackupReplacesExistingDataAndRemovesOldAttachments(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{
		Title: "Restored report",
		PocFiles: []PocFile{
			{Name: "restored.txt", Type: "text/plain", Data: "data:text/plain;base64,bmV3"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	backup, err := source.CreateEncryptedBackup("backup password")
	if err != nil {
		t.Fatal(err)
	}

	target, oldAttachmentPath := appWithExistingRestoreDataForTest(t)
	restored, err := target.RestoreEncryptedBackup(backup.Data, "backup password")
	if err != nil {
		t.Fatal(err)
	}

	if len(restored) != 1 || restored[0].Title != "Restored report" {
		t.Fatalf("restored reports = %#v, want only restored report", restored)
	}
	if _, err := os.Stat(oldAttachmentPath); !os.IsNotExist(err) {
		t.Fatalf("old attachment still exists or stat failed unexpectedly: %v", err)
	}

	restoredPath, err := target.attachmentAbsolutePath(restored[0].PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(restoredPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new" {
		t.Fatalf("restored attachment = %q, want new", content)
	}
}

func TestRestoreBackupPayloadCleansTemporaryDirectoryOnFailure(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")

	err := app.restoreBackupPayload(nil, map[string][]byte{
		"attachments/../reports.json": []byte("secret"),
	})
	if err == nil {
		t.Fatal("restoreBackupPayload accepted an unsafe staged attachment path")
	}
	assertNoRestoreStageDirsForTest(t, filepath.Dir(app.StorePath()))
}

func TestRestoreEncryptedBackupRejectsMalformedArchiveInputs(t *testing.T) {
	app, existingPath := appWithExistingRestoreDataForTest(t)
	withMaxEncryptedBackupBytesForTest(t, 32)

	largeArchive := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), maxEncryptedBackupBytes+1))
	tests := []struct {
		name string
		data string
	}{
		{name: "broken base64", data: "not-base64"},
		{name: "broken data URL base64", data: "data:application/zip;base64,%%%"},
		{name: "missing data URL payload", data: "data:application/zip;base64"},
		{name: "archive too large", data: largeArchive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := app.RestoreEncryptedBackup(tt.data, "backup password"); err == nil {
				t.Fatal("RestoreEncryptedBackup accepted malformed archive input")
			}
			assertExistingRestoreDataPreservedForTest(t, app, existingPath)
		})
	}
}

func TestReadEncryptedBackupZipRejectsOversizedEntries(t *testing.T) {
	withMaxEncryptedBackupBytesForTest(t, 32)

	manifest := encryptedBackupManifest{
		Format:    encryptedBackupFormat,
		Algorithm: encryptedBackupAlgorithm,
		KDF:       encryptedBackupKDF,
		KDFParams: defaultBackupKDFParams(),
		Salt:      base64.StdEncoding.EncodeToString([]byte("1234567890123456")),
		Nonce:     base64.StdEncoding.EncodeToString([]byte("123456789012")),
	}
	archive := buildBackupZipForTest(t, &manifest, bytes.Repeat([]byte("x"), maxEncryptedBackupBytes+1))

	if _, _, err := readEncryptedBackupZip(archive); err == nil {
		t.Fatal("readEncryptedBackupZip accepted an oversized payload entry")
	}
}

func TestEncryptedBackupPasswordBoundaries(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := app.SaveReport(ReportDraft{Title: "Password boundary"}); err != nil {
		t.Fatal(err)
	}

	for _, password := range []string{" ", "\t\n"} {
		if _, err := app.CreateEncryptedBackup(password); err == nil {
			t.Fatalf("CreateEncryptedBackup accepted whitespace-only password %q", password)
		}
	}

	for _, password := range []string{"正しい パスワード 🔐", strings.Repeat("long-password-", 128)} {
		backup, err := app.CreateEncryptedBackup(password)
		if err != nil {
			t.Fatalf("CreateEncryptedBackup(%q) failed: %v", password, err)
		}
		restored, err := app.RestoreEncryptedBackup(backup.Data, password)
		if err != nil {
			t.Fatalf("RestoreEncryptedBackup(%q) failed: %v", password, err)
		}
		if len(restored) != 1 || restored[0].Title != "Password boundary" {
			t.Fatalf("restored reports = %#v, want password boundary report", restored)
		}
	}
}

func TestEncryptedBackupIsNonDeterministicForSameDataAndPassword(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := app.SaveReport(ReportDraft{
		Title: "Same plaintext",
		PocFiles: []PocFile{
			{Name: "same.txt", Type: "text/plain", Data: "data:text/plain;base64,c2FtZQ=="},
		},
	}); err != nil {
		t.Fatal(err)
	}

	first, err := app.CreateEncryptedBackup("same password")
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.CreateEncryptedBackup("same password")
	if err != nil {
		t.Fatal(err)
	}
	if first.Data == second.Data {
		t.Fatal("encrypted backups for same data and password were identical")
	}

	firstManifest, firstCiphertext, err := readEncryptedBackupZip(decodeBackupDataForTest(t, first.Data))
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, secondCiphertext, err := readEncryptedBackupZip(decodeBackupDataForTest(t, second.Data))
	if err != nil {
		t.Fatal(err)
	}
	if firstManifest.Salt == secondManifest.Salt {
		t.Fatal("encrypted backups reused salt")
	}
	if firstManifest.Nonce == secondManifest.Nonce {
		t.Fatal("encrypted backups reused nonce")
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Fatal("encrypted backups produced identical ciphertext")
	}
}

func TestRestoreEncryptedBackupHandlesDuplicateReferencesAndRemovesOrphanPayloadAttachments(t *testing.T) {
	payload := encryptedBackupPayload{
		Format: encryptedBackupFormat,
		Reports: []Report{
			{
				ID:       "one",
				Title:    "Shared attachment one",
				PocFiles: []PocFile{{ID: "attachment_shared", Name: "shared.txt", Type: "text/plain", Size: 6, Path: "attachments/attachment_shared/shared.txt"}},
			},
			{
				ID:       "two",
				Title:    "Shared attachment two",
				PocFiles: []PocFile{{ID: "attachment_shared", Name: "shared.txt", Type: "text/plain", Size: 6, Path: "attachments/attachment_shared/shared.txt"}},
			},
		},
		Attachments: []backupAttachment{
			{Path: "attachments/attachment_shared/shared.txt", Data: base64.StdEncoding.EncodeToString([]byte("shared"))},
			{Path: "attachments/attachment_orphan/orphan.txt", Data: base64.StdEncoding.EncodeToString([]byte("orphan"))},
		},
	}

	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	backup := encryptedBackupFromPayloadForTest(t, payload, "backup password")
	restored, err := app.RestoreEncryptedBackup(backup, "backup password")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 2 {
		t.Fatalf("len(restored) = %d, want 2", len(restored))
	}
	for _, report := range restored {
		if len(report.PocFiles) != 1 || report.PocFiles[0].Path != "attachments/attachment_shared/shared.txt" {
			t.Fatalf("restored report has unexpected PoC files: %#v", report)
		}
	}

	sharedPath, err := app.attachmentAbsolutePath(restored[0].PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(sharedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "shared" {
		t.Fatalf("shared attachment = %q, want shared", content)
	}

	orphanPath := filepath.Join(filepath.Dir(app.StorePath()), "attachments", "attachment_orphan", "orphan.txt")
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatalf("orphan payload attachment still exists or stat failed unexpectedly: %v", err)
	}
}

func TestRestoredDataCanBeReBackedUpAndRestoredAgain(t *testing.T) {
	source := NewApp()
	source.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := source.SaveReport(ReportDraft{
		Title: "Portable report",
		PocFiles: []PocFile{
			{Name: "portable.txt", Type: "text/plain", Data: "data:text/plain;base64,cG9ydGFibGU="},
		},
	}); err != nil {
		t.Fatal(err)
	}
	firstBackup, err := source.CreateEncryptedBackup("first password")
	if err != nil {
		t.Fatal(err)
	}

	intermediate := NewApp()
	intermediate.storePath = filepath.Join(t.TempDir(), "reports.json")
	if _, err := intermediate.RestoreEncryptedBackup(firstBackup.Data, "first password"); err != nil {
		t.Fatal(err)
	}
	secondBackup, err := intermediate.CreateEncryptedBackup("second password")
	if err != nil {
		t.Fatal(err)
	}

	final := NewApp()
	final.storePath = filepath.Join(t.TempDir(), "reports.json")
	restored, err := final.RestoreEncryptedBackup(secondBackup.Data, "second password")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].Title != "Portable report" {
		t.Fatalf("final restored reports = %#v, want portable report", restored)
	}
	path, err := final.attachmentAbsolutePath(restored[0].PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "portable" {
		t.Fatalf("final restored attachment = %q, want portable", content)
	}
}

func TestNormalizeBackupPayloadRejectsUnsafeOrMissingAttachments(t *testing.T) {
	tests := []struct {
		name    string
		payload encryptedBackupPayload
	}{
		{
			name: "attachment path outside attachments",
			payload: encryptedBackupPayload{
				Format: encryptedBackupFormat,
				Reports: []Report{{
					Title:    "Unsafe path",
					PocFiles: []PocFile{{Name: "poc.txt", Path: "attachments/../reports.json"}},
				}},
				Attachments: []backupAttachment{{Path: "attachments/../reports.json", Data: base64.StdEncoding.EncodeToString([]byte("x"))}},
			},
		},
		{
			name: "attachment content missing",
			payload: encryptedBackupPayload{
				Format: encryptedBackupFormat,
				Reports: []Report{{
					Title:    "Missing attachment",
					PocFiles: []PocFile{{Name: "poc.txt", Path: "attachments/attachment_1/poc.txt"}},
				}},
			},
		},
		{
			name: "attachment path not under attachments",
			payload: encryptedBackupPayload{
				Format: encryptedBackupFormat,
				Reports: []Report{{
					Title:    "Wrong root",
					PocFiles: []PocFile{{Name: "poc.txt", Path: "reports.json"}},
				}},
				Attachments: []backupAttachment{{Path: "reports.json", Data: base64.StdEncoding.EncodeToString([]byte("x"))}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := normalizeBackupPayload(tt.payload); err == nil {
				t.Fatal("normalizeBackupPayload accepted invalid backup payload")
			}
		})
	}
}

func TestEncryptedBackupRequiresPassword(t *testing.T) {
	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")

	if _, err := app.CreateEncryptedBackup(""); err == nil {
		t.Fatal("CreateEncryptedBackup accepted an empty password")
	}
	if _, err := app.RestoreEncryptedBackup("not-base64", ""); err == nil {
		t.Fatal("RestoreEncryptedBackup accepted an empty password")
	}
}

func decodeBackupDataForTest(t *testing.T, data string) []byte {
	t.Helper()

	archive, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

func tamperBackupCiphertextForTest(t *testing.T, backupData string) string {
	t.Helper()

	archive := decodeBackupDataForTest(t, backupData)
	manifest, ciphertext, err := readEncryptedBackupZip(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext is empty")
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	rebuilt, err := buildEncryptedBackupZip(manifest, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(rebuilt)
}

func mutateBackupManifestForTest(t *testing.T, backupData string, mutate func(*encryptedBackupManifest)) string {
	t.Helper()

	archive := decodeBackupDataForTest(t, backupData)
	manifest, ciphertext, err := readEncryptedBackupZip(archive)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&manifest)
	rebuilt, err := buildEncryptedBackupZip(manifest, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(rebuilt)
}

func encryptedBackupFromPayloadForTest(t *testing.T, payload encryptedBackupPayload, password string) string {
	t.Helper()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	manifest, ciphertext, err := encryptBackupPayload(payloadJSON, password)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := buildEncryptedBackupZip(manifest, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(archive)
}

func buildBackupZipForTest(t *testing.T, manifest *encryptedBackupManifest, ciphertext []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	if manifest != nil {
		manifestJSON, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeZipFile(archive, encryptedBackupManifestName, manifestJSON); err != nil {
			t.Fatal(err)
		}
	}
	if ciphertext != nil {
		if err := writeZipFile(archive, encryptedBackupPayloadName, ciphertext); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func withMaxEncryptedBackupBytesForTest(t *testing.T, value int) {
	t.Helper()

	original := maxEncryptedBackupBytes
	maxEncryptedBackupBytes = value
	t.Cleanup(func() {
		maxEncryptedBackupBytes = original
	})
}

func appWithExistingRestoreDataForTest(t *testing.T) (*App, string) {
	t.Helper()

	app := NewApp()
	app.storePath = filepath.Join(t.TempDir(), "reports.json")
	existing, err := app.SaveReport(ReportDraft{
		Title: "Existing local data",
		PocFiles: []PocFile{
			{Name: "existing.txt", Type: "text/plain", Data: "data:text/plain;base64,b2xk"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	existingPath, err := app.attachmentAbsolutePath(existing.PocFiles[0])
	if err != nil {
		t.Fatal(err)
	}
	return app, existingPath
}

func assertNoRestoreStageDirsForTest(t *testing.T, baseDir string) {
	t.Helper()

	entries, err := os.ReadDir(baseDir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".vulndock-restore-") {
			t.Fatalf("restore staging directory was left behind: %s", filepath.Join(baseDir, entry.Name()))
		}
	}
}

func assertExistingRestoreDataPreservedForTest(t *testing.T, app *App, existingPath string) {
	t.Helper()

	reports, err := app.ListReports()
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Title != "Existing local data" {
		t.Fatalf("reports after failed restore = %#v, want existing local data preserved", reports)
	}
	content, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old" {
		t.Fatalf("existing attachment after failed restore = %q, want old", content)
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
