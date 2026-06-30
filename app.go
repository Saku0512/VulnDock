package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type App struct {
	ctx       context.Context
	storePath string
}

type Report struct {
	ID               string              `json:"id"`
	Title            string              `json:"title"`
	Program          string              `json:"program"`
	Asset            string              `json:"asset"`
	CVSSVersion      string              `json:"cvssVersion"`
	CVSSScore        string              `json:"cvssScore"`
	CVSSVector       string              `json:"cvssVector"`
	Status           string              `json:"status"`
	SubmittedAt      string              `json:"submittedAt"`
	ReportURL        string              `json:"reportUrl"`
	MaintainerLog    string              `json:"maintainerLog"`
	ConversationLogs []ConversationEntry `json:"conversationLogs"`
	Tags             []string            `json:"tags"`
	PocFiles         []PocFile           `json:"pocFiles"`
	CreatedAt        string              `json:"createdAt"`
	UpdatedAt        string              `json:"updatedAt"`
}

type ReportDraft struct {
	ID               string              `json:"id"`
	Title            string              `json:"title"`
	Program          string              `json:"program"`
	Asset            string              `json:"asset"`
	CVSSVersion      string              `json:"cvssVersion"`
	CVSSScore        string              `json:"cvssScore"`
	CVSSVector       string              `json:"cvssVector"`
	Status           string              `json:"status"`
	SubmittedAt      string              `json:"submittedAt"`
	ReportURL        string              `json:"reportUrl"`
	MaintainerLog    string              `json:"maintainerLog"`
	ConversationLogs []ConversationEntry `json:"conversationLogs"`
	Tags             []string            `json:"tags"`
	PocFiles         []PocFile           `json:"pocFiles"`
}

type ConversationEntry struct {
	ID             string `json:"id"`
	From           string `json:"from"`
	To             string `json:"to"`
	CommunicatedAt string `json:"communicatedAt"`
	Body           string `json:"body"`
}

type PocFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Data string `json:"data"`
}

type storedReport struct {
	Report
	Severity string `json:"severity"`
	Body     string `json:"body"`
	Summary  string `json:"summary"`
	Impact   string `json:"impact"`
	Steps    string `json:"steps"`
	Evidence string `json:"evidence"`
	Notes    string `json:"notes"`
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.storePath = defaultStorePath()
}

func (a *App) ListReports() ([]Report, error) {
	return a.loadReports()
}

func (a *App) SaveReport(draft ReportDraft) (Report, error) {
	reports, err := a.loadReports()
	if err != nil {
		return Report{}, err
	}

	now := time.Now().Format(time.RFC3339)
	report := normalizeDraft(draft)
	report.UpdatedAt = now

	found := false
	for i := range reports {
		if reports[i].ID == report.ID && report.ID != "" {
			report.CreatedAt = reports[i].CreatedAt
			if report.CreatedAt == "" {
				report.CreatedAt = now
			}
			reports[i] = report
			found = true
			break
		}
	}

	if !found {
		report.ID = newReportID()
		report.CreatedAt = now
		reports = append(reports, report)
	}

	if err := a.saveReports(reports); err != nil {
		return Report{}, err
	}

	return report, nil
}

func (a *App) DeleteReport(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("report id is required")
	}

	reports, err := a.loadReports()
	if err != nil {
		return err
	}

	next := make([]Report, 0, len(reports))
	found := false
	for _, report := range reports {
		if report.ID == id {
			found = true
			continue
		}
		next = append(next, report)
	}
	if !found {
		return errors.New("report not found")
	}

	return a.saveReports(next)
}

func (a *App) StorePath() string {
	if a.storePath == "" {
		a.storePath = defaultStorePath()
	}
	return a.storePath
}

func (a *App) loadReports() ([]Report, error) {
	path := a.StorePath()
	content, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		reports := []Report{}
		return reports, a.saveReports(reports)
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(content))) == 0 {
		return []Report{}, nil
	}

	var stored []storedReport
	if err := json.Unmarshal(content, &stored); err != nil {
		return nil, err
	}

	reports, hadReportContent := migrateReports(stored)
	sortReports(reports)
	if hadReportContent {
		return reports, a.saveReports(reports)
	}
	return reports, nil
}

func (a *App) saveReports(reports []Report) error {
	sortReports(reports)

	path := a.StorePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	content, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, content, 0o600)
}

func normalizeDraft(draft ReportDraft) Report {
	conversationLogs := normalizeConversationLogs(draft.ConversationLogs, draft.MaintainerLog)

	return Report{
		ID:               strings.TrimSpace(draft.ID),
		Title:            withDefault(strings.TrimSpace(draft.Title), "Untitled report"),
		Program:          strings.TrimSpace(draft.Program),
		Asset:            strings.TrimSpace(draft.Asset),
		CVSSVersion:      normalizeChoice(draft.CVSSVersion, "3.1", []string{"3.1", "4.0"}),
		CVSSScore:        normalizeCVSSScore(draft.CVSSScore),
		CVSSVector:       strings.TrimSpace(draft.CVSSVector),
		Status:           normalizeChoice(draft.Status, "Draft", []string{"Draft", "Submitted", "Triaged", "Resolved", "Duplicate", "Rejected", "Paid"}),
		SubmittedAt:      strings.TrimSpace(draft.SubmittedAt),
		ReportURL:        strings.TrimSpace(draft.ReportURL),
		MaintainerLog:    "",
		ConversationLogs: conversationLogs,
		Tags:             normalizeTags(draft.Tags),
		PocFiles:         normalizePocFiles(draft.PocFiles),
	}
}

func migrateReports(stored []storedReport) ([]Report, bool) {
	reports := make([]Report, 0, len(stored))
	hadReportContent := false
	for _, item := range stored {
		report := item.Report
		hadReportContent = hadReportContent || hasReportContent(item)
		if strings.TrimSpace(report.CVSSVersion) == "" {
			report.CVSSVersion = "3.1"
		}
		if strings.TrimSpace(report.CVSSScore) == "" {
			report.CVSSScore = legacySeverityScore(item.Severity)
		} else {
			report.CVSSScore = normalizeCVSSScore(report.CVSSScore)
		}
		report.CVSSVector = strings.TrimSpace(report.CVSSVector)
		report.ConversationLogs = normalizeConversationLogs(report.ConversationLogs, report.MaintainerLog)
		report.MaintainerLog = ""
		report.Tags = normalizeTags(report.Tags)
		report.PocFiles = normalizePocFiles(report.PocFiles)
		reports = append(reports, report)
	}
	return reports, hadReportContent
}

func hasReportContent(report storedReport) bool {
	values := []string{
		report.Body,
		report.Summary,
		report.Impact,
		report.Steps,
		report.Evidence,
		report.Notes,
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func normalizeConversationLogs(logs []ConversationEntry, legacyLog string) []ConversationEntry {
	next := []ConversationEntry{}
	for i, log := range logs {
		body := strings.TrimSpace(log.Body)
		if body == "" {
			continue
		}

		from := normalizeParticipant(log.From, "自分")
		to := normalizeParticipant(log.To, oppositeParticipant(from))
		if from == to {
			to = oppositeParticipant(from)
		}

		id := strings.TrimSpace(log.ID)
		if id == "" {
			id = newConversationEntryID(i)
		}

		next = append(next, ConversationEntry{
			ID:             id,
			From:           from,
			To:             to,
			CommunicatedAt: strings.TrimSpace(log.CommunicatedAt),
			Body:           body,
		})
	}

	legacyLog = strings.TrimSpace(legacyLog)
	if len(next) == 0 && legacyLog != "" {
		next = append(next, ConversationEntry{
			ID:   newConversationEntryID(0),
			From: "自分",
			To:   "メンテナー",
			Body: legacyLog,
		})
	}

	return next
}

func normalizeParticipant(value string, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "自分", "me", "myself", "self":
		return "自分"
	case "メンテナー", "maintainer":
		return "メンテナー"
	default:
		return fallback
	}
}

func oppositeParticipant(value string) string {
	if value == "メンテナー" {
		return "自分"
	}
	return "メンテナー"
}

func normalizePocFiles(files []PocFile) []PocFile {
	next := []PocFile{}
	for _, file := range files {
		name := strings.TrimSpace(file.Name)
		data := strings.TrimSpace(file.Data)
		if name == "" || data == "" {
			continue
		}
		if file.Size < 0 {
			file.Size = 0
		}
		next = append(next, PocFile{
			Name: name,
			Type: strings.TrimSpace(file.Type),
			Size: file.Size,
			Data: data,
		})
	}
	return next
}

func normalizeCVSSScore(score string) string {
	score = strings.TrimSpace(score)
	if score == "" {
		return ""
	}

	value, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return ""
	}
	if value < 0 {
		value = 0
	}
	if value > 10 {
		value = 10
	}
	return strconv.FormatFloat(value, 'f', 1, 64)
}

func legacySeverityScore(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "4.0"
	case "low":
		return "0.1"
	case "info", "none":
		return "0.0"
	default:
		return ""
	}
}

func normalizeTags(tags []string) []string {
	seen := map[string]bool{}
	next := []string{}
	for _, tag := range tags {
		tag = strings.Trim(strings.TrimSpace(tag), "#")
		if tag == "" {
			continue
		}
		key := strings.ToLower(tag)
		if seen[key] {
			continue
		}
		seen[key] = true
		next = append(next, tag)
	}
	return next
}

func normalizeChoice(value string, fallback string, allowed []string) string {
	value = strings.TrimSpace(value)
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return candidate
		}
	}
	return fallback
}

func withDefault(value string, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func sortReports(reports []Report) {
	sort.SliceStable(reports, func(i, j int) bool {
		left := reports[i].UpdatedAt
		if left == "" {
			left = reports[i].CreatedAt
		}
		right := reports[j].UpdatedAt
		if right == "" {
			right = reports[j].CreatedAt
		}
		return left > right
	})
}

func newReportID() string {
	return "report_" + time.Now().UTC().Format("20060102150405.000000000")
}

func newConversationEntryID(index int) string {
	return "conversation_" + time.Now().UTC().Format("20060102150405.000000000") + "_" + strconv.Itoa(index)
}

func defaultStorePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		configDir = "."
	}
	return filepath.Join(configDir, "VulnDock", "reports.json")
}
