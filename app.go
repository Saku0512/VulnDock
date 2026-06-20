package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type App struct {
	ctx       context.Context
	storePath string
}

type Report struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Program     string    `json:"program"`
	Asset       string    `json:"asset"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	SubmittedAt string    `json:"submittedAt"`
	Tags        []string  `json:"tags"`
	Body        string    `json:"body"`
	PocFiles    []PocFile `json:"pocFiles"`
	CreatedAt   string    `json:"createdAt"`
	UpdatedAt   string    `json:"updatedAt"`
}

type ReportDraft struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Program     string    `json:"program"`
	Asset       string    `json:"asset"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	SubmittedAt string    `json:"submittedAt"`
	Tags        []string  `json:"tags"`
	Body        string    `json:"body"`
	PocFiles    []PocFile `json:"pocFiles"`
}

type PocFile struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Data string `json:"data"`
}

type storedReport struct {
	Report
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

	reports := migrateReports(stored)
	sortReports(reports)
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
	return Report{
		ID:          strings.TrimSpace(draft.ID),
		Title:       withDefault(strings.TrimSpace(draft.Title), "Untitled report"),
		Program:     strings.TrimSpace(draft.Program),
		Asset:       strings.TrimSpace(draft.Asset),
		Severity:    normalizeChoice(draft.Severity, "Medium", []string{"Critical", "High", "Medium", "Low", "Info"}),
		Status:      normalizeChoice(draft.Status, "Draft", []string{"Draft", "Submitted", "Triaged", "Resolved", "Duplicate", "Rejected", "Paid"}),
		SubmittedAt: strings.TrimSpace(draft.SubmittedAt),
		Tags:        normalizeTags(draft.Tags),
		Body:        strings.TrimSpace(draft.Body),
		PocFiles:    normalizePocFiles(draft.PocFiles),
	}
}

func migrateReports(stored []storedReport) []Report {
	reports := make([]Report, 0, len(stored))
	for _, item := range stored {
		report := item.Report
		if strings.TrimSpace(report.Body) == "" {
			report.Body = legacyBody(item)
		}
		report.Tags = normalizeTags(report.Tags)
		report.PocFiles = normalizePocFiles(report.PocFiles)
		reports = append(reports, report)
	}
	return reports
}

func legacyBody(report storedReport) string {
	sections := []struct {
		title string
		value string
	}{
		{title: "概要", value: report.Summary},
		{title: "影響", value: report.Impact},
		{title: "再現手順", value: report.Steps},
		{title: "証跡リンク / 添付メモ", value: report.Evidence},
		{title: "メモ", value: report.Notes},
	}

	parts := []string{}
	for _, section := range sections {
		value := strings.TrimSpace(section.value)
		if value == "" {
			continue
		}
		parts = append(parts, "## "+section.title+"\n"+value)
	}
	return strings.Join(parts, "\n\n")
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

func defaultStorePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		configDir = "."
	}
	return filepath.Join(configDir, "VulnDock", "reports.json")
}
