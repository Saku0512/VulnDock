package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
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
	NextActionAt     string              `json:"nextActionAt"`
	RewardStatus     string              `json:"rewardStatus"`
	RewardAmount     string              `json:"rewardAmount"`
	RewardCurrency   string              `json:"rewardCurrency"`
	RewardPaidAt     string              `json:"rewardPaidAt"`
	RewardNote       string              `json:"rewardNote"`
	Memo             string              `json:"memo"`
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
	NextActionAt     string              `json:"nextActionAt"`
	RewardStatus     string              `json:"rewardStatus"`
	RewardAmount     string              `json:"rewardAmount"`
	RewardCurrency   string              `json:"rewardCurrency"`
	RewardPaidAt     string              `json:"rewardPaidAt"`
	RewardNote       string              `json:"rewardNote"`
	Memo             string              `json:"memo"`
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
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
	Path string `json:"path,omitempty"`
	Data string `json:"data,omitempty"`
}

type EncryptedBackup struct {
	FileName string `json:"fileName"`
	Data     string `json:"data"`
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

type encryptedBackupManifest struct {
	Format    string          `json:"format"`
	Algorithm string          `json:"algorithm"`
	KDF       string          `json:"kdf"`
	KDFParams backupKDFParams `json:"kdfParams"`
	Salt      string          `json:"salt"`
	Nonce     string          `json:"nonce"`
}

type backupKDFParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keyLen"`
}

type encryptedBackupPayload struct {
	Format      string             `json:"format"`
	Reports     []Report           `json:"reports"`
	Attachments []backupAttachment `json:"attachments"`
}

type backupAttachment struct {
	Path string `json:"path"`
	Data string `json:"data"`
}

const (
	encryptedBackupFormat       = "vulndock.encrypted-backup.v1"
	encryptedBackupManifestName = "vulndock-backup.json"
	encryptedBackupPayloadName  = "payload.bin"
	encryptedBackupAlgorithm    = "AES-256-GCM"
	encryptedBackupKDF          = "argon2id"
	backupKDFTime               = uint32(3)
	backupKDFMemory             = uint32(64 * 1024)
	backupKDFThreads            = uint8(4)
	backupKDFKeyLen             = uint32(32)
)

var maxEncryptedBackupBytes = 256 * 1024 * 1024

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
	if err := validateIncomingPocFiles(draft.PocFiles); err != nil {
		return Report{}, err
	}

	now := time.Now().Format(time.RFC3339)
	report := normalizeDraft(draft)
	if _, err := a.persistPocFiles(&report); err != nil {
		return Report{}, err
	}
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

func (a *App) OpenPocFile(file PocFile) (string, error) {
	path, err := a.attachmentAbsolutePath(file)
	if err != nil {
		return "", err
	}
	info, err := secureAttachmentFileInfo(a.attachmentsDir(), path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("attachment path points to a directory")
	}

	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String(), nil
}

func (a *App) CreateEncryptedBackup(password string) (EncryptedBackup, error) {
	if err := validateBackupPassword(password); err != nil {
		return EncryptedBackup{}, err
	}

	reports, err := a.loadReports()
	if err != nil {
		return EncryptedBackup{}, err
	}

	payload, err := a.buildBackupPayload(reports)
	if err != nil {
		return EncryptedBackup{}, err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return EncryptedBackup{}, err
	}

	manifest, ciphertext, err := encryptBackupPayload(payloadJSON, password)
	if err != nil {
		return EncryptedBackup{}, err
	}

	archive, err := buildEncryptedBackupZip(manifest, ciphertext)
	if err != nil {
		return EncryptedBackup{}, err
	}

	suffix, err := randomHex(6)
	if err != nil {
		return EncryptedBackup{}, err
	}
	return EncryptedBackup{
		FileName: "vulndock-backup-" + suffix + ".zip",
		Data:     base64.StdEncoding.EncodeToString(archive),
	}, nil
}

func (a *App) RestoreEncryptedBackup(archiveData string, password string) ([]Report, error) {
	if err := validateBackupPassword(password); err != nil {
		return nil, err
	}

	archive, err := decodeBackupArchiveData(archiveData)
	if err != nil {
		return nil, err
	}
	if len(archive) > maxEncryptedBackupBytes {
		return nil, errors.New("backup archive is too large")
	}

	manifest, ciphertext, err := readEncryptedBackupZip(archive)
	if err != nil {
		return nil, err
	}
	payloadJSON, err := decryptBackupPayload(manifest, ciphertext, password)
	if err != nil {
		return nil, err
	}

	var payload encryptedBackupPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, err
	}
	if payload.Format != encryptedBackupFormat {
		return nil, errors.New("unsupported encrypted backup payload")
	}

	reports, attachments, err := normalizeBackupPayload(payload)
	if err != nil {
		return nil, err
	}
	if err := a.restoreBackupPayload(reports, attachments); err != nil {
		return nil, err
	}

	reports, err = a.loadReports()
	if err != nil {
		return nil, err
	}
	return reports, nil
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
	hadAttachmentMigration := false
	for i := range reports {
		migrated, err := a.persistPocFiles(&reports[i])
		if err != nil {
			return nil, err
		}
		if migrated {
			hadAttachmentMigration = true
		}
	}
	sortReports(reports)
	if hadReportContent || hadAttachmentMigration {
		return reports, a.saveReports(reports)
	}
	return reports, nil
}

func (a *App) saveReports(reports []Report) error {
	for i := range reports {
		if _, err := a.persistPocFiles(&reports[i]); err != nil {
			return err
		}
		if err := validatePocFileMetadata(reports[i].PocFiles); err != nil {
			return err
		}
	}
	if err := a.writeReportsFile(reports); err != nil {
		return err
	}
	return a.cleanupOrphanAttachments(reports)
}

func (a *App) writeReportsFile(reports []Report) error {
	return writeReportsToPath(a.StorePath(), reports)
}

func (a *App) persistPocFiles(report *Report) (bool, error) {
	changed := false
	for i := range report.PocFiles {
		file := &report.PocFiles[i]
		if strings.TrimSpace(file.Data) == "" {
			continue
		}

		stored, err := a.writeAttachment(*file)
		if err != nil {
			return false, err
		}
		*file = stored
		changed = true
	}
	return changed, nil
}

func (a *App) writeAttachment(file PocFile) (PocFile, error) {
	name := sanitizeAttachmentName(file.Name)
	contentType, content, err := decodeDataURL(file.Data)
	if err != nil {
		return PocFile{}, fmt.Errorf("decode PoC attachment %q: %w", name, err)
	}

	id := newAttachmentID()
	if err := ensureDirNoSymlink(a.attachmentsDir(), 0o700); err != nil {
		return PocFile{}, err
	}
	dir := filepath.Join(a.attachmentsDir(), id)
	if err := ensureDirNoSymlink(dir, 0o700); err != nil {
		return PocFile{}, err
	}

	path := filepath.Join(dir, name)
	if _, err := os.Lstat(path); err == nil {
		return PocFile{}, errors.New("PoC attachment target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return PocFile{}, err
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return PocFile{}, err
	}

	file.ID = id
	file.Name = name
	if strings.TrimSpace(file.Type) == "" {
		file.Type = contentType
	}
	file.Type = strings.TrimSpace(file.Type)
	file.Size = int64(len(content))
	file.Path = filepath.ToSlash(filepath.Join("attachments", id, name))
	file.Data = ""
	return file, nil
}

func decodeDataURL(data string) (string, []byte, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return "", nil, errors.New("attachment data is required")
	}
	if !strings.HasPrefix(strings.ToLower(data), "data:") {
		return "", nil, errors.New("attachment data must be a data URL")
	}

	header, payload, ok := strings.Cut(data[5:], ",")
	if !ok {
		return "", nil, errors.New("data URL is missing payload")
	}

	parts := strings.Split(header, ";")
	contentType := strings.TrimSpace(parts[0])
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	isBase64 := false
	for _, part := range parts[1:] {
		if strings.EqualFold(strings.TrimSpace(part), "base64") {
			isBase64 = true
			break
		}
	}
	if !isBase64 {
		return "", nil, errors.New("data URL payload must be base64 encoded")
	}

	content, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", nil, err
	}
	return contentType, content, nil
}

func (a *App) attachmentAbsolutePath(file PocFile) (string, error) {
	relPath := strings.TrimSpace(file.Path)
	if relPath == "" {
		return "", errors.New("attachment path is required")
	}
	if filepath.IsAbs(relPath) {
		return "", errors.New("attachment path must be relative")
	}

	base, err := filepath.Abs(filepath.Dir(a.StorePath()))
	if err != nil {
		return "", err
	}
	attachmentsBase, err := filepath.Abs(a.attachmentsDir())
	if err != nil {
		return "", err
	}
	candidate, err := filepath.Abs(filepath.Join(base, filepath.FromSlash(relPath)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(attachmentsBase, candidate)
	if err != nil {
		return "", err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("attachment path escapes the attachments directory")
	}
	return candidate, nil
}

func (a *App) attachmentsDir() string {
	return filepath.Join(filepath.Dir(a.StorePath()), "attachments")
}

func ensureDirNoSymlink(path string, perm os.FileMode) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s must be a directory", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory", path)
	}
	return nil
}

func readSecureAttachmentFile(baseDir string, path string) ([]byte, error) {
	info, err := secureAttachmentFileInfo(baseDir, path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("attachment path points to a directory")
	}
	return os.ReadFile(path)
}

func secureAttachmentFileInfo(baseDir string, path string) (os.FileInfo, error) {
	if err := rejectSymlinkPath(baseDir, path); err != nil {
		return nil, err
	}
	return os.Stat(path)
}

func rejectSymlinkPath(baseDir string, path string) error {
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}
	target, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("attachment path escapes the attachments directory")
	}

	current := base
	baseInfo, err := os.Lstat(current)
	if err != nil {
		return err
	}
	if baseInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink", current)
	}
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must not be a symlink", current)
		}
	}
	return nil
}

func (a *App) cleanupOrphanAttachments(reports []Report) error {
	dir := a.attachmentsDir()
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	keep := map[string]bool{}
	for _, report := range reports {
		for _, file := range report.PocFiles {
			path, err := a.attachmentAbsolutePath(file)
			if err == nil {
				keep[path] = true
			}
		}
	}

	dirs := []string{}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		if entry.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		if !keep[path] {
			return os.Remove(path)
		}
		return nil
	}); err != nil {
		return err
	}

	sort.Sort(sort.Reverse(sort.StringSlice(dirs)))
	for _, path := range dirs {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			if entries, readErr := os.ReadDir(path); readErr != nil || len(entries) != 0 {
				continue
			}
			return err
		}
	}
	return nil
}

func (a *App) buildBackupPayload(reports []Report) (encryptedBackupPayload, error) {
	payload := encryptedBackupPayload{
		Format:  encryptedBackupFormat,
		Reports: reports,
	}

	seen := map[string]bool{}
	for _, report := range reports {
		for _, file := range report.PocFiles {
			relPath := filepath.ToSlash(strings.TrimSpace(file.Path))
			if relPath == "" || seen[relPath] {
				continue
			}
			if err := validateBackupAttachmentPath(relPath); err != nil {
				return encryptedBackupPayload{}, err
			}
			path, err := a.attachmentAbsolutePath(file)
			if err != nil {
				return encryptedBackupPayload{}, err
			}
			content, err := readSecureAttachmentFile(a.attachmentsDir(), path)
			if err != nil {
				return encryptedBackupPayload{}, fmt.Errorf("read PoC attachment %q: %w", file.Name, err)
			}

			payload.Attachments = append(payload.Attachments, backupAttachment{
				Path: filepath.ToSlash(relPath),
				Data: base64.StdEncoding.EncodeToString(content),
			})
			seen[relPath] = true
		}
	}
	return payload, nil
}

func encryptBackupPayload(payload []byte, password string) (encryptedBackupManifest, []byte, error) {
	salt, err := randomBytes(16)
	if err != nil {
		return encryptedBackupManifest{}, nil, err
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return encryptedBackupManifest{}, nil, err
	}

	params := defaultBackupKDFParams()
	key := deriveBackupKey(password, salt, params)
	block, err := aes.NewCipher(key)
	if err != nil {
		return encryptedBackupManifest{}, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return encryptedBackupManifest{}, nil, err
	}

	manifest := encryptedBackupManifest{
		Format:    encryptedBackupFormat,
		Algorithm: encryptedBackupAlgorithm,
		KDF:       encryptedBackupKDF,
		KDFParams: params,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
	}
	ciphertext := gcm.Seal(nil, nonce, payload, []byte(encryptedBackupFormat))
	return manifest, ciphertext, nil
}

func decryptBackupPayload(manifest encryptedBackupManifest, ciphertext []byte, password string) ([]byte, error) {
	if manifest.Format != encryptedBackupFormat {
		return nil, errors.New("unsupported encrypted backup format")
	}
	if manifest.Algorithm != encryptedBackupAlgorithm {
		return nil, errors.New("unsupported encrypted backup encryption algorithm")
	}
	if manifest.KDF != encryptedBackupKDF {
		return nil, errors.New("unsupported encrypted backup key derivation")
	}
	if err := validateBackupKDFParams(manifest.KDFParams); err != nil {
		return nil, err
	}

	salt, err := base64.StdEncoding.DecodeString(manifest.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(manifest.Nonce)
	if err != nil {
		return nil, err
	}

	key := deriveBackupKey(password, salt, manifest.KDFParams)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid encrypted backup nonce")
	}

	payload, err := gcm.Open(nil, nonce, ciphertext, []byte(encryptedBackupFormat))
	if err != nil {
		return nil, errors.New("backup password is invalid or archive has been tampered with")
	}
	return payload, nil
}

func buildEncryptedBackupZip(manifest encryptedBackupManifest, ciphertext []byte) ([]byte, error) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeZipFile(archive, encryptedBackupManifestName, manifestJSON); err != nil {
		return nil, err
	}
	if err := writeZipFile(archive, encryptedBackupPayloadName, ciphertext); err != nil {
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func readEncryptedBackupZip(data []byte) (encryptedBackupManifest, []byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return encryptedBackupManifest{}, nil, err
	}

	var manifest encryptedBackupManifest
	var ciphertext []byte
	for _, file := range reader.File {
		switch file.Name {
		case encryptedBackupManifestName:
			content, err := readZipFile(file)
			if err != nil {
				return encryptedBackupManifest{}, nil, err
			}
			if err := json.Unmarshal(content, &manifest); err != nil {
				return encryptedBackupManifest{}, nil, err
			}
		case encryptedBackupPayloadName:
			content, err := readZipFile(file)
			if err != nil {
				return encryptedBackupManifest{}, nil, err
			}
			ciphertext = content
		}
	}

	if manifest.Format == "" {
		return encryptedBackupManifest{}, nil, errors.New("backup manifest is missing")
	}
	if len(ciphertext) == 0 {
		return encryptedBackupManifest{}, nil, errors.New("backup payload is missing")
	}
	return manifest, ciphertext, nil
}

func writeZipFile(archive *zip.Writer, name string, content []byte) error {
	writer, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(content)
	return err
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	content, err := io.ReadAll(io.LimitReader(reader, int64(maxEncryptedBackupBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxEncryptedBackupBytes {
		return nil, errors.New("backup zip entry is too large")
	}
	return content, nil
}

func normalizeBackupPayload(payload encryptedBackupPayload) ([]Report, map[string][]byte, error) {
	if err := validateBackupReportAttachmentPaths(payload.Reports); err != nil {
		return nil, nil, err
	}

	stored := make([]storedReport, 0, len(payload.Reports))
	for _, report := range payload.Reports {
		stored = append(stored, storedReport{Report: report})
	}
	reports, _ := migrateReports(stored)

	attachments := map[string][]byte{}
	for _, attachment := range payload.Attachments {
		relPath := filepath.ToSlash(strings.TrimSpace(attachment.Path))
		if err := validateBackupAttachmentPath(relPath); err != nil {
			return nil, nil, err
		}
		content, err := base64.StdEncoding.DecodeString(attachment.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("decode backup attachment %q: %w", relPath, err)
		}
		attachments[relPath] = content
	}

	for _, report := range reports {
		for _, file := range report.PocFiles {
			relPath := filepath.ToSlash(strings.TrimSpace(file.Path))
			if relPath == "" {
				continue
			}
			if err := validateBackupAttachmentPath(relPath); err != nil {
				return nil, nil, err
			}
			if _, ok := attachments[relPath]; !ok {
				return nil, nil, fmt.Errorf("backup is missing attachment content for %q", relPath)
			}
		}
	}
	return reports, attachments, nil
}

func validateBackupReportAttachmentPaths(reports []Report) error {
	for _, report := range reports {
		for _, file := range report.PocFiles {
			path := filepath.ToSlash(strings.TrimSpace(file.Path))
			if path == "" {
				continue
			}
			if err := validateBackupAttachmentPath(path); err != nil {
				return fmt.Errorf("backup report %q contains invalid attachment path: %w", report.Title, err)
			}
		}
	}
	return nil
}

func (a *App) restoreBackupPayload(reports []Report, attachments map[string][]byte) error {
	baseDir := filepath.Dir(a.StorePath())
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return err
	}

	stageDir, err := os.MkdirTemp(baseDir, ".vulndock-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageDir)

	for relPath, content := range attachments {
		path, err := stagedAttachmentPath(stageDir, relPath)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return err
		}
	}

	if err := validateReportsForRestore(reports); err != nil {
		return err
	}
	stagedReportsPath := filepath.Join(stageDir, "reports.json")
	if err := writeReportsToPath(stagedReportsPath, reports); err != nil {
		return err
	}

	attachmentsDir := a.attachmentsDir()
	backupAttachmentsDir := filepath.Join(stageDir, "previous-attachments")
	hadPreviousAttachments := false
	if _, err := os.Stat(attachmentsDir); err == nil {
		hadPreviousAttachments = true
		if err := os.Rename(attachmentsDir, backupAttachmentsDir); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	restorePreviousAttachments := func() {
		if !hadPreviousAttachments {
			return
		}
		if _, err := os.Stat(attachmentsDir); err == nil {
			_ = os.RemoveAll(attachmentsDir)
		}
		_ = os.Rename(backupAttachmentsDir, attachmentsDir)
	}

	stagedAttachments := filepath.Join(stageDir, "attachments")
	if _, err := os.Stat(stagedAttachments); err == nil {
		if err := os.Rename(stagedAttachments, attachmentsDir); err != nil {
			restorePreviousAttachments()
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		restorePreviousAttachments()
		return err
	}

	if err := os.Rename(stagedReportsPath, a.StorePath()); err != nil {
		restorePreviousAttachments()
		return err
	}
	if err := a.cleanupOrphanAttachments(reports); err != nil {
		return err
	}
	return nil
}

func validateReportsForRestore(reports []Report) error {
	for _, report := range reports {
		if err := validatePocFileMetadata(report.PocFiles); err != nil {
			return err
		}
	}
	return nil
}

func writeReportsToPath(path string, reports []Report) error {
	sortReports(reports)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

func validateBackupAttachmentPath(relPath string) error {
	if relPath == "" {
		return errors.New("backup attachment path is required")
	}
	if filepath.IsAbs(relPath) {
		return errors.New("backup attachment path must be relative")
	}
	if relPath == "attachments" || !strings.HasPrefix(relPath, "attachments/") {
		return errors.New("backup attachment path must be under attachments")
	}
	_, err := stagedAttachmentPath("", relPath)
	return err
}

func stagedAttachmentPath(stageDir string, relPath string) (string, error) {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	candidate, err := filepath.Abs(filepath.Join(stageDir, filepath.FromSlash(relPath)))
	if err != nil {
		return "", err
	}
	base, err := filepath.Abs(filepath.Join(stageDir, "attachments"))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return "", err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("backup attachment path escapes the attachments directory")
	}
	return candidate, nil
}

func decodeBackupArchiveData(data string) ([]byte, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, errors.New("backup archive is required")
	}
	if strings.HasPrefix(strings.ToLower(data), "data:") {
		_, payload, ok := strings.Cut(data, ",")
		if !ok {
			return nil, errors.New("backup archive data URL is missing payload")
		}
		data = payload
	}
	return base64.StdEncoding.DecodeString(data)
}

func validateBackupPassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("backup password is required")
	}
	return nil
}

func defaultBackupKDFParams() backupKDFParams {
	return backupKDFParams{
		Time:    backupKDFTime,
		Memory:  backupKDFMemory,
		Threads: backupKDFThreads,
		KeyLen:  backupKDFKeyLen,
	}
}

func validateBackupKDFParams(params backupKDFParams) error {
	if params != defaultBackupKDFParams() {
		return errors.New("unsupported encrypted backup key derivation parameters")
	}
	return nil
}

func deriveBackupKey(password string, salt []byte, params backupKDFParams) []byte {
	return argon2.IDKey([]byte(password), salt, params.Time, params.Memory, params.Threads, params.KeyLen)
}

func randomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func randomHex(size int) (string, error) {
	data, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
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
		Status:           normalizeChoice(draft.Status, "Draft", []string{"Draft", "Submitted", "Triaged", "Resolved", "Published", "Duplicate", "Rejected", "Paid"}),
		SubmittedAt:      strings.TrimSpace(draft.SubmittedAt),
		NextActionAt:     strings.TrimSpace(draft.NextActionAt),
		RewardStatus:     normalizeRewardStatus(draft.RewardStatus),
		RewardAmount:     strings.TrimSpace(draft.RewardAmount),
		RewardCurrency:   strings.ToUpper(strings.TrimSpace(draft.RewardCurrency)),
		RewardPaidAt:     strings.TrimSpace(draft.RewardPaidAt),
		RewardNote:       strings.TrimSpace(draft.RewardNote),
		Memo:             strings.TrimSpace(draft.Memo),
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
		report.NextActionAt = strings.TrimSpace(report.NextActionAt)
		report.RewardStatus = normalizeRewardStatus(report.RewardStatus)
		report.RewardAmount = strings.TrimSpace(report.RewardAmount)
		report.RewardCurrency = strings.ToUpper(strings.TrimSpace(report.RewardCurrency))
		report.RewardPaidAt = strings.TrimSpace(report.RewardPaidAt)
		report.RewardNote = strings.TrimSpace(report.RewardNote)
		report.Memo = strings.TrimSpace(report.Memo)
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
		id := normalizeAttachmentID(file.ID)
		name := strings.TrimSpace(file.Name)
		path := filepath.ToSlash(strings.TrimSpace(file.Path))
		data := strings.TrimSpace(file.Data)
		if name == "" || (data == "" && path == "") {
			continue
		}
		if data == "" && validateBackupAttachmentPath(path) != nil {
			continue
		}
		if file.Size < 0 {
			file.Size = 0
		}
		next = append(next, PocFile{
			ID:   id,
			Name: name,
			Type: strings.TrimSpace(file.Type),
			Size: file.Size,
			Path: path,
			Data: data,
		})
	}
	return next
}

func validateIncomingPocFiles(files []PocFile) error {
	for _, file := range files {
		name := strings.TrimSpace(file.Name)
		id := strings.TrimSpace(file.ID)
		path := filepath.ToSlash(strings.TrimSpace(file.Path))
		data := strings.TrimSpace(file.Data)
		if name == "" && id == "" && path == "" && data == "" {
			continue
		}
		if name == "" {
			return errors.New("PoC attachment name is required")
		}
		if id != "" && normalizeAttachmentID(id) != id {
			return fmt.Errorf("PoC attachment %q id is invalid", name)
		}
		if data == "" && path == "" {
			return fmt.Errorf("PoC attachment %q path is required", name)
		}
		if path != "" {
			if err := validateBackupAttachmentPath(path); err != nil {
				return fmt.Errorf("PoC attachment %q path is invalid: %w", name, err)
			}
		}
	}
	return nil
}

func validatePocFileMetadata(files []PocFile) error {
	for _, file := range files {
		if strings.TrimSpace(file.Data) != "" {
			continue
		}
		name := strings.TrimSpace(file.Name)
		if name == "" {
			return errors.New("PoC attachment name is required")
		}
		path := filepath.ToSlash(strings.TrimSpace(file.Path))
		if path == "" {
			return fmt.Errorf("PoC attachment %q path is required", name)
		}
		if err := validateBackupAttachmentPath(path); err != nil {
			return fmt.Errorf("PoC attachment %q path is invalid: %w", name, err)
		}
		id := strings.TrimSpace(file.ID)
		if id != "" && normalizeAttachmentID(id) != id {
			return fmt.Errorf("PoC attachment %q id is invalid", name)
		}
	}
	return nil
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

func normalizeRewardStatus(value string) string {
	return normalizeChoice(value, "Unknown", []string{"Unknown", "Pending", "Paid", "None"})
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

func newAttachmentID() string {
	suffix, err := randomHex(4)
	if err == nil {
		return "attachment_" + time.Now().UTC().Format("20060102150405.000000000") + "_" + suffix
	}
	return "attachment_" + time.Now().UTC().Format("20060102150405.000000000")
}

func normalizeAttachmentID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || id == "." || id == ".." {
		return ""
	}
	for _, value := range id {
		switch {
		case value >= 'a' && value <= 'z':
		case value >= 'A' && value <= 'Z':
		case value >= '0' && value <= '9':
		case value == '_' || value == '-' || value == '.':
		default:
			return ""
		}
	}
	return id
}

func sanitizeAttachmentName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "attachment"
	}

	var builder strings.Builder
	for _, value := range name {
		switch {
		case value < 32 || value == 127:
			builder.WriteRune('_')
		case value == '/' || value == '\\':
			builder.WriteRune('_')
		default:
			builder.WriteRune(value)
		}
	}

	name = strings.TrimSpace(builder.String())
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	return name
}

func defaultStorePath() string {
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		configDir = "."
	}
	return filepath.Join(configDir, "VulnDock", "reports.json")
}
