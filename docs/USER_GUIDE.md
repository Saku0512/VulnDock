# VulnDock User Guide

VulnDock is a local desktop application for organizing vulnerability report metadata, PoC attachments, and CVSS vectors. It is intended for tracking reports during vulnerability research or coordinated disclosure work.

## Main Workflow

1. Create a report.
2. Fill in the affected program, asset, report URL, status, submission dates, CVSS data, tags, notes, and reward tracking fields.
3. Attach minimal PoC files when needed.
4. Save the report to local storage.
5. Search, filter, edit, or delete reports as your work progresses.

## Report Fields

VulnDock stores these report fields:

- Title: Human-readable report title. Blank titles are saved as `Untitled report`.
- Program: The program, vendor, or project that receives the report.
- Asset: The affected target, URL, package, host, or component.
- CVSS Version: `3.1` or `4.0`.
- CVSS Score: Numeric score from `0.0` to `10.0`.
- CVSS Vector: CVSS vector string.
- Status: One of `Draft`, `Submitted`, `Triaged`, `Resolved`, `Published`, `Duplicate`, `Rejected`, or `Paid`.
- Submitted At: Date or datetime when the report was submitted.
- Next Action At: Date or datetime for follow-up.
- Reward Status: One of `Unknown`, `Pending`, `Paid`, or `None`.
- Reward Amount: Reward amount as text.
- Reward Currency: Currency code or label.
- Reward Paid At: Date or datetime when a reward was paid.
- Reward Note: Notes related to reward handling.
- Memo: Private notes for the report.
- Report URL: Link to the external report, advisory, issue, or disclosure page.
- Conversation Logs: Communication entries between you and the maintainer.
- Tags: Searchable labels. Leading `#` characters are removed.
- PoC Files: Attached proof-of-concept files stored under the local attachments directory.

## External Interface

VulnDock exposes a desktop graphical interface through Wails. Users interact with the application through windows, forms, buttons, filters, and local file selections.

The application accepts these external inputs:

- Text entered into report fields.
- CVSS vectors entered by the user.
- Local files selected as PoC attachments.
- Encrypted backup ZIP files selected for restore.
- Existing local report data loaded from the VulnDock data file.

The application produces these outputs and side effects:

- A local JSON report store.
- PoC attachment files stored separately under the local attachments directory.
- Password-protected encrypted ZIP backup downloads.
- Desktop app windows and UI state.
- Release artifacts produced by the GitHub Actions release workflow.

VulnDock does not require a network service for normal report editing. External report URLs are stored as text unless the user opens them outside the application.

## Local Data Storage

Reports are stored locally at:

```text
~/.config/VulnDock/reports.json
```

PoC attachment metadata is stored in that JSON file. Attachment contents are stored separately under:

```text
~/.config/VulnDock/attachments/
```

Older data URL attachments are migrated into the attachments directory when reports are loaded. Treat both the JSON file and attachments directory as sensitive. Do not store production credentials, private customer data, private keys, tokens, or exploit material that you are not allowed to keep locally.

## Encrypted Backups

The encrypted ZIP action creates a ZIP container with an AES-256-GCM encrypted payload. The payload includes report data and attachment contents. The password is used with Argon2id to derive the encryption key.

Restoring an encrypted ZIP replaces the current local reports and attachments only after the password decrypts and authenticates the payload successfully.

## CVSS Handling

VulnDock supports CVSS 3.1 and CVSS 4.0 base score calculation from vector strings. Invalid or incomplete vectors may leave the calculated score blank. Manually entered CVSS scores are normalized to the range `0.0` through `10.0`.

## Installing Releases

Release downloads are published on GitHub Releases. See [README.md](../README.md#install-desktop-app) for Linux, macOS, Windows, Homebrew, WinGet, and Docker installation options.

Release assets include SHA-256 checksums and keyless Sigstore signature bundles. See [README.md](../README.md#releasing) for a verification example.

## Building From Source

Install the requirements from [README.md](../README.md#requirements), then run:

```sh
make install
make build
```

For development:

```sh
make dev
```

## Testing

Run backend and frontend checks with:

```sh
make check
```

Focused checks are:

```sh
go test ./...
npm test --prefix frontend
npm run check --prefix frontend
npm run build --prefix frontend
```

## Feedback and Security Reports

Use GitHub Issues for public bugs and feature requests. Use [SECURITY.md](../SECURITY.md) for suspected security vulnerabilities.
