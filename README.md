# VulnDock

VulnDock is a desktop app for organizing vulnerability report metadata, PoC attachments, and CVSS vectors in one local workspace. It is built with Wails, Go, Svelte, and TypeScript.

## Features

- Create, edit, search, and delete vulnerability reports.
- Track program, target asset, status, submission date, tags, and report URL.
- Store PoC files as report attachments.
- Calculate CVSS 3.1 and CVSS 4.0 scores automatically from vector strings.
- Filter reports by status and CVSS rating.
- Persist data locally as JSON.

## Data Storage

Reports are stored locally at:

```text
~/.config/VulnDock/reports.json
```

PoC attachments are embedded in that JSON file as data URLs. Avoid attaching secrets, production credentials, customer data, or any material you should not keep in a local application data file.

## Requirements

- Go 1.24+
- Node.js 22+
- npm
- Wails v2
- Linux WebKit dependencies required by Wails when running or building on Linux

## Setup

Install frontend dependencies:

```sh
make install
```

## Install Desktop App

Install the latest Linux or macOS release:

```sh
curl -fsSL https://raw.githubusercontent.com/Saku0512/VulnDock/main/scripts/install.sh | bash
```

Install a specific release:

```sh
curl -fsSL https://raw.githubusercontent.com/Saku0512/VulnDock/main/scripts/install.sh | VULNDOCK_VERSION=v0.1.0 bash
```

On Linux this installs `VulnDock` to `~/.local/bin`, adds a desktop entry under `~/.local/share/applications`, and installs the app icon under `~/.local/share/icons`.

## Development

Run the Wails app in development mode:

```sh
make dev
```

Run only the frontend development server:

```sh
make frontend-dev
```

## Testing

Run backend and frontend unit tests:

```sh
make test
```

Run all checks used during development:

```sh
make check
```

Individual commands:

```sh
go test ./...
npm test --prefix frontend
npm run check --prefix frontend
npm run build --prefix frontend
```

## Building

Build a redistributable Wails package:

```sh
make build
```

Package the Linux desktop app in the same format used by GitHub Releases:

```sh
make package-linux
```

Build only the frontend assets:

```sh
make frontend-build
```

## Releasing

Create and push a version tag to build desktop app artifacts and publish them to a GitHub Release:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow uploads Linux, macOS, and Windows desktop app archives when the platform build succeeds. The `scripts/install.sh` installer downloads the matching Linux or macOS asset from the latest release by default.

## Project Layout

- `app.go` - Go application model, persistence, and Wails bindings.
- `main.go` - Wails application bootstrap and embedded frontend assets.
- `frontend/src/App.svelte` - main UI.
- `frontend/src/cvss.ts` - CVSS 3.1 and CVSS 4.0 scoring logic.
- `frontend/test/` - frontend unit tests.
- `.github/workflows/ci.yml` - GitHub Actions CI.
- `.github/workflows/release.yml` - GitHub Actions release builds.
- `scripts/install.sh` - installer for `curl | bash` installs from GitHub Releases.

## CI

GitHub Actions runs on pushes to `main` and pull requests. The workflow checks Go formatting, `go mod tidy`, Go tests, frontend type checks, frontend unit tests, and frontend build.

## License

See [LICENSE](LICENSE).
