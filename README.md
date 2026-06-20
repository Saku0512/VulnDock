# VulnDock

VulnDock is a desktop app for organizing vulnerability reports, PoC attachments, CVSS vectors, and report notes in one local workspace. It is built with Wails, Go, Svelte, and TypeScript.

## Features

- Create, edit, search, and delete vulnerability reports.
- Track program, target asset, status, submission date, tags, and report body.
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

- Go 1.23+
- Node.js 20+
- npm
- Wails v2
- Linux WebKit dependencies required by Wails when running or building on Linux

## Setup

Install frontend dependencies:

```sh
make install
```

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

Build only the frontend assets:

```sh
make frontend-build
```

## Project Layout

- `app.go` - Go application model, persistence, and Wails bindings.
- `main.go` - Wails application bootstrap and embedded frontend assets.
- `frontend/src/App.svelte` - main UI.
- `frontend/src/cvss.ts` - CVSS 3.1 and CVSS 4.0 scoring logic.
- `frontend/test/` - frontend unit tests.
- `.github/workflows/ci.yml` - GitHub Actions CI.

## CI

GitHub Actions runs on pushes to `main` and pull requests. The workflow checks Go formatting, `go mod tidy`, Go tests, frontend type checks, frontend unit tests, and frontend build.

## License

See [LICENSE](LICENSE).
