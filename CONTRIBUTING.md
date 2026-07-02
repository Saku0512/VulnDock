# Contributing to VulnDock

Thank you for considering a contribution to VulnDock. Contributions are handled through GitHub issues and pull requests.

## Reporting Bugs and Requesting Enhancements

Use GitHub Issues for public bug reports, feature requests, documentation improvements, and build problems. Include enough detail for maintainers to reproduce or evaluate the report:

- What you expected to happen.
- What actually happened.
- Steps to reproduce the behavior.
- Operating system and desktop environment, if relevant.
- Relevant logs, screenshots, or sample input that does not contain sensitive data.

Do not report suspected security vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) instead.

## Contribution Process

1. Open an issue or comment on an existing issue when the change is user-visible, security-sensitive, or likely to need discussion.
2. Fork the repository and create a focused branch.
3. Make the smallest practical change that solves the problem.
4. Add or update tests and documentation when behavior changes.
5. Run the project checks locally.
6. Open a pull request that explains the change, the reason for it, and the checks you ran.

Pull requests are reviewed on GitHub. A maintainer may ask for changes before merging.

## Development Setup

Install the required tools listed in [README.md](README.md#requirements), then install frontend dependencies:

```sh
make install
```

Run the desktop app in development mode:

```sh
make dev
```

## Required Checks

Before opening a pull request, run:

```sh
make check
```

For focused checks, run:

```sh
go test ./...
npm test --prefix frontend
npm run check --prefix frontend
npm run build --prefix frontend
```

If you change Go module requirements, run:

```sh
go mod tidy
```

## Contribution Requirements

Acceptable contributions should meet these requirements:

- Go code must be formatted with `gofmt`.
- TypeScript and Svelte code must pass `npm run check --prefix frontend`.
- Tests must pass for the affected backend or frontend area.
- User-visible behavior changes should update README or documentation.
- New dependencies should be necessary, maintained, and compatible with the project license.
- Do not commit generated build outputs, local report data, credentials, tokens, or private vulnerability details.
- Keep pull requests focused. Separate unrelated changes into separate pull requests.

## Security-Sensitive Changes

For changes that affect report storage, PoC attachment handling, release signing, dependency management, or GitHub Actions permissions, include a short security rationale in the pull request description.

## License

By contributing, you agree that your contribution will be released under the project's MIT license.
