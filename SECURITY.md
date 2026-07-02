# Security Policy

## Supported Versions

Security fixes are handled on the `main` branch. If release artifacts or versioned builds are introduced later, this policy should be updated with a supported-version table.

## Reporting a Vulnerability

Please do not open a public issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting or Security Advisory flow when available. If that is not available, contact the maintainer through a private channel before sharing details publicly.

Report privately via:
https://github.com/Saku0512/VulnDock/security/advisories/new

When reporting, include:

- A clear description of the issue.
- Steps to reproduce.
- Impact and affected components.
- Relevant CVSS vector, if known.
- Minimal PoC material needed to verify the issue.

Avoid sending real credentials, customer data, private keys, production tokens, or unnecessary sensitive data.

## Handling Expectations

The maintainer will try to:

- Acknowledge the report after it is received.
- Confirm whether the issue is reproducible.
- Coordinate a fix before public disclosure when appropriate.
- Credit reporters when requested and practical.

This project is maintained on a best-effort basis, so response times may vary.

## Security Notes for Users

VulnDock stores report data locally in:

```text
~/.config/VulnDock/reports.json
```

PoC attachment metadata is stored in `reports.json`. Attachment contents are stored separately under:

```text
~/.config/VulnDock/attachments/
```

Treat both locations as sensitive. Do not store secrets, production credentials, private customer data, or exploit material that you are not allowed to keep locally.

Encrypted backup ZIP files protect report data and attachment contents with AES-256-GCM. The backup password is required to authenticate and restore the payload; lost passwords cannot be recovered by VulnDock.

If you share bug reports, screenshots, exported data, or repository issues, review them for sensitive vulnerability details first.
