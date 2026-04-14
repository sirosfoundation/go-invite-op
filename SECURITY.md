# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to **security@siros.org** with:

- A description of the vulnerability
- Steps to reproduce (if applicable)
- The potential impact
- Any suggested fix (optional)

We will acknowledge receipt within **2 business days** and aim to provide an initial assessment within **5 business days**.

## Security Measures

This repository enforces the following security controls:

- **Branch protection** on `main`: required PR reviews, status checks (test/lint/build), signed commits, linear history
- **Secret scanning** with push protection enabled
- **Dependabot** security updates enabled
- **CodeQL** static analysis on push, PR, and weekly schedule
- **govulncheck** dependency vulnerability scanning
- **SBOM** generation via shared workflow

## Disclosure Policy

We follow coordinated disclosure. We will work with reporters to understand and address vulnerabilities before any public disclosure, typically within 90 days.
