# Security Policy

VPSAgent is designed around a **Zero-Root Safety Wall** so AI agents can manage isolated apps without root SSH access or `/var/run/docker.sock`. We take security vulnerabilities seriously.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report security issues privately using **GitHub Private Vulnerability Reporting** (under the repository's **Security → Advisories** tab) or contact the maintainers directly.

When reporting, please include:
- A clear description of the issue and potential impact
- Steps to reproduce or a minimal proof of concept
- Any affected versions or configuration details

## Scope Highlights

We especially appreciate reports covering:
- Container escape or Docker socket / Runtime Bridge allowlist bypasses
- Authentication, session, or `vpsmcp_` Visitor Pass scope bypasses
- Secret leakage in logs, audit events, API responses, or MCP tool outputs
- SSRF, command injection, or path traversal in GitHub deploy / build flows
