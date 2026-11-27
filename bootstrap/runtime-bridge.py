#!/usr/bin/env python3
"""
VPSAgent v2 Host Runtime Bridge (`vpsagent-runtime`).

Runs on the Ubuntu host as a privileged systemd daemon listening exclusively on a
permission-scoped Unix domain socket (/var/lib/vpsagent/run/runtime.sock) mounted into
the core control container — never exposing /var/run/docker.sock to any container.

Exposes a strict, schema-validated allowlist of operations:
  - GET  /health               (unauthenticated liveness check)
  - GET  /v1/host/stats        (host CPU, RAM, uptime, and disk metrics)
  - POST /v1/apps/lifecycle    (start | stop | restart | status)
  - POST /v1/apps/build-git    (DNS-checked HTTPS Git clone + Dockerfile build with timeout)
  - POST /v1/apps/logs         (tail bounded & secret-redacted logs)
  - POST /v1/apps/route-caddy  (attach network, write scoped .caddy, validate & reload)
  - POST /v1/apps/remove       (compose down, remove route, optional folder cleanup)
  - POST /v1/apps/statuses     (batch live Compose status lookup with overall deadline)
  - POST /v1/apps/inspect      (live container, Locked Apartment security audit, HTTP probe)
  - POST /v1/apps/readiness    (bounded startup readiness retries accepting 4xx API roots)
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait as wait_futures
from contextlib import contextmanager
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import platform
try:
    import pwd
except ImportError:  # pragma: no cover - non-POSIX
    pwd = None  # type: ignore[assignment]
import re
import select
import shutil
import signal
import socket
import socketserver
import sqlite3
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable, Iterator
from urllib.parse import urljoin, urlparse, urlsplit

MAX_BODY_BYTES = 512 * 1024
MAX_COMMAND_OUTPUT_BYTES = 48 * 1024
MAX_HOST_CMD_TIMEOUT_S = 180
DEFAULT_HOST_CMD_TIMEOUT_S = 30
MAX_READ_FILE_BYTES = 128 * 1024
MAX_WRITE_FILE_BYTES = 256 * 1024
MAX_BACKUP_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_BACKUP_STAGING_BYTES = 200 * 1024 * 1024
BACKUP_SECRET_BASENAME_RE = re.compile(
    r"^(?:\.env(?:\..*)?|runtime\.token|.*\.(?:pem|key|p12|pfx))$", re.IGNORECASE
)

SERVICE_UNIT_PATTERN = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")
ALLOWED_SERVICE_ACTIONS = frozenset(
    {"start", "stop", "restart", "reload", "enable", "disable", "status"}
)
PROTECTED_SERVICES = frozenset({"vpsagent-runtime", "vpsagent-runtime.service"})
PROTECTED_DELETE_PATHS = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/tmp",
        "/usr",
        "/var",
        "/var/lib",
        "/var/lib/vpsagent",
    }
)
SECRET_FILE_BASENAMES = frozenset(
    {
        ".env",
        "shadow",
        "gshadow",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "runtime.token",
        "registry.db",
        "registry.db-wal",
        "registry.db-shm",
        "registry.sqlite",
        "registry.sqlite-wal",
        "registry.sqlite-shm",
    }
)
MAX_READ_SCAN_BYTES = 256 * 1024
MAX_COMPOSE_BYTES = 512 * 1024
MAX_ENV_BYTES = 64 * 1024
MAX_LOG_LINE_CHARS = 2000
MAX_LOGS_RESPONSE_BYTES = 64 * 1024
MAX_TAIL_LINES = 500
MAX_STATUS_SLUGS = 100
DEFAULT_STATUS_DEADLINE_S = 25.0
MAX_PROBE_BODY_BYTES = 4096
MAX_PROBE_CONFIG_BYTES = 4 * 1024
DEFAULT_PROBE_TIMEOUT_S = 3.0
DEFAULT_HEALTH_INTERVAL_S = 15.0
DEFAULT_HEALTH_RETRIES = 3
DEFAULT_READINESS_TIMEOUT_S = 15.0
DEFAULT_READINESS_POLL_MS = 500
DEFAULT_BUILD_TIMEOUT_S = 300
MIN_BUILD_TIMEOUT_S = 10
MAX_BUILD_TIMEOUT_S = 600
MAX_BUILD_LOG_LINES = 80

DEFAULT_RELEASE_REPO = "VPSAgent/vpsagent"
DEFAULT_GITHUB_API_BASE = "https://api.github.com"
RELEASE_REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
RELEASE_TAG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
SEMVER_PATTERN = re.compile(
    r"^[vV]?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
GITHUB_REMOTE_URL_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
ALLOWED_RELEASE_DOWNLOAD_HOSTS = frozenset(
    {
        "api.github.com",
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "github-releases.githubusercontent.com",
    }
)
MAX_RELEASE_JSON_BYTES = 1 * 1024 * 1024
MAX_CHECKSUM_FILE_BYTES = 256 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_RELEASE_EXTRACT_BYTES = 256 * 1024 * 1024
MAX_RELEASE_EXTRACT_MEMBERS = 10_000
MAX_RELEASE_NOTES_CHARS = 1500
ACTIVE_SOURCE_FILENAME = "active-source.json"
MAX_ACTIVE_SOURCE_BYTES = 16 * 1024

PROBE_PATH_PATTERN = re.compile(r"^/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]{0,127}$")
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$")
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}$"
)
CONTAINER_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
SERVICE_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
IMAGE_REF_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{1,200}$")
ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
GIT_BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")
GIT_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{8,512}$")
DOCKERFILE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
MEM_LIMIT_PATTERN = re.compile(r"^(\d+)([kmgKMG]?)$")
NUMERIC_USER_PATTERN = re.compile(r"^(\d+)(?::(\d+))?$")
RELATIVE_MOUNT_PATTERN = re.compile(
    r"^\./(?:data|workspace)(?:/[A-Za-z0-9._-]+)*:/[A-Za-z0-9._/-]+(?::(?:ro|rw))?$"
)
INTERPOLATION_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

RESERVED_SLUGS = frozenset(
    {
        "core",
        "vpsagent",
        "vps-os",
        "caddy",
        "api",
        "dashboard",
        "agent",
        "system",
        "root",
        "admin",
    }
)

BLOCKED_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
        "100.100.100.200",
    }
)

ALLOWED_LIFECYCLE_ACTIONS = frozenset({"start", "stop", "restart", "status"})
ALLOWED_TOP_LEVEL_COMPOSE_KEYS = frozenset({"services", "networks"})
ALLOWED_SERVICE_KEYS = frozenset(
    {
        "image",
        "container_name",
        "restart",
        "working_dir",
        "command",
        "user",
        "init",
        "env_file",
        "environment",
        "volumes",
        "cpus",
        "mem_limit",
        "cap_drop",
        "security_opt",
        "networks",
        "healthcheck",
        "depends_on",
    }
)
ALLOWED_HEALTHCHECK_KEYS = frozenset(
    {"test", "interval", "timeout", "retries", "start_period"}
)
ALLOWED_DEPENDS_ON_CONDITIONS = frozenset(
    {"service_started", "service_healthy", "service_completed_successfully"}
)
ALLOWED_ENV_INTERPOLATION_VARS = frozenset(
    {
        "APP_SLUG",
        "APP_PORT",
        "POSTGRES_DB",
        "POSTGRES_USER",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
    }
)
ALLOWED_COMMAND_INTERPOLATION_VARS = frozenset(
    {"APP_SLUG", "APP_PORT", "REDIS_PASSWORD"}
)

DISALLOWED_ENV_PREFIXES = ("VPSAGENT_", "VPS_OS_", "DOCKER_", "LD_")
DISALLOWED_ENV_EXACT = frozenset(
    {"PATH", "HOME", "HOSTALIASES", "IFS", "ENV", "BASH_ENV"}
)

PEM_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
URL_CREDS_RE = re.compile(r"\b(https?://)([^:@\s/]+):([^@\s/]+)@", re.IGNORECASE)
AUTH_HEADER_RE = re.compile(
    r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}", re.IGNORECASE
)
JSON_SECRET_RE = re.compile(
    r'"([A-Za-z0-9_]*(?:key|token|secret|password|passwd|pass|passphrase|credential|auth)[A-Za-z0-9_]*)"\s*:\s*"([^"]*)"',
    re.IGNORECASE,
)
ENV_OR_YAML_SECRET_RE = re.compile(
    r'\b([A-Za-z0-9_]*(?:key|token|secret|password|passwd|pass|passphrase|credential|auth)[A-Za-z0-9_]*)\s*([:=])\s*(?!\[REDACTED\]@)("[^"]*"|\'[^\']*\'|[^\s,;]+)',
    re.IGNORECASE,
)
KNOWN_TOKEN_RE = re.compile(
    r"\b(sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|vpsmcp_[A-Za-z0-9_-]{16,}|tskey-[a-z]+-[A-Za-z0-9_-]{8,}|\d{6,12}:AA[A-Za-z0-9_-]{25,})\b"
)
GIT_AUTH_ERROR_RE = re.compile(
    r"(?:authentication failed|could not read username|terminal prompts disabled|repository not found|returned error:\s*40[134]|access denied|invalid username or (?:password|token))",
    re.IGNORECASE,
)
TAILSCALE_AUTHKEY_PATTERN = re.compile(r"^tskey-auth-[A-Za-z0-9_-]{8,256}$")
TAILSCALE_LOGIN_URL_RE = re.compile(
    r"https://login\.tailscale\.com/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+"
)
DEFAULT_TAILSCALE_TARGET_URL = "http://127.0.0.1:3001"


def _validate_tailscale_target_url(raw: str) -> tuple[str, str, int]:
    """
    Validates that the Tailscale Serve upstream target is strictly an HTTP loopback
    host:port (e.g. http://127.0.0.1:3001) with no credentials, path, query, or fragment.
    """
    cleaned = raw.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme != "http":
        raise ValueError("Tailscale target URL must use http:// on loopback.")
    if parsed.username or parsed.password:
        raise ValueError("Tailscale target URL cannot contain credentials.")
    host = (parsed.hostname or "").lower()
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(
            "Tailscale target URL must point to 127.0.0.1 or localhost."
        )
    if parsed.path not in ("", "/") or parsed.params or parsed.query or parsed.fragment:
        raise ValueError(
            "Tailscale target URL cannot include a path, query, or fragment."
        )
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid Tailscale target port.") from exc
    if port is None or port < 1 or port > 65535:
        raise ValueError(
            "Tailscale target URL must specify a port between 1 and 65535."
        )
    return f"http://{host}:{port}", host, port


def _default_loopback_port_checker(
    host: str, port: int, timeout_s: float = 1.0
) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def _normalize_tailscale_url(raw: str | None) -> str | None:
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip().rstrip(".,);]")
    if not cleaned:
        return None
    parsed = urlparse(cleaned)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        return None
    if host != "tailscale.com" and not host.endswith(".tailscale.com"):
        return None
    return cleaned


def _sanitize_proxy_target_for_display(raw: str) -> str:
    """
    Strips URL userinfo, query strings, and fragments from a Tailscale Serve proxy
    target before showing or persisting it in conflict messages.
    """
    cleaned = raw.strip()
    if not cleaned:
        return ""
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        parts = None
    if parts is not None and parts.scheme and parts.netloc:
        has_userinfo = (
            parts.username is not None
            or parts.password is not None
            or "@" in parts.netloc
        )
        try:
            hostname = parts.hostname
            port = parts.port
        except ValueError:
            hostname = None
            port = None
        if hostname:
            host_part = f"[{hostname}]" if ":" in hostname else hostname
            host_port = f"{host_part}:{port}" if port is not None else host_part
        else:
            host_port = parts.netloc.rsplit("@", 1)[-1]
        prefix = "[REDACTED]@" if has_userinfo else ""
        return redact_secrets(f"{parts.scheme}://{prefix}{host_port}{parts.path}")
    fallback = re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@",
        r"\1[REDACTED]@",
        cleaned,
    )
    fallback = re.split(r"[?#]", fallback, maxsplit=1)[0]
    return redact_secrets(fallback)

DnsResolver = Callable[[str, int], list[str]]
TlsChecker = Callable[[str, float], tuple[bool, str, str | None]]


def default_tls_checker(
    domain: str, timeout_s: float = 4.0
) -> tuple[bool, str, str | None]:
    """
    Verifies a live TLS certificate handshake against `(domain, 443)` with full
    hostname verification. Returns `(https_active, tls_status, tls_error)`.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout_s) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain):
                return True, "active", None
    except ssl.SSLError as exc:
        return False, "failed", redact_secrets(f"TLS handshake failed: {exc}")
    except OSError as exc:
        return False, "pending", redact_secrets(f"HTTPS not reachable yet: {exc}")


class BridgeRequestError(Exception):
    def __init__(
        self,
        status_code: int,
        message: str,
        build_log_tail: list[str] | None = None,
    ) -> None:
        super().__init__(redact_secrets(message))
        self.status_code = status_code
        self.build_log_tail = [
            redact_secrets(line)[:MAX_LOG_LINE_CHARS]
            for line in (build_log_tail or [])
        ][-MAX_BUILD_LOG_LINES:]


def redact_secrets(text: str) -> str:
    if not text:
        return ""
    result = PEM_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    result = URL_CREDS_RE.sub(r"\1\2:[REDACTED]@", result)
    result = AUTH_HEADER_RE.sub(r"\1 [REDACTED]", result)
    result = JSON_SECRET_RE.sub(r'"\1":"[REDACTED]"', result)
    result = ENV_OR_YAML_SECRET_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{' ' if m.group(2) == ':' else ''}[REDACTED]",
        result,
    )
    return KNOWN_TOKEN_RE.sub("[REDACTED]", result)


def _scrub_secret_values(text: str, secret_values: list[str] | None = None) -> str:
    scrubbed = redact_secrets(text)
    if secret_values:
        for val in secret_values:
            if val:
                scrubbed = scrubbed.replace(val, "[REDACTED]")
    return scrubbed


def validate_git_token(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Invalid GitHub access token format.")
    trimmed = raw.strip()
    if not trimmed:
        return None
    if not GIT_TOKEN_PATTERN.match(trimmed):
        raise BridgeRequestError(400, "Invalid GitHub access token format.")
    return trimmed


def assert_github_host_for_token(repo_host: str, repo_port: int) -> None:
    if repo_host != "github.com" or repo_port != 443:
        raise BridgeRequestError(
            400,
            "GitHub access tokens can only be used with https://github.com repositories.",
        )


def validate_slug(raw: Any) -> str:
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'slug' must be a string.")
    if not SLUG_PATTERN.match(raw):
        raise BridgeRequestError(
            400,
            f'Invalid app slug "{raw}": must be 2-48 lowercase alphanumeric characters or hyphens.',
        )
    if raw in RESERVED_SLUGS:
        raise BridgeRequestError(400, f'Reserved app slug "{raw}" cannot be used.')
    return raw


def validate_domain(raw: Any) -> str:
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'domain' must be a string or null.")
    normalized = raw.strip().lower()
    if not DOMAIN_PATTERN.match(normalized):
        raise BridgeRequestError(400, f'Invalid domain name "{raw}".')
    try:
        ipaddress.ip_address(normalized)
        raise BridgeRequestError(400, "IP addresses cannot be used as domain names.")
    except ValueError:
        pass
    return normalized


def validate_email(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'acmeEmail' must be a string or null.")
    trimmed = raw.strip()
    if not trimmed:
        return None
    if not EMAIL_PATTERN.match(trimmed):
        raise BridgeRequestError(400, f'Invalid email address "{raw}".')
    return trimmed


def validate_port(raw: Any) -> int:
    if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1 or raw > 65535:
        raise BridgeRequestError(
            400, "Field 'internalPort' must be an integer between 1 and 65535."
        )
    return raw


def validate_tail(raw: Any) -> int:
    if raw is None:
        return 100
    if (
        not isinstance(raw, int)
        or isinstance(raw, bool)
        or raw < 1
        or raw > MAX_TAIL_LINES
    ):
        raise BridgeRequestError(
            400, f"Field 'tail' must be an integer between 1 and {MAX_TAIL_LINES}."
        )
    return raw


def validate_probe_path(raw: Any) -> str:
    if raw is None:
        return "/"
    if not isinstance(raw, str):
        raise BridgeRequestError(
            400, "Field 'probePath' must be a valid HTTP path starting with '/'."
        )
    if (
        not raw
        or any(ch.isspace() for ch in raw)
        or not PROBE_PATH_PATTERN.match(raw)
    ):
        raise BridgeRequestError(
            400, "Field 'probePath' must be a valid HTTP path starting with '/'."
        )
    return raw


def validate_git_branch(raw: Any) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'gitBranch' must be a string or null.")
    trimmed = raw.strip()
    if not trimmed:
        return None
    if (
        not GIT_BRANCH_PATTERN.match(trimmed)
        or trimmed.startswith("-")
        or trimmed.startswith("/")
        or trimmed.endswith("/")
        or trimmed.endswith(".lock")
        or ".." in trimmed
        or "//" in trimmed
        or "@{" in trimmed
    ):
        raise BridgeRequestError(400, f'Invalid Git branch name "{raw}".')
    return trimmed


ENV_SECRET_KEY_HINT_RE = re.compile(
    r"(?:key|token|secret|password|passwd|pass|passphrase|credential|auth|private|database_url|redis_url)",
    re.IGNORECASE,
)
EXPOSE_PORT_RE = re.compile(r"^\s*EXPOSE\s+(\d{1,5})(?:/tcp)?(?:\s|$)", re.IGNORECASE | re.MULTILINE)
MAX_INSPECT_FILE_BYTES = 256 * 1024
MAX_ENV_EXAMPLE_BYTES = 32 * 1024


def _derive_slug_and_name_from_repo_url(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url)
    segments = [seg for seg in parsed.path.split("/") if seg]
    raw_repo = segments[-1] if segments else "github-app"
    if raw_repo.lower().endswith(".git"):
        raw_repo = raw_repo[:-4]
    cleaned = re.sub(r"[^a-z0-9]+", "-", raw_repo.lower()).strip("-")
    if len(cleaned) < 2:
        cleaned = f"{cleaned or 'my'}-app"
    slug = cleaned[:48].rstrip("-")
    if len(slug) < 2 or not SLUG_PATTERN.match(slug) or slug in RESERVED_SLUGS:
        base = re.sub(r"[^a-z0-9-]", "", slug)[:40].strip("-") or "repo"
        slug = f"{base}-app"
        if slug in RESERVED_SLUGS:
            slug = "github-app"
    words = [w for w in re.split(r"[-_.\s]+", raw_repo) if w]
    display_name = " ".join(w[:1].upper() + w[1:] for w in words)[:100] or "GitHub App"
    return slug, display_name


def _is_regular_file_inside(repo_root: str, rel_path: str) -> str | None:
    real_root = os.path.realpath(repo_root)
    current = real_root
    for part in rel_path.split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return None
    if not os.path.isfile(current):
        return None
    real_target = os.path.realpath(current)
    if not real_target.startswith(real_root + os.sep):
        return None
    return real_target


def _safe_read_repo_text(repo_root: str, rel_path: str, max_bytes: int) -> str | None:
    target = _is_regular_file_inside(repo_root, rel_path)
    if target is None:
        return None
    try:
        return _read_regular_file_nofollow(target, max_bytes, rel_path)
    except BridgeRequestError:
        return None


def _extract_env_example_keys(repo_root: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    keys: list[dict[str, Any]] = []
    for candidate in (".env.example", ".env.sample", ".env.template", "env.example"):
        content = _safe_read_repo_text(repo_root, candidate, MAX_ENV_EXAMPLE_BYTES)
        if not content:
            continue
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            key = line.split("=", 1)[0].strip()
            if not key or not ENV_KEY_PATTERN.match(key):
                continue
            if key in DISALLOWED_ENV_EXACT or any(
                key.startswith(prefix) for prefix in DISALLOWED_ENV_PREFIXES
            ):
                continue
            if key in seen:
                continue
            seen.add(key)
            keys.append(
                {
                    "key": key,
                    "isSecret": bool(ENV_SECRET_KEY_HINT_RE.search(key)),
                }
            )
            if len(keys) >= 60:
                return keys
    return keys


def _detect_dockerfile_exposed_port(dockerfile_text: str) -> int:
    match = EXPOSE_PORT_RE.search(dockerfile_text)
    if match:
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return port
    return 8080


def _build_node_install_lines(pkg_manager: str) -> list[str]:
    if pkg_manager == "pnpm":
        return [
            "RUN corepack enable",
            "COPY package.json pnpm-lock.yaml* ./",
            "RUN pnpm install --frozen-lockfile || pnpm install",
        ]
    if pkg_manager == "yarn":
        return [
            "RUN corepack enable",
            "COPY package.json yarn.lock* ./",
            "RUN yarn install --frozen-lockfile || yarn install",
        ]
    return [
        "COPY package.json package-lock.json* ./",
        "RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi",
    ]


def _inspect_cloned_repo(
    clone_dir: str,
    repo_url: str,
    resolved_branch: str | None,
    commit_sha: str | None,
    dockerfile_rel: str,
) -> dict[str, Any]:
    """
    Safely inspects a cloned public repository (strictly no symlink escapes, bounded reads,
    never extracts .env.example values) to detect its runtime, port, companion databases,
    required env key names, and optional auto-generated Locked-Apartment Dockerfile.
    """
    suggested_slug, suggested_name = _derive_slug_and_name_from_repo_url(repo_url)
    env_example_keys = _extract_env_example_keys(clone_dir)
    env_key_names = {item["key"] for item in env_example_keys}
    notes: list[str] = []

    check_df_rel = "Dockerfile" if dockerfile_rel == "auto" else dockerfile_rel
    # Verify explicit dockerfile path does not escape via symlinks
    real_clone_dir = os.path.realpath(clone_dir)
    df_current = real_clone_dir
    for part in check_df_rel.split("/"):
        df_current = os.path.join(df_current, part)
        if os.path.islink(df_current):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: Dockerfile path "{check_df_rel}" contains a symlink.',
            )
    has_dockerfile = os.path.isfile(df_current) and os.path.realpath(
        df_current
    ).startswith(real_clone_dir + os.sep)

    # Gather dependency hints from package.json and Python files for companion suggestions
    pkg_text = _safe_read_repo_text(clone_dir, "package.json", MAX_INSPECT_FILE_BYTES)
    pkg_data: dict[str, Any] | None = None
    if pkg_text:
        try:
            loaded = json.loads(pkg_text)
            if isinstance(loaded, dict):
                pkg_data = loaded
        except json.JSONDecodeError:
            pkg_data = None

    deps: dict[str, Any] = {}
    scripts: dict[str, str] = {}
    if pkg_data is not None:
        for field in ("dependencies", "devDependencies"):
            val = pkg_data.get(field)
            if isinstance(val, dict):
                deps.update(val)
        raw_scripts = pkg_data.get("scripts")
        if isinstance(raw_scripts, dict):
            scripts = {
                str(k): str(v) for k, v in raw_scripts.items() if isinstance(v, str)
            }

    req_text = _safe_read_repo_text(clone_dir, "requirements.txt", MAX_INSPECT_FILE_BYTES) or ""
    pyproject_text = _safe_read_repo_text(clone_dir, "pyproject.toml", MAX_INSPECT_FILE_BYTES) or ""
    py_deps_lower = f"{req_text}\n{pyproject_text}".lower()

    suggested_companions: list[str] = []
    if (
        any(k in env_key_names or k.startswith("POSTGRES_") for k in ("DATABASE_URL",))
        or any(k.startswith("POSTGRES_") for k in env_key_names)
        or any(d in deps for d in ("pg", "postgres", "prisma", "@prisma/client", "drizzle-orm"))
        or any(p in py_deps_lower for p in ("psycopg", "asyncpg", "sqlalchemy", "sqlmodel"))
    ):
        suggested_companions.append("postgres")
    if (
        "REDIS_URL" in env_key_names
        or any(k.startswith("REDIS_") for k in env_key_names)
        or any(d in deps for d in ("redis", "ioredis", "bullmq"))
        or re.search(r"\bredis\b", py_deps_lower)
    ):
        suggested_companions.append("redis")

    if has_dockerfile:
        df_text = _safe_read_repo_text(clone_dir, check_df_rel, MAX_INSPECT_FILE_BYTES) or ""
        suggested_port = _detect_dockerfile_exposed_port(df_text)
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": True,
            "dockerfilePath": check_df_rel,
            "detectedRuntime": "dockerfile",
            "suggestedPort": suggested_port,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": f"Uses repository {check_df_rel} (port {suggested_port}).",
            "notes": notes,
            "generatedDockerfile": None,
        }

    # Auto-detect common runtimes when no Dockerfile exists
    if pkg_data is not None:
        if _is_regular_file_inside(clone_dir, "pnpm-lock.yaml"):
            pkg_manager = "pnpm"
            run_prefix = "pnpm"
        elif _is_regular_file_inside(clone_dir, "yarn.lock"):
            pkg_manager = "yarn"
            run_prefix = "yarn"
        else:
            pkg_manager = "npm"
            run_prefix = "npm run"

        install_lines = _build_node_install_lines(pkg_manager)

        if "next" in deps:
            build_cmd = f"{run_prefix} build" if "build" in scripts else "npx next build"
            start_cmd = (
                '["sh", "-c", "npx next start -H 0.0.0.0 -p ${PORT:-3000}"]'
                if pkg_manager == "npm"
                else f'["sh", "-c", "{pkg_manager} exec next start -H 0.0.0.0 -p ${{PORT:-3000}}"]'
            )
            generated_df = "\n".join(
                [
                    "FROM node:22-alpine",
                    "WORKDIR /app",
                    "ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0",
                    *install_lines,
                    "COPY . .",
                    f"RUN {build_cmd}",
                    "RUN chown -R node:node /app",
                    "USER node",
                    "EXPOSE 3000",
                    f"CMD {start_cmd}",
                    "",
                ]
            )
            notes.append(
                f"No Dockerfile found — auto-detected Next.js ({pkg_manager}) and generated a non-root Locked-Apartment build recipe."
            )
            return {
                "ok": True,
                "gitRepoUrl": repo_url,
                "resolvedBranch": resolved_branch,
                "commitSha": commit_sha,
                "hasDockerfile": False,
                "dockerfilePath": "auto",
                "detectedRuntime": "nextjs",
                "suggestedPort": 3000,
                "suggestedSlug": suggested_slug,
                "suggestedName": suggested_name,
                "envExampleKeys": env_example_keys,
                "suggestedCompanions": suggested_companions,
                "buildPlanSummary": f"Auto-detected Next.js ({pkg_manager}) — runs on port 3000.",
                "notes": notes,
                "generatedDockerfile": generated_df,
            }

        backend_deps = {
            "express",
            "fastify",
            "hono",
            "@nestjs/core",
            "koa",
            "nuxt",
            "astro",
            "@sveltejs/kit",
        }
        start_script = scripts.get("start", "")
        has_server_start = bool(
            re.search(r"\b(node|tsx|ts-node|bun|fastify|nest)\b", start_script)
        )
        if (
            "vite" in deps
            and "build" in scripts
            and not any(d in deps for d in backend_deps)
            and not has_server_start
        ):
            build_cmd = f"{run_prefix} build"
            generated_df = "\n".join(
                [
                    "FROM node:22-alpine AS builder",
                    "WORKDIR /app",
                    *install_lines,
                    "COPY . .",
                    f"RUN {build_cmd}",
                    "",
                    "FROM nginxinc/nginx-unprivileged:alpine",
                    "COPY --from=builder /app/dist /usr/share/nginx/html",
                    r'RUN printf "server {\n  listen 8080;\n  server_name _;\n  root /usr/share/nginx/html;\n  index index.html;\n  location / {\n    try_files \$uri \$uri/ /index.html;\n  }\n}\n" > /etc/nginx/conf.d/default.conf',
                    "EXPOSE 8080",
                    "",
                ]
            )
            notes.append(
                f"No Dockerfile found — auto-detected Vite web app ({pkg_manager}) and packaged it with an unprivileged static web server."
            )
            return {
                "ok": True,
                "gitRepoUrl": repo_url,
                "resolvedBranch": resolved_branch,
                "commitSha": commit_sha,
                "hasDockerfile": False,
                "dockerfilePath": "auto",
                "detectedRuntime": "vite-static",
                "suggestedPort": 8080,
                "suggestedSlug": suggested_slug,
                "suggestedName": suggested_name,
                "envExampleKeys": env_example_keys,
                "suggestedCompanions": suggested_companions,
                "buildPlanSummary": f"Auto-detected Vite frontend ({pkg_manager}) — builds dist/ and serves on port 8080.",
                "notes": notes,
                "generatedDockerfile": generated_df,
            }

        has_build = "build" in scripts
        if "start" in scripts:
            start_cmd = (
                '["pnpm", "start"]'
                if pkg_manager == "pnpm"
                else '["yarn", "start"]'
                if pkg_manager == "yarn"
                else '["npm", "start"]'
            )
        elif _is_regular_file_inside(clone_dir, "server.js"):
            start_cmd = '["node", "server.js"]'
        elif _is_regular_file_inside(clone_dir, "index.js"):
            start_cmd = '["node", "index.js"]'
        else:
            start_cmd = '["npm", "start"]'

        node_lines = [
            "FROM node:22-alpine",
            "WORKDIR /app",
            "ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0",
            *install_lines,
            "COPY . .",
        ]
        if has_build:
            node_lines.append(f"RUN {run_prefix} build")
        node_lines.extend(
            [
                "RUN chown -R node:node /app",
                "USER node",
                "EXPOSE 3000",
                f"CMD {start_cmd}",
                "",
            ]
        )
        notes.append(
            f"No Dockerfile found — auto-detected Node.js ({pkg_manager}) and generated a non-root Locked-Apartment build recipe."
        )
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": False,
            "dockerfilePath": "auto",
            "detectedRuntime": "node",
            "suggestedPort": 3000,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": f"Auto-detected Node.js ({pkg_manager}) — runs on port 3000.",
            "notes": notes,
            "generatedDockerfile": "\n".join(node_lines),
        }

    if req_text or pyproject_text:
        has_main = _is_regular_file_inside(clone_dir, "main.py") is not None
        has_app = _is_regular_file_inside(clone_dir, "app.py") is not None
        has_wsgi = _is_regular_file_inside(clone_dir, "wsgi.py") is not None
        if ("fastapi" in py_deps_lower or "uvicorn" in py_deps_lower) and (
            has_main or has_app
        ):
            mod = "main" if has_main else "app"
            py_cmd = f'["python", "-m", "uvicorn", "{mod}:app", "--host", "0.0.0.0", "--port", "8000"]'
            py_desc = f"FastAPI / Uvicorn ({mod}:app)"
        elif "gunicorn" in py_deps_lower and (has_wsgi or has_app or has_main):
            mod = "wsgi" if has_wsgi else ("app" if has_app else "main")
            py_cmd = f'["python", "-m", "gunicorn", "--bind", "0.0.0.0:8000", "{mod}:app"]'
            py_desc = f"Gunicorn ({mod}:app)"
        elif "flask" in py_deps_lower and (has_app or has_main):
            mod = "app" if has_app else "main"
            py_cmd = f'["python", "-m", "flask", "--app", "{mod}", "run", "--host", "0.0.0.0", "--port", "8000"]'
            py_desc = f"Flask ({mod}.py)"
        elif has_main:
            py_cmd = '["python", "main.py"]'
            py_desc = "Python (main.py)"
        elif has_app:
            py_cmd = '["python", "app.py"]'
            py_desc = "Python (app.py)"
        else:
            py_cmd = '["python", "-m", "http.server", "8000"]'
            py_desc = "Python"

        py_lines = [
            "FROM python:3.12-slim",
            "WORKDIR /app",
            "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000",
            "RUN useradd --create-home --uid 10001 appuser",
            "COPY . .",
        ]
        if req_text:
            py_lines.append(
                "RUN pip install --no-cache-dir -r requirements.txt"
            )
        elif pyproject_text:
            py_lines.append("RUN pip install --no-cache-dir .")
        py_lines.extend(
            [
                "RUN chown -R appuser:appuser /app",
                "USER appuser",
                "EXPOSE 8000",
                f"CMD {py_cmd}",
                "",
            ]
        )
        notes.append(
            f"No Dockerfile found — auto-detected {py_desc} and generated a non-root Locked-Apartment build recipe."
        )
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": False,
            "dockerfilePath": "auto",
            "detectedRuntime": "python",
            "suggestedPort": 8000,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": f"Auto-detected {py_desc} — runs on port 8000.",
            "notes": notes,
            "generatedDockerfile": "\n".join(py_lines),
        }

    if _is_regular_file_inside(clone_dir, "index.html"):
        generated_df = "\n".join(
            [
                "FROM nginxinc/nginx-unprivileged:alpine",
                "COPY . /usr/share/nginx/html",
                "RUN printf '%s\\n' 'server {' '  listen 8080;' '  server_name _;' '  root /usr/share/nginx/html;' '  index index.html;' '  location ~ (^/\\.(?!well-known(/|$))|.+/\\.) {' '    deny all;' '    return 404;' '  }' '  location / {' '    try_files $uri $uri/ =404;' '  }' '}' > /etc/nginx/conf.d/default.conf",
                "EXPOSE 8080",
                "",
            ]
        )
        notes.append(
            "No Dockerfile found — auto-detected static HTML site (index.html) and packaged it with an unprivileged web server (hidden dotfiles and repo metadata excluded)."
        )
        return {
            "ok": True,
            "gitRepoUrl": repo_url,
            "resolvedBranch": resolved_branch,
            "commitSha": commit_sha,
            "hasDockerfile": False,
            "dockerfilePath": "auto",
            "detectedRuntime": "static",
            "suggestedPort": 8080,
            "suggestedSlug": suggested_slug,
            "suggestedName": suggested_name,
            "envExampleKeys": env_example_keys,
            "suggestedCompanions": suggested_companions,
            "buildPlanSummary": "Auto-detected static website (index.html) — serves on port 8080.",
            "notes": notes,
            "generatedDockerfile": generated_df,
        }

    notes.append(
        "No Dockerfile found and no Node.js (package.json), Python (requirements.txt/pyproject.toml), or static (index.html) project was detected. Add a Dockerfile to this repository to deploy it."
    )
    return {
        "ok": True,
        "gitRepoUrl": repo_url,
        "resolvedBranch": resolved_branch,
        "commitSha": commit_sha,
        "hasDockerfile": False,
        "dockerfilePath": check_df_rel,
        "detectedRuntime": "unknown",
        "suggestedPort": 8080,
        "suggestedSlug": suggested_slug,
        "suggestedName": suggested_name,
        "envExampleKeys": env_example_keys,
        "suggestedCompanions": suggested_companions,
        "buildPlanSummary": "Could not auto-detect project type — a Dockerfile is required.",
        "notes": notes,
        "generatedDockerfile": None,
    }


def validate_dockerfile_path(raw: Any) -> str:
    if raw is None:
        return "Dockerfile"
    if not isinstance(raw, str):
        raise BridgeRequestError(400, "Field 'dockerfilePath' must be a string.")
    trimmed = raw.strip()
    if (
        not trimmed
        or not DOCKERFILE_PATH_PATTERN.match(trimmed)
        or trimmed.startswith("/")
        or trimmed.startswith("-")
        or "\\" in trimmed
        or ".." in trimmed
        or any(seg in ("", ".", "..") for seg in trimmed.split("/"))
    ):
        raise BridgeRequestError(
            400,
            f'Invalid Dockerfile path "{raw}": must be a safe relative path inside the repository.',
        )
    return trimmed


def _assert_public_ip_address(ip_str: str, raw_host: str) -> None:
    clean_ip = ip_str.strip().strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(clean_ip)
    except ValueError as exc:
        raise BridgeRequestError(
            400, f'Invalid resolved IP address for host "{raw_host}".'
        ) from exc

    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254 or ::ffff:10.0.0.1)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    # Cloud metadata checks (AWS/GCP/Azure 169.254.0.0/16, Alibaba 100.100.100.200, AWS IMDSv2 IPv6)
    if isinstance(addr, ipaddress.IPv4Address):
        octets = addr.packed
        if octets[0] == 169 and octets[1] == 254:
            raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_host}".')
        if (octets[0], octets[1], octets[2], octets[3]) == (100, 100, 100, 200):
            raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_host}".')
        # CGNAT 100.64.0.0/10
        if octets[0] == 100 and 64 <= octets[1] <= 127:
            raise BridgeRequestError(400, f'Blocked private network host "{raw_host}".')
    else:
        if addr == ipaddress.IPv6Address("fd00:ec2::254"):
            raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_host}".')

    if addr.is_link_local:
        raise BridgeRequestError(400, f'Blocked link-local host "{raw_host}".')
    if addr.is_loopback or addr.is_unspecified:
        raise BridgeRequestError(400, f'Blocked loopback host "{raw_host}".')
    if addr.is_private or addr.is_multicast or addr.is_reserved:
        raise BridgeRequestError(400, f'Blocked private network host "{raw_host}".')


def default_dns_resolver(hostname: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            ips.append(sockaddr[0])
    return ips


def validate_git_repo_url_with_ips(
    raw: Any, dns_resolver: DnsResolver | None = None
) -> tuple[str, str, int, list[str]]:
    """
    Validates a public HTTPS Git repository URL and returns
    `(normalized_url, host, port, validated_public_ips)` so the subsequent
    TCP connection can be pinned strictly to the validated public IP(s).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise BridgeRequestError(400, "Field 'gitRepoUrl' must be a non-empty string.")
    trimmed = raw.strip()
    if any(ch.isspace() or ord(ch) < 32 for ch in trimmed):
        raise BridgeRequestError(
            400,
            "Git repository URL contains invalid whitespace or control characters.",
        )

    parsed = urlparse(trimmed)
    if parsed.scheme.lower() != "https":
        raise BridgeRequestError(400, "Git repository URL must use https://.")
    if parsed.username or parsed.password:
        raise BridgeRequestError(400, "Git repository URL must not embed credentials.")
    if not parsed.hostname:
        raise BridgeRequestError(400, "Git repository URL is missing a hostname.")

    raw_hostname = parsed.hostname.lower()
    host = raw_hostname.strip("[]").rstrip(".")
    if not host:
        raise BridgeRequestError(400, "Git repository URL is missing a hostname.")
    if host in BLOCKED_METADATA_HOSTS:
        raise BridgeRequestError(400, f'Blocked cloud metadata host "{raw_hostname}".')
    if host == "localhost" or host.endswith(".localhost"):
        raise BridgeRequestError(400, f'Blocked loopback host "{raw_hostname}".')

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise BridgeRequestError(400, "Git repository URL has an invalid port.") from exc

    is_literal_ip = False
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        is_literal_ip = True
    except ValueError:
        is_literal_ip = False

    validated_ips: list[str] = []
    if is_literal_ip:
        _assert_public_ip_address(host, raw_hostname)
        validated_ips.append(host.split("%", 1)[0])
    else:
        if "." not in host:
            raise BridgeRequestError(
                400, f'Blocked single-label internal host "{raw_hostname}".'
            )
        resolver = dns_resolver or default_dns_resolver
        try:
            resolved_ips = resolver(host, port)
        except OSError as exc:
            raise BridgeRequestError(
                400, f'Could not resolve Git host "{raw_hostname}": {exc}'
            ) from exc
        if not resolved_ips:
            raise BridgeRequestError(
                400, f'Could not resolve Git host "{raw_hostname}".'
            )
        seen: set[str] = set()
        for ip_str in resolved_ips:
            _assert_public_ip_address(ip_str, raw_hostname)
            clean = ip_str.strip().strip("[]").split("%", 1)[0]
            if clean not in seen:
                seen.add(clean)
                validated_ips.append(clean)

    return trimmed, host, port, validated_ips


def validate_git_repo_url(
    raw: Any, dns_resolver: DnsResolver | None = None
) -> str:
    """
    Validates a public HTTPS Git repository URL and checks every DNS-resolved IP
    against loopback, RFC1918/ULA private networks, CGNAT, and cloud metadata endpoints.
    """
    url, _, _, _ = validate_git_repo_url_with_ips(raw, dns_resolver=dns_resolver)
    return url


class _PinnedGitConnectProxy:
    """
    Single-purpose ephemeral loopback HTTP CONNECT proxy used during `git clone`.
    Enforces that Git/libcurl can ONLY connect to the exact validated hostname,
    port, and pre-validated public IP(s) — eliminating DNS rebinding TOCTOU while
    preserving full hostname SNI and TLS certificate verification.
    """

    def __init__(
        self,
        expected_host: str,
        expected_port: int,
        validated_ips: list[str],
        connect_timeout: float = 15.0,
    ) -> None:
        self.expected_host = expected_host.lower().strip("[]").rstrip(".")
        self.expected_port = expected_port
        self.validated_ips = list(validated_ips)
        self.connect_timeout = connect_timeout
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.port = 0

    def __enter__(self) -> "_PinnedGitConnectProxy":
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        srv.settimeout(0.5)
        self._sock = srv
        self.port = int(srv.getsockname()[1])
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(client,), daemon=True
            ).start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(10.0)
            req_buf = b""
            while b"\r\n\r\n" not in req_buf and len(req_buf) < 8192:
                chunk = client.recv(2048)
                if not chunk:
                    return
                req_buf += chunk
            first_line = req_buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first_line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            authority = parts[1]
            if authority.startswith("["):
                host_part, _, port_part = authority[1:].partition("]:")
            else:
                host_part, _, port_part = authority.rpartition(":")
            req_host = host_part.lower().rstrip(".")
            try:
                req_port = int(port_part)
            except ValueError:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            if req_host != self.expected_host or req_port != self.expected_port:
                client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return

            last_err: OSError | None = None
            for ip in self.validated_ips:
                try:
                    _assert_public_ip_address(ip, self.expected_host)
                    upstream = socket.create_connection(
                        (ip, self.expected_port), timeout=self.connect_timeout
                    )
                    break
                except (OSError, BridgeRequestError) as exc:
                    last_err = exc if isinstance(exc, OSError) else OSError(str(exc))
                    upstream = None
            if upstream is None:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            client.setblocking(False)
            upstream.setblocking(False)
            sockets = [client, upstream]
            while not self._stop.is_set():
                readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
                if exceptional:
                    break
                for src in readable:
                    dst = upstream if src is client else client
                    try:
                        data = src.recv(16384)
                    except OSError:
                        return
                    if not data:
                        return
                    dst.setblocking(True)
                    dst.settimeout(10.0)
                    dst.sendall(data)
                    dst.setblocking(False)
        except OSError:
            pass
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            try:
                client.close()
            except OSError:
                pass


def _probe_container_http(
    ip_addr: str,
    port: int,
    probe_path: str,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """
    Probes an app container's private bridge IP over HTTP.
    Treats any non-5xx HTTP status (`100 <= status < 500`, including 4xx API roots)
    as `ok: True` (server is listening and routable).
    """
    try:
        parsed_ip = ipaddress.ip_address(ip_addr)
    except ValueError:
        return {
            "attempted": False,
            "ok": False,
            "statusCode": None,
            "latencyMs": None,
            "contentType": None,
            "error": "Container IP address is invalid.",
        }
    if (
        parsed_ip.is_link_local
        or parsed_ip.is_multicast
        or parsed_ip.is_unspecified
        or not (parsed_ip.is_private or parsed_ip.is_loopback)
    ):
        return {
            "attempted": False,
            "ok": False,
            "statusCode": None,
            "latencyMs": None,
            "contentType": None,
            "error": "Refused HTTP probe against non-private container address.",
        }

    t0 = time.perf_counter()
    conn: http.client.HTTPConnection | None = None
    try:
        conn = http.client.HTTPConnection(ip_addr, port, timeout=timeout_s)
        conn.request(
            "GET",
            probe_path,
            headers={
                "Host": "localhost",
                "User-Agent": "vpsagent-probe/2",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        resp.read(MAX_PROBE_BODY_BYTES)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "attempted": True,
            "ok": 100 <= resp.status < 500,
            "statusCode": resp.status,
            "latencyMs": elapsed_ms,
            "contentType": resp.getheader("Content-Type"),
            "error": None,
        }
    except (OSError, http.client.HTTPException) as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "attempted": True,
            "ok": False,
            "statusCode": None,
            "latencyMs": elapsed_ms,
            "contentType": None,
            "error": redact_secrets(str(exc)),
        }
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _sanitized_subprocess_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Never inherit core secrets from systemd EnvironmentFile into docker/git subprocesses."""
    allowlist = [
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ]
    if sys.platform == "win32":
        allowlist.extend(["SYSTEMROOT", "PATHEXT", "COMSPEC", "TEMP", "TMP"])
    env = {k: os.environ[k] for k in allowlist if k in os.environ}
    if extra:
        env.update(extra)
    return env


def _read_regular_file_nofollow(path: str, max_bytes: int, label: str) -> str:
    if not os.path.lexists(path):
        raise BridgeRequestError(404, f"{label} does not exist.")
    if os.path.islink(path):
        raise BridgeRequestError(
            400, f"Security boundary violation: {label} cannot be a symlink."
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise BridgeRequestError(400, f"Could not safely open {label}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BridgeRequestError(
                400, f"Security boundary violation: {label} must be a regular file."
            )
        if st.st_size > max_bytes:
            raise BridgeRequestError(400, f"{label} exceeds maximum allowed size.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BridgeRequestError(400, f"{label} exceeds maximum allowed size.")
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeRequestError(400, f"{label} must be valid UTF-8 text.") from exc
    finally:
        os.close(fd)


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx]
    return line


def _split_inline_yaml_list(inner: str) -> list[str]:
    items: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for ch in inner:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_double:
            buf.append(ch)
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            continue
        if ch == "," and not in_single and not in_double:
            items.append("".join(buf))
            buf.clear()
            continue
        buf.append(ch)
    if buf or items:
        items.append("".join(buf))
    return items


def _parse_yaml_scalar(raw: str) -> Any:
    val = raw.strip()
    if val == "":
        return None
    if val in ("true", "True", "TRUE"):
        return True
    if val in ("false", "False", "FALSE"):
        return False
    if val in ("null", "Null", "~"):
        return None
    if val.startswith("[") and val.endswith("]"):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_yaml_scalar(part) for part in _split_inline_yaml_list(inner)]
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        if len(val) >= 2:
            if val.startswith('"'):
                try:
                    return json.loads(val)
                except json.JSONDecodeError:
                    return val[1:-1]
            return val[1:-1]
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    if re.fullmatch(r"-?\d+\.\d+", val):
        return float(val)
    if val.startswith(("&", "*", "!")):
        raise BridgeRequestError(
            400, "YAML anchors, aliases, and custom tags are forbidden."
        )
    return val


def _split_yaml_mapping(text: str) -> tuple[str, str] | None:
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(text):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if idx + 1 == len(text) or text[idx + 1].isspace():
                return text[:idx].strip().strip("'\""), text[idx + 1 :].strip()
    return None


def parse_simple_yaml(content: str) -> dict[str, Any]:
    """
    Indentation-aware strict YAML subset parser for Locked Apartment Compose files.
    Rejects anchors, aliases, tags, multi-document streams, and tabs in indentation.
    """
    tokens: list[tuple[int, str]] = []
    for lineno, raw_line in enumerate(content.splitlines(), start=1):
        stripped_comment = _strip_yaml_comment(raw_line).rstrip()
        if not stripped_comment.strip():
            continue
        if stripped_comment.strip() in ("---", "..."):
            raise BridgeRequestError(400, "Multi-document YAML streams are forbidden.")
        leading = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        if "\t" in stripped_comment[:leading] or stripped_comment.startswith("\t"):
            raise BridgeRequestError(
                400, f"Tabs are not permitted in YAML indentation (line {lineno})."
            )
        tokens.append((leading, stripped_comment[leading:]))

    if not tokens:
        raise BridgeRequestError(400, "docker-compose.yml cannot be empty.")

    def parse_block(index: int, expected_indent: int) -> tuple[Any, int]:
        if index >= len(tokens):
            return {}, index
        indent, text = tokens[index]
        if indent < expected_indent:
            return None, index

        if text.startswith("- ") or text == "-":
            items: list[Any] = []
            list_indent = indent
            while index < len(tokens):
                cur_indent, cur_text = tokens[index]
                if cur_indent != list_indent or not (
                    cur_text.startswith("- ") or cur_text == "-"
                ):
                    break
                after_dash = cur_text[1:].strip()
                index += 1
                if not after_dash:
                    nested, index = parse_block(index, list_indent + 1)
                    items.append(nested)
                    continue
                kv = _split_yaml_mapping(after_dash)
                if kv is not None:
                    key, val_part = kv
                    item_dict: dict[str, Any] = {}
                    if val_part == "":
                        nested, index = parse_block(index, list_indent + 2)
                        item_dict[key] = nested if nested is not None else {}
                    else:
                        item_dict[key] = _parse_yaml_scalar(val_part)
                    if index < len(tokens) and tokens[index][0] > list_indent:
                        more, index = parse_block(index, tokens[index][0])
                        if isinstance(more, dict):
                            item_dict.update(more)
                        else:
                            raise BridgeRequestError(
                                400, "Invalid list item mapping in Compose file."
                            )
                    items.append(item_dict)
                else:
                    items.append(_parse_yaml_scalar(after_dash))
            return items, index

        mapping: dict[str, Any] = {}
        map_indent = indent
        while index < len(tokens):
            cur_indent, cur_text = tokens[index]
            if cur_indent < map_indent:
                break
            if cur_indent > map_indent or cur_text.startswith("- ") or cur_text == "-":
                raise BridgeRequestError(
                    400, f"Invalid YAML structure near '{cur_text}'."
                )
            kv = _split_yaml_mapping(cur_text)
            if kv is None:
                raise BridgeRequestError(
                    400, f"Expected key: value mapping near '{cur_text}'."
                )
            key, val_part = kv
            if not key:
                raise BridgeRequestError(400, "Empty YAML key is not allowed.")
            index += 1
            if val_part == "":
                if index < len(tokens) and tokens[index][0] > map_indent:
                    nested, index = parse_block(index, tokens[index][0])
                    mapping[key] = nested
                else:
                    mapping[key] = {}
            else:
                mapping[key] = _parse_yaml_scalar(val_part)
        return mapping, index

    parsed, next_idx = parse_block(0, tokens[0][0])
    if next_idx != len(tokens) or not isinstance(parsed, dict):
        raise BridgeRequestError(
            400, "docker-compose.yml root must be a YAML mapping."
        )
    return parsed


def _unescape_double_quoted_env(inner: str) -> str:
    out: list[str] = []
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if ch == "\\" and i + 1 < n:
            nxt = inner[i + 1]
            if nxt == "n":
                out.append("\n")
            elif nxt == "r":
                out.append("\r")
            elif nxt == '"':
                out.append('"')
            elif nxt == "\\":
                out.append("\\")
            else:
                out.append("\\" + nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_and_validate_env_file(env_text: str, slug: str) -> dict[str, str]:
    env_map: dict[str, str] = {}
    for lineno, raw_line in enumerate(env_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise BridgeRequestError(400, f"Invalid .env syntax at line {lineno}.")
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not ENV_KEY_PATTERN.match(key):
            raise BridgeRequestError(
                400, f'Invalid .env key "{key}" at line {lineno}.'
            )
        if key in DISALLOWED_ENV_EXACT or key.startswith(DISALLOWED_ENV_PREFIXES):
            raise BridgeRequestError(
                400, f'Forbidden environment variable "{key}" in app .env.'
            )
        if "\x00" in val:
            raise BridgeRequestError(
                400, f'Invalid null byte in .env value for "{key}".'
            )
        if len(val) >= 2 and val.startswith("'") and val.endswith("'"):
            val = val[1:-1]
        elif len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = _unescape_double_quoted_env(val[1:-1])
        env_map[key] = val

    if "APP_SLUG" in env_map and env_map["APP_SLUG"] != slug:
        raise BridgeRequestError(
            400,
            f'App .env APP_SLUG="{env_map["APP_SLUG"]}" does not match slug "{slug}".',
        )
    if "APP_PORT" in env_map and env_map["APP_PORT"]:
        try:
            validate_port(int(env_map["APP_PORT"]))
        except ValueError as exc:
            raise BridgeRequestError(400, "Invalid APP_PORT in app .env.") from exc
    if "APP_IMAGE" in env_map and env_map["APP_IMAGE"]:
        if "$" in env_map["APP_IMAGE"] or not IMAGE_REF_PATTERN.match(
            env_map["APP_IMAGE"]
        ):
            raise BridgeRequestError(400, "Invalid APP_IMAGE in app .env.")
    return env_map


def _resolve_allowed_vars(
    value: str, env_map: dict[str, str], allowed_vars: frozenset[str] | set[str], field: str
) -> str:
    if "$" not in value:
        return value

    out: list[str] = []
    pos = 0
    for match in INTERPOLATION_RE.finditer(value):
        literal_prefix = value[pos : match.start()]
        if "$" in literal_prefix:
            raise BridgeRequestError(
                400, f"Unsupported variable expansion syntax in Compose {field}."
            )
        out.append(literal_prefix)

        var_name = match.group(1)
        default_val = match.group(2)
        if var_name not in allowed_vars:
            raise BridgeRequestError(
                400, f'Disallowed variable "${{{var_name}}}" in Compose {field}.'
            )
        if var_name in env_map and env_map[var_name] != "":
            out.append(env_map[var_name])
        elif default_val is not None:
            out.append(default_val)
        else:
            raise BridgeRequestError(
                400, f'Missing variable "{var_name}" referenced in Compose {field}.'
            )
        pos = match.end()

    trailing = value[pos:]
    if "$" in trailing:
        raise BridgeRequestError(
            400, f"Unsupported variable expansion syntax in Compose {field}."
        )
    out.append(trailing)
    return "".join(out)


def _validate_cpus(raw: Any, slug: str, svc_name: str) -> str:
    if raw is None or isinstance(raw, bool):
        raise BridgeRequestError(
            400,
            f'Compose isolation policy rejected "{slug}": service "{svc_name}" must specify cpus.',
        )
    try:
        val = float(str(raw).strip())
    except ValueError as exc:
        raise BridgeRequestError(
            400, f'Invalid cpus value for service "{svc_name}".'
        ) from exc
    if val < 0.05 or val > 64.0:
        raise BridgeRequestError(
            400, f'cpus for service "{svc_name}" must be between 0.05 and 64.0.'
        )
    return str(raw).strip()


def _validate_mem_limit(raw: Any, slug: str, svc_name: str) -> str:
    if raw is None or isinstance(raw, bool):
        raise BridgeRequestError(
            400,
            f'Compose isolation policy rejected "{slug}": service "{svc_name}" must specify mem_limit.',
        )
    text = str(raw).strip()
    m = MEM_LIMIT_PATTERN.match(text)
    if not m:
        raise BridgeRequestError(
            400, f'Invalid mem_limit "{raw}" for service "{svc_name}".'
        )
    num = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "g":
        mb = num * 1024
    elif unit == "m":
        mb = num
    elif unit == "k":
        mb = num / 1024.0
    else:
        mb = num / (1024.0 * 1024.0)
    if mb < 16 or mb > 131072:
        raise BridgeRequestError(
            400, f'mem_limit for service "{svc_name}" must be between 16m and 131072m.'
        )
    return text


def _validate_no_symlink_volume_source(app_dir: str, rel_path: str, slug: str) -> str:
    real_app_dir = os.path.realpath(app_dir)
    current = real_app_dir
    for part in rel_path.replace("\\", "/").split("/"):
        if not part or part == ".":
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: volume mount path "{rel_path}" for "{slug}" contains a symlink.',
            )
    real_target = os.path.realpath(current)
    if real_target != real_app_dir and not real_target.startswith(
        real_app_dir + os.sep
    ):
        raise BridgeRequestError(
            400,
            f'Security boundary violation: volume mount path "{rel_path}" for "{slug}" escapes workspace.',
        )
    return current


def _prepare_service_volume_dir(
    app_dir: str, rel_path: str, user_spec: str | None, slug: str
) -> str:
    """
    Validates a relative volume mount source has no symlinks and prepares private
    host storage ownership for non-root services (e.g. Postgres 70:70, Redis 999:999).
    """
    abs_src = _validate_no_symlink_volume_source(app_dir, rel_path, slug)
    parts = [p for p in rel_path.replace("\\", "/").split("/") if p and p != "."]
    if parts:
        # Ensure top-level ./data or ./workspace is traversable by non-root companion UIDs
        top_dir = os.path.join(os.path.realpath(app_dir), parts[0])
        if not os.path.exists(top_dir):
            os.makedirs(top_dir, mode=0o755, exist_ok=True)
        if len(parts) > 1:
            try:
                os.chmod(top_dir, 0o755)
            except OSError:
                pass
    if not os.path.exists(abs_src):
        os.makedirs(abs_src, mode=0o700 if user_spec else 0o750, exist_ok=True)

    if user_spec:
        m = NUMERIC_USER_PATTERN.match(user_spec)
        if m:
            uid = int(m.group(1))
            gid = int(m.group(2)) if m.group(2) is not None else uid
            try:
                os.chmod(abs_src, 0o700)
            except OSError:
                pass
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                os.chown(abs_src, uid, gid)
                for root_dir, dirs, files in os.walk(abs_src):
                    if os.path.islink(root_dir):
                        continue
                    os.chown(root_dir, uid, gid)
                    for d in dirs:
                        p = os.path.join(root_dir, d)
                        if not os.path.islink(p):
                            os.chown(p, uid, gid)
                    for f in files:
                        p = os.path.join(root_dir, f)
                        if not os.path.islink(p):
                            os.chown(p, uid, gid)
    return abs_src


def _escape_compose_dollars(value: Any) -> Any:
    """Escape literal `$` as `$$` in rendered Compose values so Docker Compose never re-interpolates."""
    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, list):
        return [_escape_compose_dollars(item) for item in value]
    if isinstance(value, dict):
        return {k: _escape_compose_dollars(v) for k, v in value.items()}
    return value


def validate_and_render_compose(
    compose_text: str,
    slug: str,
    app_dir: str,
    env_map: dict[str, str],
    env_file_override: str | None,
    *,
    prepare_volumes: bool = False,
) -> dict[str, Any]:
    """
    Structurally validates every section of an app's docker-compose.yml against
    Locked Apartment boundaries and returns a self-contained JSON-serializable
    Compose structure with canonical host paths inside `app_dir`.
    """
    doc = parse_simple_yaml(compose_text)
    unknown_top = set(doc.keys()) - ALLOWED_TOP_LEVEL_COMPOSE_KEYS
    if unknown_top:
        raise BridgeRequestError(
            400,
            f"Unsupported top-level Compose keys: {', '.join(sorted(unknown_top))}.",
        )

    networks = doc.get("networks")
    if not isinstance(networks, dict) or set(networks.keys()) != {"app_net"}:
        raise BridgeRequestError(
            400,
            'Compose networks must define only isolated bridge network "app_net".',
        )
    app_net_cfg = networks["app_net"]
    if app_net_cfg is not None:
        if not isinstance(app_net_cfg, dict):
            raise BridgeRequestError(400, "Invalid app_net configuration.")
        if set(app_net_cfg.keys()) - {"driver"}:
            raise BridgeRequestError(400, "app_net may only specify driver: bridge.")
        if app_net_cfg.get("driver", "bridge") != "bridge":
            raise BridgeRequestError(400, "app_net must use driver: bridge.")

    services = doc.get("services")
    if not isinstance(services, dict) or not (1 <= len(services) <= 4):
        raise BridgeRequestError(
            400, "Compose services must contain 1-4 service definitions."
        )

    service_names = set(str(k) for k in services.keys())
    vars_ctx = {"APP_SLUG": slug, **env_map}
    rendered_services: dict[str, Any] = {}

    for svc_name, svc_cfg in services.items():
        svc_key = str(svc_name)
        if not SERVICE_NAME_PATTERN.match(svc_key) or not isinstance(svc_cfg, dict):
            raise BridgeRequestError(
                400, f'Invalid Compose service definition "{svc_key}".'
            )
        forbidden_keys = set(svc_cfg.keys()) - ALLOWED_SERVICE_KEYS
        if forbidden_keys:
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": forbidden keys ({", ".join(sorted(forbidden_keys))}).',
            )

        out_svc: dict[str, Any] = dict(svc_cfg)

        raw_image = svc_cfg.get("image")
        if not isinstance(raw_image, str):
            raise BridgeRequestError(
                400, f'Service "{svc_key}" must specify an image.'
            )
        resolved_image = _resolve_allowed_vars(
            raw_image, vars_ctx, {"APP_IMAGE"}, f"{svc_key}.image"
        )
        if not IMAGE_REF_PATTERN.match(resolved_image):
            raise BridgeRequestError(
                400, f'Invalid Docker image reference "{resolved_image}".'
            )
        out_svc["image"] = resolved_image

        if "container_name" in svc_cfg:
            raw_cname = svc_cfg["container_name"]
            if not isinstance(raw_cname, str):
                raise BridgeRequestError(400, "container_name must be a string.")
            resolved_cname = _resolve_allowed_vars(
                raw_cname, vars_ctx, {"APP_SLUG"}, f"{svc_key}.container_name"
            )
            expected_prefix = f"vpsagent-app-{slug}"
            if resolved_cname != expected_prefix and not resolved_cname.startswith(
                f"{expected_prefix}-"
            ):
                raise BridgeRequestError(
                    400,
                    f'container_name "{resolved_cname}" must be scoped to "{expected_prefix}".',
                )
            out_svc["container_name"] = resolved_cname

        if "user" in svc_cfg:
            raw_user = str(svc_cfg["user"]).strip()
            m_user = NUMERIC_USER_PATTERN.match(raw_user)
            if not m_user:
                raise BridgeRequestError(
                    400,
                    f'Service "{svc_key}" user must be numeric non-root "uid" or "uid:gid".',
                )
            uid = int(m_user.group(1))
            gid = int(m_user.group(2)) if m_user.group(2) is not None else None
            if uid < 1 or (gid is not None and gid < 1):
                raise BridgeRequestError(
                    400, f'Service "{svc_key}" cannot run as root user "{raw_user}".'
                )
            out_svc["user"] = raw_user

        out_svc["cpus"] = _validate_cpus(svc_cfg.get("cpus"), slug, svc_key)
        out_svc["mem_limit"] = _validate_mem_limit(
            svc_cfg.get("mem_limit"), slug, svc_key
        )

        cap_drop = svc_cfg.get("cap_drop")
        if not isinstance(cap_drop, list) or "ALL" not in [
            str(c).upper() for c in cap_drop
        ]:
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": cap_drop must include ALL.',
            )

        sec_opt = svc_cfg.get("security_opt")
        if not isinstance(sec_opt, list):
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": security_opt must include no-new-privileges:true.',
            )
        sec_strings = [str(s) for s in sec_opt]
        if "no-new-privileges:true" not in sec_strings or any(
            "unconfined" in s.lower() for s in sec_strings
        ):
            raise BridgeRequestError(
                400,
                f'Compose isolation policy rejected "{slug}": insecure security_opt.',
            )

        svc_nets = svc_cfg.get("networks")
        if svc_nets != ["app_net"] and (
            not isinstance(svc_nets, dict) or set(svc_nets.keys()) != {"app_net"}
        ):
            raise BridgeRequestError(
                400,
                f'Service "{svc_key}" may only connect to isolated network app_net.',
            )

        if "depends_on" in svc_cfg:
            deps = svc_cfg["depends_on"]
            if isinstance(deps, list):
                for dep in deps:
                    dep_name = str(dep)
                    if dep_name not in service_names or dep_name == svc_key:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" has invalid depends_on target "{dep_name}".',
                        )
            elif isinstance(deps, dict):
                for dep_name, dep_cfg in deps.items():
                    dep_str = str(dep_name)
                    if dep_str not in service_names or dep_str == svc_key:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" has invalid depends_on target "{dep_str}".',
                        )
                    if not isinstance(dep_cfg, dict) or set(dep_cfg.keys()) - {
                        "condition"
                    }:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" depends_on.{dep_str} only supports condition.',
                        )
                    cond = dep_cfg.get("condition", "service_started")
                    if cond not in ALLOWED_DEPENDS_ON_CONDITIONS:
                        raise BridgeRequestError(
                            400,
                            f'Service "{svc_key}" depends_on.{dep_str} has unsupported condition "{cond}".',
                        )
            else:
                raise BridgeRequestError(
                    400, f'Service "{svc_key}" depends_on must be a list or mapping.'
                )

        if "command" in svc_cfg:
            cmd_val = svc_cfg["command"]
            if isinstance(cmd_val, list):
                out_svc["command"] = [
                    _resolve_allowed_vars(
                        str(part),
                        vars_ctx,
                        ALLOWED_COMMAND_INTERPOLATION_VARS,
                        f"{svc_key}.command",
                    )
                    for part in cmd_val
                ]
            elif isinstance(cmd_val, str):
                out_svc["command"] = _resolve_allowed_vars(
                    cmd_val,
                    vars_ctx,
                    ALLOWED_COMMAND_INTERPOLATION_VARS,
                    f"{svc_key}.command",
                )
            else:
                raise BridgeRequestError(400, "command must be a string or list.")

        uses_app_env_file = False
        if "env_file" in svc_cfg:
            env_files = svc_cfg["env_file"]
            if not isinstance(env_files, list):
                raise BridgeRequestError(400, "env_file must be a list.")
            for entry in env_files:
                if isinstance(entry, str):
                    if entry != ".env":
                        raise BridgeRequestError(
                            400, "env_file may only reference '.env'."
                        )
                    uses_app_env_file = True
                elif isinstance(entry, dict):
                    if (
                        set(entry.keys()) - {"path", "required"}
                        or entry.get("path") != ".env"
                    ):
                        raise BridgeRequestError(
                            400, "env_file entries may only reference path '.env'."
                        )
                    req_flag = entry.get("required", True)
                    if not isinstance(req_flag, bool):
                        raise BridgeRequestError(
                            400, "env_file.required must be a boolean."
                        )
                    uses_app_env_file = True
                else:
                    raise BridgeRequestError(400, "Invalid env_file entry.")
            # Never pass `.env` to Docker Compose `env_file` (which expands `${VAR}` inside
            # double quotes). Instead inject parsed literal `env_map` values directly into
            # `environment` and escape `$` -> `$$` so every quote, newline, backslash, and
            # `$` arrives verbatim in the container.
            out_svc.pop("env_file", None)

        explicit_env: dict[str, Any] = {}
        if "environment" in svc_cfg:
            env_section = svc_cfg["environment"]
            if isinstance(env_section, dict):
                for ek, ev in env_section.items():
                    ek_str = str(ek)
                    if ek_str in DISALLOWED_ENV_EXACT or ek_str.startswith(
                        DISALLOWED_ENV_PREFIXES
                    ):
                        raise BridgeRequestError(
                            400, f'Forbidden Compose environment key "{ek_str}".'
                        )
                    if isinstance(ev, str):
                        explicit_env[ek_str] = _resolve_allowed_vars(
                            ev,
                            vars_ctx,
                            ALLOWED_ENV_INTERPOLATION_VARS,
                            f"{svc_key}.environment.{ek_str}",
                        )
                    else:
                        explicit_env[ek_str] = ev
            elif isinstance(env_section, list):
                for item in env_section:
                    item_str = str(item)
                    if "=" not in item_str:
                        raise BridgeRequestError(
                            400, f'Compose environment entry "{item_str}" must be KEY=VALUE.'
                        )
                    k, v = item_str.split("=", 1)
                    k = k.strip()
                    if k in DISALLOWED_ENV_EXACT or k.startswith(
                        DISALLOWED_ENV_PREFIXES
                    ):
                        raise BridgeRequestError(
                            400, f'Forbidden Compose environment key "{k}".'
                        )
                    explicit_env[k] = _resolve_allowed_vars(
                        v,
                        vars_ctx,
                        ALLOWED_ENV_INTERPOLATION_VARS,
                        f"{svc_key}.environment.{k}",
                    )
            else:
                raise BridgeRequestError(
                    400, "environment must be a mapping or list."
                )

        if uses_app_env_file or explicit_env:
            merged_env: dict[str, Any] = {}
            if uses_app_env_file:
                merged_env.update(env_map)
            merged_env.update(explicit_env)
            out_svc["environment"] = merged_env

        if "volumes" in svc_cfg:
            vols = svc_cfg["volumes"]
            if not isinstance(vols, list):
                raise BridgeRequestError(400, "volumes must be a list.")
            rewritten_vols: list[str] = []
            for vol in vols:
                if not isinstance(vol, str) or "$" in vol or ".." in vol:
                    raise BridgeRequestError(
                        400,
                        f'Compose isolation policy rejected "{slug}": unsafe volume mount.',
                    )
                if not RELATIVE_MOUNT_PATTERN.match(vol):
                    raise BridgeRequestError(
                        400,
                        f'Compose isolation policy rejected "{slug}": volume "{vol}" escapes ./data or ./workspace.',
                    )
                rel_src, rest = vol.split(":", 1)
                if prepare_volumes:
                    abs_src = _prepare_service_volume_dir(
                        app_dir, rel_src[2:], out_svc.get("user"), slug
                    )
                else:
                    abs_src = _validate_no_symlink_volume_source(
                        app_dir, rel_src[2:], slug
                    )
                rewritten_vols.append(f"{abs_src}:{rest}")
            out_svc["volumes"] = rewritten_vols

        if "healthcheck" in svc_cfg:
            hc = svc_cfg["healthcheck"]
            if not isinstance(hc, dict) or (set(hc.keys()) - ALLOWED_HEALTHCHECK_KEYS):
                raise BridgeRequestError(400, "Invalid healthcheck configuration.")
            hc_allowed = {"APP_PORT", "APP_SLUG", "POSTGRES_USER", "POSTGRES_DB"}
            if isinstance(hc.get("test"), str):
                hc_copy = dict(hc)
                hc_copy["test"] = _resolve_allowed_vars(
                    hc["test"], vars_ctx, hc_allowed, f"{svc_key}.healthcheck.test"
                )
                out_svc["healthcheck"] = hc_copy
            elif isinstance(hc.get("test"), list):
                hc_copy = dict(hc)
                hc_copy["test"] = [
                    _resolve_allowed_vars(
                        str(part),
                        vars_ctx,
                        hc_allowed,
                        f"{svc_key}.healthcheck.test",
                    )
                    for part in hc["test"]
                ]
                out_svc["healthcheck"] = hc_copy

        rendered_services[svc_key] = _escape_compose_dollars(out_svc)

    return {
        "services": rendered_services,
        "networks": {"app_net": {"driver": "bridge"}},
    }


def ensure_real_directory(dir_path: str, label: str) -> str:
    if not os.path.exists(dir_path):
        raise BridgeRequestError(500, f"{label} directory does not exist: {dir_path}")
    if os.path.islink(dir_path) or not os.path.isdir(dir_path):
        raise BridgeRequestError(
            400, f"Security boundary violation: {label} must be a real directory."
        )
    return os.path.realpath(dir_path)


def resolve_scoped_app_dir(
    apps_root: str, slug: str, *, require_exists: bool = True
) -> str:
    safe_slug = validate_slug(slug)
    real_root = ensure_real_directory(apps_root, "appsRoot")
    candidate = os.path.join(real_root, safe_slug)
    if not os.path.lexists(candidate):
        if require_exists:
            raise BridgeRequestError(
                404, f'App workspace "{safe_slug}" does not exist.'
            )
        return candidate
    if os.path.islink(candidate) or not os.path.isdir(candidate):
        raise BridgeRequestError(
            400,
            f'Security boundary violation: workspace "{safe_slug}" is not a real directory.',
        )
    real_candidate = os.path.realpath(candidate)
    if real_candidate != os.path.join(real_root, safe_slug):
        raise BridgeRequestError(
            400,
            f'Security boundary violation: workspace "{safe_slug}" escapes appsRoot.',
        )
    return real_candidate


def parse_compose_ps_output(raw_stdout: str) -> list[dict[str, Any]]:
    text = raw_stdout.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        except json.JSONDecodeError:
            return []
    items: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                items.append(obj)
        except json.JSONDecodeError:
            continue
    return items


def derive_app_status(containers: list[dict[str, Any]]) -> str:
    if not containers:
        return "stopped"
    has_running = False
    for entry in containers:
        state = str(entry.get("State", "")).strip().lower()
        health = str(entry.get("Health", "")).strip().lower()
        exit_code = entry.get("ExitCode", 0)
        if state in ("restarting", "dead") or health == "unhealthy":
            return "error"
        if (
            state == "exited"
            and isinstance(exit_code, int)
            and exit_code not in (0, 143)
        ):
            return "error"
        if state == "running":
            has_running = True
    return "running" if has_running else "stopped"


def _extract_domains_from_caddy_text(text: str) -> set[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("{"):
            host = line[:-1].strip().lower()
            if DOMAIN_PATTERN.match(host):
                domains.add(host)
    return domains


def collect_host_stats(disk_mount: str = "/") -> dict[str, Any]:
    """Collects host CPU, RAM, uptime, and disk metrics using Python stdlib only."""
    uptime_seconds = 0.0
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            uptime_seconds = max(0.0, float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        uptime_seconds = 0.0

    load_1m = 0.0
    if hasattr(os, "getloadavg"):
        try:
            load_1m = max(0.0, round(float(os.getloadavg()[0]), 2))
        except OSError:
            load_1m = 0.0

    mem_total_kb = 0
    mem_avail_kb = 0
    try:
        meminfo: dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val_tokens = parts[1].strip().split()
                    if val_tokens and val_tokens[0].isdigit():
                        meminfo[key] = int(val_tokens[0])
        mem_total_kb = meminfo.get("MemTotal", 0)
        if "MemAvailable" in meminfo:
            mem_avail_kb = meminfo["MemAvailable"]
        else:
            mem_avail_kb = (
                meminfo.get("MemFree", 0)
                + meminfo.get("Buffers", 0)
                + meminfo.get("Cached", 0)
            )
    except OSError:
        mem_total_kb = 0
        mem_avail_kb = 0

    mem_total_mb = round(mem_total_kb / 1024.0, 1)
    mem_used_mb = round(max(0, mem_total_kb - mem_avail_kb) / 1024.0, 1)
    mem_pct = (
        round(min(100.0, max(0.0, (mem_used_mb / mem_total_mb) * 100.0)), 1)
        if mem_total_mb > 0
        else 0.0
    )

    mount_target = disk_mount if os.path.exists(disk_mount) else "/"
    usage = shutil.disk_usage(mount_target)
    total_gb = round(usage.total / (1024.0**3), 2)
    used_gb = round(usage.used / (1024.0**3), 2)
    free_gb = round(usage.free / (1024.0**3), 2)
    used_pct = (
        round(min(100.0, max(0.0, (usage.used / usage.total) * 100.0)), 1)
        if usage.total > 0
        else 0.0
    )

    return {
        "metrics": {
            "hostname": socket.gethostname(),
            "platform": f"{platform.system().lower()}-{platform.machine()}",
            "uptimeSeconds": round(uptime_seconds, 1),
            "cpuCount": max(1, os.cpu_count() or 1),
            "loadAverage1m": load_1m,
            "memoryTotalMb": mem_total_mb,
            "memoryUsedMb": mem_used_mb,
            "memoryUsagePercent": mem_pct,
            "collectedAt": datetime.now(timezone.utc).isoformat(),
        },
        "disk": {
            "totalGb": total_gb,
            "usedGb": used_gb,
            "freeGb": free_gb,
            "usedPercent": used_pct,
            "mount": mount_target,
        },
    }


class _SlugLockEntry:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.refs = 0


def _dockerfile_needs_git_dir(dockerfile_path: str) -> bool:
    """Return True only if a repository-supplied Dockerfile explicitly invokes git or copies .git."""
    try:
        with open(dockerfile_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read(65536)
    except OSError:
        return False
    lines = [line for line in raw.splitlines() if not line.lstrip().startswith("#")]
    unfolded = re.sub(r"\\\s*\n", " ", "\n".join(lines))
    for line in unfolded.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        upper = stripped.upper()
        if upper.startswith(("RUN ", "RUN\t", "RUN[")):
            if re.search(r"(?<![.\w/-])git(?=\s|\"|'|$)", stripped) or re.search(
                r"(?:^|[\s/\"'])\.git(?:/|\s|\"|'|$)", stripped
            ):
                return True
        elif upper.startswith(("COPY ", "COPY\t", "COPY[", "ADD ", "ADD\t", "ADD[")):
            if re.search(r"(?:^|[\s/\"'])\.git(?:/|\s|\"|'|$)", stripped):
                return True
    return False


def _strip_git_metadata_dir(clone_dir: str) -> None:
    git_meta_dir = os.path.join(clone_dir, ".git")
    if not os.path.lexists(git_meta_dir):
        return
    if os.path.isdir(git_meta_dir) and not os.path.islink(git_meta_dir):
        shutil.rmtree(git_meta_dir, ignore_errors=True)
    else:
        try:
            os.unlink(git_meta_dir)
        except OSError:
            pass


def normalize_version_label(raw: str | None) -> str | None:
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    if len(cleaned) >= 2 and cleaned[0] in ("v", "V") and cleaned[1].isdigit():
        return cleaned[1:]
    return cleaned


def parse_semver(
    raw: str | None,
) -> tuple[int, int, int, tuple[tuple[int, int | str], ...]] | None:
    if not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned:
        return None
    match = SEMVER_PATTERN.match(cleaned)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3))
    pre_raw = match.group(4)
    if not pre_raw:
        return (major, minor, patch, ())
    pre_parts: list[tuple[int, int | str]] = []
    for ident in pre_raw.split("."):
        if ident.isdigit():
            pre_parts.append((0, int(ident)))
        else:
            pre_parts.append((1, ident))
    return (major, minor, patch, tuple(pre_parts))


def compare_versions(a: str | None, b: str | None) -> int | None:
    pa = parse_semver(a)
    pb = parse_semver(b)
    if pa is None or pb is None:
        return None
    core_a = pa[:3]
    core_b = pb[:3]
    if core_a < core_b:
        return -1
    if core_a > core_b:
        return 1
    pre_a = pa[3]
    pre_b = pb[3]
    if not pre_a and not pre_b:
        return 0
    if not pre_a:
        return 1
    if not pre_b:
        return -1
    for item_a, item_b in zip(pre_a, pre_b):
        if item_a < item_b:
            return -1
        if item_a > item_b:
            return 1
    if len(pre_a) < len(pre_b):
        return -1
    if len(pre_a) > len(pre_b):
        return 1
    return 0


def is_release_newer(
    current_version: str | None,
    latest_tag: str | None,
    *,
    current_release_tag: str | None = None,
) -> bool:
    if not isinstance(latest_tag, str) or not latest_tag.strip():
        return False
    latest = latest_tag.strip()
    cur_tag = (
        current_release_tag.strip()
        if isinstance(current_release_tag, str) and current_release_tag.strip()
        else None
    )
    if cur_tag and cur_tag == latest:
        return False
    cur_candidate = (
        cur_tag
        if cur_tag and parse_semver(cur_tag) is not None
        else current_version
    )
    cmp_val = compare_versions(cur_candidate, latest)
    if cmp_val is not None:
        return cmp_val < 0
    cur_norm = normalize_version_label(cur_candidate)
    lat_norm = normalize_version_label(latest)
    if not cur_norm:
        return bool(lat_norm)
    return cur_norm != lat_norm


def is_release_older(
    current_version: str | None,
    target_tag: str | None,
    *,
    current_release_tag: str | None = None,
) -> bool:
    if not isinstance(target_tag, str) or not target_tag.strip():
        return False
    target = target_tag.strip()
    cur_tag = (
        current_release_tag.strip()
        if isinstance(current_release_tag, str) and current_release_tag.strip()
        else None
    )
    if cur_tag and cur_tag == target:
        return False
    cur_candidate = (
        cur_tag
        if cur_tag and parse_semver(cur_tag) is not None
        else current_version
    )
    cmp_val = compare_versions(cur_candidate, target)
    if cmp_val is None:
        return False
    return cmp_val > 0


def parse_sha256_checksum(
    text: str, asset_name: str, *, allow_bare_hash: bool = False
) -> str | None:
    if not isinstance(text, str) or not asset_name:
        return None
    target_name = asset_name.strip()
    target_base = os.path.basename(target_name)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m_gnu = re.match(r"^([0-9a-fA-F]{64})\s+[* ]?(.+?)$", line)
        if m_gnu:
            digest = m_gnu.group(1).lower()
            cand = m_gnu.group(2).strip()
            if cand.startswith("./"):
                cand = cand[2:]
            if cand == target_name or os.path.basename(cand) == target_base:
                return digest
            continue
        m_bsd = re.match(
            r"^SHA256\s*\((.+?)\)\s*=\s*([0-9a-fA-F]{64})$",
            line,
            re.IGNORECASE,
        )
        if m_bsd:
            cand = m_bsd.group(1).strip()
            if cand.startswith("./"):
                cand = cand[2:]
            if cand == target_name or os.path.basename(cand) == target_base:
                return m_bsd.group(2).lower()
    if allow_bare_hash:
        stripped = text.strip()
        if SHA256_HEX_PATTERN.match(stripped):
            return stripped.lower()
    return None


def safe_extract_release_tarball(archive_path: str, dest_dir: str) -> dict[str, Any]:
    """
    Safely extracts a VPSAgent release `.tar.gz` archive into `dest_dir`.
    Rejects symlinks, hardlinks, device nodes, FIFOs, `..` traversal, absolute
    paths, and oversized archives, strips a single common wrapper directory if
    present, and validates core VPSAgent manifest & bootstrap files.
    """
    os.makedirs(dest_dir, mode=0o750, exist_ok=True)
    real_dest = os.path.realpath(dest_dir)
    if not os.path.isdir(real_dest):
        raise RuntimeError(f"Release destination is not a directory: {dest_dir}")

    validated_entries: list[tuple[tarfile.TarInfo, list[str]]] = []
    total_bytes = 0

    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            members = tf.getmembers()
            if len(members) > MAX_RELEASE_EXTRACT_MEMBERS:
                raise RuntimeError(
                    f"Release archive contains too many entries ({len(members)})."
                )
            for member in members:
                if (
                    member.type == getattr(tarfile, "XGLTYPE", b"g")
                    or member.name == "pax_global_header"
                ):
                    continue
                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                    or member.ischr()
                    or member.isblk()
                    or not (member.isdir() or member.isfile())
                ):
                    raise RuntimeError(
                        f'Release archive contains unsupported entry type for "{member.name}".'
                    )
                raw_name = member.name
                if (
                    not raw_name
                    or "\x00" in raw_name
                    or "\\" in raw_name
                    or raw_name.startswith("/")
                ):
                    raise RuntimeError(
                        f'Release archive contains unsafe path "{raw_name}".'
                    )
                stripped = raw_name.rstrip("/")
                while stripped.startswith("./"):
                    stripped = stripped[2:]
                if not stripped or stripped == ".":
                    continue
                parts = stripped.split("/")
                if any(part in ("", ".", "..") for part in parts):
                    raise RuntimeError(
                        f'Release archive contains unsafe path segment in "{raw_name}".'
                    )
                if member.isfile():
                    if member.size < 0:
                        raise RuntimeError("Release archive contains invalid file size.")
                    total_bytes += member.size
                    if total_bytes > MAX_RELEASE_EXTRACT_BYTES:
                        raise RuntimeError(
                            "Release archive uncompressed size exceeds safety limit."
                        )
                validated_entries.append((member, parts))

            if not validated_entries:
                raise RuntimeError("Release archive is empty.")

            first_parts = {parts[0] for _, parts in validated_entries}
            strip_prefix = len(first_parts) == 1 and any(
                len(parts) > 1 for _, parts in validated_entries
            )

            extracted_bytes = 0
            for member, parts in validated_entries:
                rel_parts = parts[1:] if strip_prefix else parts
                if not rel_parts:
                    continue
                target_path = os.path.join(real_dest, *rel_parts)
                # Walk every component to confirm no symlinks exist along target path
                walk = real_dest
                for seg in rel_parts[:-1]:
                    walk = os.path.join(walk, seg)
                    if os.path.islink(walk):
                        raise RuntimeError(
                            f'Refused symlink directory "{walk}" during release extraction.'
                        )
                    if not os.path.exists(walk):
                        os.makedirs(walk, mode=0o755, exist_ok=True)
                if os.path.islink(target_path):
                    raise RuntimeError(
                        f'Refused symlink target "{target_path}" during release extraction.'
                    )
                real_target = os.path.realpath(os.path.dirname(target_path))
                if real_target != real_dest and not real_target.startswith(
                    real_dest + os.sep
                ):
                    raise RuntimeError(
                        f'Release entry "{member.name}" escapes destination directory.'
                    )

                if member.isdir():
                    os.makedirs(target_path, mode=0o755, exist_ok=True)
                    continue

                src_stream = tf.extractfile(member)
                if src_stream is None:
                    raise RuntimeError(
                        f'Could not read "{member.name}" from release archive.'
                    )
                with src_stream, open(target_path, "wb") as dst_fh:
                    remaining = member.size
                    while True:
                        chunk = src_stream.read(65536)
                        if not chunk:
                            break
                        extracted_bytes += len(chunk)
                        if extracted_bytes > MAX_RELEASE_EXTRACT_BYTES:
                            raise RuntimeError(
                                "Release archive uncompressed size exceeds safety limit."
                            )
                        remaining -= len(chunk)
                        dst_fh.write(chunk)
                safe_mode = 0o755 if (member.mode & 0o111) else 0o644
                os.chmod(target_path, safe_mode)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise RuntimeError(
            f"Could not extract release archive cleanly: {redact_secrets(str(exc))}"
        ) from exc

    required_files = (
        "package.json",
        os.path.join("bootstrap", "Dockerfile"),
        os.path.join("bootstrap", "docker-compose.core.yml"),
        os.path.join("bootstrap", "Caddyfile"),
        os.path.join("bootstrap", "runtime-bridge.py"),
    )
    for rel in required_files:
        candidate = os.path.join(real_dest, rel)
        if os.path.islink(candidate) or not os.path.isfile(candidate):
            raise RuntimeError(
                f'Release archive is missing required file "{rel}".'
            )

    pkg_text = _read_regular_file_nofollow(
        os.path.join(real_dest, "package.json"), 128 * 1024, "package.json"
    )
    try:
        pkg_json = json.loads(pkg_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Release package.json is not valid JSON.") from exc
    if not isinstance(pkg_json, dict) or pkg_json.get("name") != "vpsagent":
        raise RuntimeError("Release archive does not appear to be VPSAgent.")
    raw_ver = pkg_json.get("version")
    version = raw_ver.strip() if isinstance(raw_ver, str) and raw_ver.strip() else None
    return {"version": version}


def _active_source_path(vpsagent_root: str) -> str:
    return os.path.join(vpsagent_root, ACTIVE_SOURCE_FILENAME)


def _read_active_source_file(vpsagent_root: str) -> dict[str, Any] | None:
    if not vpsagent_root or not os.path.isdir(vpsagent_root):
        return None
    path = _active_source_path(vpsagent_root)
    if not os.path.lexists(path):
        return None
    try:
        raw = _read_regular_file_nofollow(
            path, MAX_ACTIVE_SOURCE_BYTES, ACTIVE_SOURCE_FILENAME
        )
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except (BridgeRequestError, OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _write_active_source_file(
    vpsagent_root: str,
    repo_dir: str,
    *,
    release_tag: str | None = None,
    release_repo: str | None = None,
) -> None:
    if not isinstance(repo_dir, str) or not repo_dir.strip():
        raise ValueError("Active source repoDir cannot be empty.")
    clean_repo = os.path.abspath(repo_dir.strip())
    if any(ch in clean_repo for ch in ("\r", "\n", "\x00")):
        raise ValueError("Active source repoDir contains invalid characters.")
    path = _active_source_path(vpsagent_root)
    if os.path.islink(path):
        raise RuntimeError(f"Security boundary violation: {path} cannot be a symlink.")
    payload: dict[str, Any] = {
        "repoDir": clean_repo,
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    if isinstance(release_tag, str) and release_tag.strip():
        payload["releaseTag"] = release_tag.strip()
    if isinstance(release_repo, str) and RELEASE_REPO_PATTERN.match(release_repo.strip()):
        payload["releaseRepo"] = release_repo.strip()
    parent = os.path.dirname(os.path.abspath(path))
    tmp_path = os.path.join(parent, f".{ACTIVE_SOURCE_FILENAME}.tmp.{os.getpid()}")
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.lexists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        pinned_ips: list[str],
        timeout: float,
    ) -> None:
        super().__init__(
            host,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._pinned_ips = list(pinned_ips)

    def connect(self) -> None:
        last_err: OSError | None = None
        for ip in self._pinned_ips:
            raw_sock = None
            try:
                _assert_public_ip_address(ip, self.host)
                raw_sock = socket.create_connection(
                    (ip, self.port), self.timeout, self.source_address
                )
                self.sock = self._context.wrap_socket(
                    raw_sock, server_hostname=self.host
                )
                return
            except (OSError, BridgeRequestError) as exc:
                last_err = exc if isinstance(exc, OSError) else OSError(str(exc))
                if raw_sock is not None:
                    try:
                        raw_sock.close()
                    except OSError:
                        pass
        if last_err is not None:
            raise last_err
        raise OSError(f"No reachable IP address for {self.host}")


class RuntimeService:
    def __init__(
        self,
        *,
        apps_root: str,
        caddy_apps_dir: str,
        caddy_core_dir: str | None = None,
        caddy_container: str,
        docker_bin: str = "docker",
        git_bin: str = "git",
        systemctl_bin: str = "systemctl",
        tailscale_bin: str = "tailscale",
        tailscale_target_url: str | None = None,
        tailscale_target_checker: Callable[[str, int], bool] | None = None,
        vpsagent_root: str | None = None,
        repo_dir: str | None = None,
        release_repo: str | None = None,
        release_api_base: str | None = None,
        release_github_token: str | None = None,
        runtime_token: str | None = None,
        allow_unauthenticated: bool = False,
        status_deadline_s: float = DEFAULT_STATUS_DEADLINE_S,
        health_interval_s: float = DEFAULT_HEALTH_INTERVAL_S,
        health_retries: int = DEFAULT_HEALTH_RETRIES,
        dns_resolver: DnsResolver | None = None,
        tls_checker: TlsChecker | None = None,
        allowed_file_roots: list[str] | None = None,
    ) -> None:
        if not CONTAINER_NAME_PATTERN.match(caddy_container):
            raise ValueError(f"Invalid caddy container name: {caddy_container}")
        if not docker_bin or any(ch.isspace() for ch in docker_bin):
            raise ValueError("Invalid docker binary path.")
        if not git_bin or any(ch.isspace() for ch in git_bin):
            raise ValueError("Invalid git binary path.")
        if not systemctl_bin or any(ch.isspace() for ch in systemctl_bin):
            raise ValueError("Invalid systemctl binary path.")
        if not tailscale_bin or any(ch.isspace() for ch in tailscale_bin):
            raise ValueError("Invalid tailscale binary path.")
        cleaned_token = (runtime_token or "").strip() or None
        if not cleaned_token and not allow_unauthenticated:
            raise ValueError(
                "RuntimeService requires runtime_token unless allow_unauthenticated=True."
            )
        self.apps_root = apps_root
        self.caddy_apps_dir = caddy_apps_dir
        self.caddy_core_dir = caddy_core_dir or os.path.join(
            os.path.dirname(os.path.abspath(caddy_apps_dir)), "core.d"
        )
        self.caddy_container = caddy_container
        self.docker_bin = docker_bin
        self.git_bin = git_bin
        self.systemctl_bin = systemctl_bin
        raw_ts_target = (
            tailscale_target_url
            if isinstance(tailscale_target_url, str) and tailscale_target_url.strip()
            else os.environ.get(
                "VPSAGENT_TAILSCALE_TARGET_URL", DEFAULT_TAILSCALE_TARGET_URL
            )
        )
        normalized_ts_target, ts_host, ts_port = _validate_tailscale_target_url(
            raw_ts_target
        )
        self.tailscale_bin = tailscale_bin
        self.tailscale_target_url = normalized_ts_target
        self._tailscale_target_host = ts_host
        self._tailscale_target_port = ts_port
        self._tailscale_target_checker = (
            tailscale_target_checker or _default_loopback_port_checker
        )
        self._tailscale_lock = threading.Lock()
        if vpsagent_root:
            self.vpsagent_root = os.path.abspath(vpsagent_root)
        else:
            env_root = os.environ.get("VPSAGENT_ROOT", "").strip()
            if env_root:
                self.vpsagent_root = os.path.abspath(env_root)
            elif os.path.basename(os.path.abspath(apps_root)) == "apps":
                self.vpsagent_root = os.path.dirname(os.path.abspath(apps_root))
            else:
                self.vpsagent_root = "/var/lib/vpsagent"
        active_source = _read_active_source_file(self.vpsagent_root)
        active_repo_raw = (
            active_source.get("repoDir")
            if active_source and isinstance(active_source.get("repoDir"), str)
            else ""
        ).strip()
        active_repo = (
            active_repo_raw
            if active_repo_raw and os.path.isdir(active_repo_raw)
            else ""
        )

        resolved_repo = (
            repo_dir.strip()
            if isinstance(repo_dir, str) and repo_dir.strip()
            else active_repo or os.environ.get("VPSAGENT_REPO_DIR", "").strip()
        )
        if not resolved_repo and os.path.isdir("/opt/vpsagent/.git"):
            resolved_repo = "/opt/vpsagent"
        self.repo_dir = os.path.abspath(resolved_repo) if resolved_repo else None
        active_release_repo = (
            active_source.get("releaseRepo")
            if active_source and isinstance(active_source.get("releaseRepo"), str)
            else ""
        ).strip()
        raw_release_repo = (
            release_repo.strip()
            if release_repo is not None
            else os.environ.get("VPSAGENT_RELEASE_REPO", "").strip()
        )
        if (
            not raw_release_repo
            and release_repo is None
            and RELEASE_REPO_PATTERN.match(active_release_repo)
        ):
            raw_release_repo = active_release_repo
        if raw_release_repo and not RELEASE_REPO_PATTERN.match(raw_release_repo):
            raise ValueError(f"Invalid release repository slug: {raw_release_repo}")
        self.release_repo: str | None = raw_release_repo or None

        raw_api_base = (
            release_api_base.strip()
            if release_api_base is not None
            else os.environ.get("VPSAGENT_RELEASE_API_BASE", "").strip()
        ) or DEFAULT_GITHUB_API_BASE
        raw_api_base = raw_api_base.rstrip("/")
        parsed_api = urlparse(raw_api_base)
        api_scheme = parsed_api.scheme.lower()
        api_host = (parsed_api.hostname or "").lower().strip("[]").rstrip(".")
        is_loopback_api = api_host in ("127.0.0.1", "localhost", "::1")
        if not api_host or (api_scheme != "https" and not (is_loopback_api and api_scheme == "http")):
            raise ValueError(f"Invalid release API base URL: {raw_api_base}")
        self.release_api_base = raw_api_base
        self._allow_loopback_release_api = is_loopback_api

        raw_gh_token = (
            release_github_token.strip()
            if release_github_token is not None
            else os.environ.get("VPSAGENT_RELEASE_GITHUB_TOKEN", "").strip()
        )
        self.release_github_token: str | None = raw_gh_token or None
        self.runtime_token = cleaned_token
        self.allow_unauthenticated = allow_unauthenticated
        self.status_deadline_s = max(0.2, float(status_deadline_s))
        self.health_interval_s = max(0.2, float(health_interval_s))
        self.health_retries = max(1, int(health_retries))
        self.dns_resolver = dns_resolver
        self.tls_checker = tls_checker or default_tls_checker
        if allowed_file_roots is not None:
            raw_roots = allowed_file_roots
        else:
            env_roots = os.environ.get("VPSAGENT_ALLOWED_FILE_ROOTS", "").strip()
            raw_roots = (
                [p.strip() for p in env_roots.split(":") if p.strip()]
                if env_roots
                else [apps_root, "/srv", "/opt/apps", "/tmp/vpsagent-work"]
            )
        self.allowed_file_roots: list[str] = [
            os.path.realpath(r) for r in raw_roots if os.path.isabs(r)
        ]
        self._locks_guard = threading.Lock()
        self._slug_locks: dict[str, _SlugLockEntry] = {}
        self._caddy_lock = threading.Lock()
        self._host_health_lock = threading.Lock()
        self._host_health: dict[str, dict[str, Any]] = {}
        self._health_stop_event = threading.Event()
        self._health_thread: threading.Thread | None = None
        self._update_lock = threading.Lock()
        self._update_status_file = os.path.join(
            self.vpsagent_root, "run", "update-status.json"
        )
        self._update_state: dict[str, Any] = self._load_persisted_update_state()

    def _read_app_probe_config(self, app_dir: str, slug: str) -> dict[str, Any] | None:
        probe_file = os.path.join(app_dir, "probe.json")
        if not os.path.lexists(probe_file):
            return None
        try:
            raw_text = _read_regular_file_nofollow(
                probe_file, MAX_PROBE_CONFIG_BYTES, f'probe.json for "{slug}"'
            )
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                return None
            probe_http = data.get("probeHttp")
            if not isinstance(probe_http, bool):
                return None
            internal_port = validate_port(data.get("internalPort"))
            probe_path = validate_probe_path(data.get("probePath"))
            return {
                "probeHttp": probe_http,
                "internalPort": internal_port,
                "probePath": probe_path,
            }
        except (BridgeRequestError, json.JSONDecodeError, ValueError, TypeError):
            return None

    def _clear_host_health(self, slug: str) -> None:
        with self._host_health_lock:
            self._host_health.pop(slug, None)

    def _get_host_health(self, slug: str) -> dict[str, Any] | None:
        with self._host_health_lock:
            entry = self._host_health.get(slug)
            return dict(entry) if entry is not None else None

    def _resolve_overall_status(self, slug: str, docker_status: str) -> str:
        """
        Single source of truth for overall app status shared by the Apps list
        (`/v1/apps/statuses`), lifecycle status, and Safety Check (`/v1/apps/inspect`).
        """
        if docker_status == "running":
            app_dir = resolve_scoped_app_dir(
                self.apps_root, slug, require_exists=False
            )
            probe_cfg = (
                self._read_app_probe_config(app_dir, slug)
                if os.path.isdir(app_dir)
                else None
            )
            if probe_cfg is not None and not probe_cfg["probeHttp"]:
                self._clear_host_health(slug)
                return docker_status
            host_health = self._get_host_health(slug)
            if host_health is not None and host_health.get("status") == "unhealthy":
                return "error"
        return docker_status

    def _record_host_health(
        self, slug: str, probe_path: str, probe_result: dict[str, Any]
    ) -> dict[str, Any]:
        code = probe_result.get("statusCode")
        is_ok = bool(probe_result.get("ok")) or (
            isinstance(code, int) and 100 <= code < 500
        )
        now = time.time()
        with self._host_health_lock:
            prev = self._host_health.get(slug) or {}
            if is_ok:
                entry = {
                    "status": "healthy",
                    "consecutiveFailures": 0,
                    "lastCheckedAt": now,
                    "lastOutput": redact_secrets(
                        f"Host HTTP probe GET {probe_path} -> {code}"
                    )[:300],
                }
            else:
                failures = int(prev.get("consecutiveFailures", 0)) + 1
                detail = probe_result.get("error") or f"HTTP {code}"
                prev_status = str(prev.get("status") or "starting")
                new_status = (
                    "unhealthy" if failures >= self.health_retries else prev_status
                )
                entry = {
                    "status": new_status,
                    "consecutiveFailures": failures,
                    "lastCheckedAt": now,
                    "lastOutput": redact_secrets(
                        f"Host HTTP probe GET {probe_path} failed "
                        f"({failures}/{self.health_retries}): {detail}"
                    )[:300],
                }
            self._host_health[slug] = entry
            return dict(entry)

    def run_recurring_health_check_once(self, slug: str) -> dict[str, Any] | None:
        """
        Runs one host-side HTTP health probe for an app configured via `probe.json`.
        Works identically for minimal/distroless/scratch images with no in-container tools.
        """
        safe_slug = validate_slug(slug)
        app_dir = resolve_scoped_app_dir(self.apps_root, safe_slug, require_exists=False)
        if not os.path.isdir(app_dir):
            self._clear_host_health(safe_slug)
            return None
        cfg = self._read_app_probe_config(app_dir, safe_slug)
        if cfg is None or not cfg["probeHttp"]:
            self._clear_host_health(safe_slug)
            return None

        inspected = self.inspect_workload(
            {
                "slug": safe_slug,
                "probeHttp": True,
                "internalPort": cfg["internalPort"],
                "probePath": cfg["probePath"],
            },
            timeout_budget_s=min(10.0, self.status_deadline_s),
            _apply_host_health=False,
        )
        containers = inspected.get("containers") or []
        primary = self._select_primary_container(safe_slug, containers)
        if primary is None or not primary.get("running"):
            self._clear_host_health(safe_slug)
            return None

        probe_result = inspected.get("httpProbe") or {
            "attempted": False,
            "ok": False,
            "statusCode": None,
            "error": "No HTTP probe result.",
        }
        return self._record_host_health(safe_slug, cfg["probePath"], probe_result)

    def run_recurring_health_sweep(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        if not os.path.isdir(self.apps_root):
            return results
        try:
            entries = sorted(os.listdir(self.apps_root))
        except OSError:
            return results
        for name in entries:
            if not SLUG_PATTERN.match(name):
                continue
            app_dir = os.path.join(self.apps_root, name)
            if os.path.islink(app_dir) or not os.path.isdir(app_dir):
                continue
            if not os.path.lexists(os.path.join(app_dir, "probe.json")):
                continue
            try:
                res = self.run_recurring_health_check_once(name)
                if res is not None:
                    results[name] = res
            except (BridgeRequestError, OSError):
                continue
        return results

    def start_health_monitor(self) -> None:
        if self._health_thread is not None and self._health_thread.is_alive():
            return
        self._health_stop_event.clear()

        def _loop() -> None:
            while not self._health_stop_event.wait(self.health_interval_s):
                try:
                    self.run_recurring_health_sweep()
                except Exception:
                    continue

        self._health_thread = threading.Thread(
            target=_loop, name="vpsagent-host-health-monitor", daemon=True
        )
        self._health_thread.start()

    def stop_health_monitor(self) -> None:
        self._health_stop_event.set()
        if self._health_thread is not None and self._health_thread.is_alive():
            self._health_thread.join(timeout=2.0)
        self._health_thread = None

    @contextmanager
    def _lock_for(self, slug: str) -> Iterator[None]:
        with self._locks_guard:
            entry = self._slug_locks.get(slug)
            if entry is None:
                entry = _SlugLockEntry()
                self._slug_locks[slug] = entry
            entry.refs += 1
        try:
            entry.lock.acquire()
            try:
                yield
            finally:
                entry.lock.release()
        finally:
            with self._locks_guard:
                entry.refs -= 1
                if entry.refs == 0:
                    self._slug_locks.pop(slug, None)

    @contextmanager
    def _validated_compose_context(
        self, app_dir: str, slug: str, *, prepare_volumes: bool = False
    ) -> Iterator[tuple[str, str]]:
        """
        Reads `.env` and `docker-compose.yml` with O_NOFOLLOW, structurally
        validates every field, resolves only allowlisted interpolation variables,
        and writes canonical validated copies into a root-owned 0700 temporary
        directory. The container env file is named `app.env` (never `.env`) and
        Docker Compose uses `tmp_dir` as `--project-directory` with NO `--env-file`
        so Compose can never implicitly rediscover or interpolate app secrets.
        """
        compose_path = os.path.join(app_dir, "docker-compose.yml")
        compose_text = _read_regular_file_nofollow(
            compose_path, MAX_COMPOSE_BYTES, f'docker-compose.yml for "{slug}"'
        )
        env_path = os.path.join(app_dir, ".env")
        env_text: str | None = None
        env_map: dict[str, str] = {}
        if os.path.lexists(env_path):
            env_text = _read_regular_file_nofollow(
                env_path, MAX_ENV_BYTES, f'.env for "{slug}"'
            )
            env_map = parse_and_validate_env_file(env_text, slug)

        tmp_dir = tempfile.mkdtemp(prefix=f"vpsagent-{slug}-")
        os.chmod(tmp_dir, 0o700)
        try:
            rendered_doc = validate_and_render_compose(
                compose_text,
                slug,
                app_dir,
                env_map,
                None,
                prepare_volumes=prepare_volumes,
            )
            tmp_compose_path = os.path.join(tmp_dir, "docker-compose.json")
            with open(tmp_compose_path, "w", encoding="utf-8") as fh:
                json.dump(rendered_doc, fh, indent=2)
            os.chmod(tmp_compose_path, 0o600)
            yield tmp_compose_path, tmp_dir
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _run_cmd(
        self,
        cmd: list[str],
        *,
        label: str,
        timeout: float = 120,
        check: bool = True,
        cwd: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                shell=False,
                env=_sanitized_subprocess_env(extra_env),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise BridgeRequestError(
                503, f"{label} CLI binary not found ({cmd[0]})."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise BridgeRequestError(
                504, f"{label} command timed out after {int(timeout)}s."
            ) from exc

        if check and proc.returncode != 0:
            detail = (
                proc.stderr or proc.stdout or f"exit code {proc.returncode}"
            ).strip()
            raise BridgeRequestError(502, redact_secrets(detail))
        return proc

    def _run_docker(
        self,
        args: list[str],
        *,
        timeout: float = 120,
        check: bool = True,
        cwd: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_cmd(
            [self.docker_bin, *args],
            label="Docker",
            timeout=timeout,
            check=check,
            cwd=cwd,
        )

    def _run_git(
        self,
        args: list[str],
        *,
        timeout: float = 120,
        check: bool = True,
        cwd: str | None = None,
        extra_env: dict[str, str] | None = None,
        secret_values: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "https",
        }
        if extra_env:
            env.update(extra_env)
        try:
            return self._run_cmd(
                [self.git_bin, *args],
                label="Git",
                timeout=timeout,
                check=check,
                cwd=cwd,
                extra_env=env,
            )
        except BridgeRequestError as exc:
            raise BridgeRequestError(
                exc.status_code,
                _scrub_secret_values(str(exc), secret_values),
            ) from exc

    def _compose_down_by_project(self, slug: str) -> None:
        with tempfile.TemporaryDirectory(
            prefix=f"vpsagent-down-{slug}-"
        ) as empty_cwd:
            self._run_docker(
                ["compose", "-p", f"vpsagent-{slug}", "down", "--remove-orphans"],
                timeout=60,
                check=True,
                cwd=empty_cwd,
            )

    def _compose_cmd_base(
        self, slug: str, project_dir: str, compose_path: str
    ) -> list[str]:
        return [
            "compose",
            "-p",
            f"vpsagent-{slug}",
            "--project-directory",
            project_dir,
            "-f",
            compose_path,
        ]

    def _compose_status(
        self, slug: str, project_dir: str, compose_path: str
    ) -> str:
        proc = self._run_docker(
            [
                *self._compose_cmd_base(slug, project_dir, compose_path),
                "ps",
                "-a",
                "--format",
                "json",
            ],
            timeout=20,
            check=False,
        )
        if proc.returncode != 0:
            return "error"
        return derive_app_status(parse_compose_ps_output(proc.stdout))

    def host_stats(self) -> dict[str, Any]:
        return collect_host_stats("/")

    def lifecycle(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        action = payload.get("action")
        if not isinstance(action, str) or action not in ALLOWED_LIFECYCLE_ACTIONS:
            raise BridgeRequestError(
                400, "Field 'action' must be one of: start, stop, restart, status."
            )

        with self._lock_for(slug):
            app_dir = resolve_scoped_app_dir(self.apps_root, slug)
            with self._validated_compose_context(
                app_dir, slug, prepare_volumes=(action == "start")
            ) as (
                compose_path,
                project_dir,
            ):
                base = self._compose_cmd_base(slug, project_dir, compose_path)
                if action == "start":
                    self._clear_host_health(slug)
                    self._run_docker(
                        [*base, "up", "-d", "--remove-orphans"], timeout=180
                    )
                elif action == "stop":
                    self._clear_host_health(slug)
                    self._run_docker([*base, "stop"], timeout=60)
                elif action == "restart":
                    self._clear_host_health(slug)
                    self._run_docker([*base, "restart"], timeout=90)

                status = self._compose_status(slug, project_dir, compose_path)
                if action == "status":
                    status = self._resolve_overall_status(slug, status)
                return {
                    "slug": slug,
                    "status": status,
                    "detail": f"Workload {slug} {action} -> {status}",
                }

    def _clone_repo(
        self,
        repo_url: str,
        repo_host: str,
        repo_port: int,
        validated_ips: list[str],
        branch: str | None,
        clone_dir: str,
        clone_timeout: float,
        *,
        git_token: str | None = None,
    ) -> tuple[str | None, str | None]:
        parent_dir = os.path.dirname(clone_dir)
        git_cfg_path = os.path.join(
            parent_dir, "git-auth.conf" if git_token else "git-empty.conf"
        )
        secret_values: list[str] = []
        if git_token:
            assert_github_host_for_token(repo_host, repo_port)
            basic_b64 = base64.b64encode(
                f"x-access-token:{git_token}".encode("utf-8")
            ).decode("ascii")
            secret_values = [git_token, basic_b64]
            cfg_content = (
                '[http "https://github.com/"]\n'
                f"\textraHeader = Authorization: Basic {basic_b64}\n"
            )
        else:
            cfg_content = ""

        fd = os.open(git_cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(cfg_content)
        os.chmod(git_cfg_path, 0o600)

        try:
            with _PinnedGitConnectProxy(
                repo_host,
                repo_port,
                validated_ips,
                connect_timeout=min(15.0, clone_timeout),
            ) as proxy:
                clone_args = [
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "-c",
                    "protocol.file.allow=never",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "core.symlinks=false",
                    "-c",
                    f"http.proxy=http://127.0.0.1:{proxy.port}",
                ]
                if branch:
                    clone_args.extend(["--branch", branch])
                clone_args.extend(["--", repo_url, clone_dir])
                self._run_git(
                    clone_args,
                    timeout=clone_timeout,
                    check=True,
                    extra_env={"GIT_CONFIG_GLOBAL": git_cfg_path},
                    secret_values=secret_values,
                )
        except BridgeRequestError as exc:
            scrubbed = _scrub_secret_values(str(exc), secret_values)
            if exc.status_code == 502 and GIT_AUTH_ERROR_RE.search(scrubbed):
                if git_token is None:
                    raise BridgeRequestError(
                        401,
                        "Authentication required: this repository appears to be private or does not exist.",
                    ) from exc
                raise BridgeRequestError(
                    401,
                    "GitHub authentication failed: the access token was rejected for this repository (verify it has not expired and has Read-only Contents permission for this repo).",
                ) from exc
            raise BridgeRequestError(exc.status_code, scrubbed) from exc
        finally:
            try:
                os.unlink(git_cfg_path)
            except FileNotFoundError:
                pass

        rev_proc = self._run_git(
            ["-C", clone_dir, "rev-parse", "HEAD"], timeout=10, check=False
        )
        commit_sha = (
            rev_proc.stdout.strip()[:40]
            if rev_proc.returncode == 0 and rev_proc.stdout.strip()
            else None
        )
        branch_proc = self._run_git(
            ["-C", clone_dir, "rev-parse", "--abbrev-ref", "HEAD"],
            timeout=10,
            check=False,
        )
        resolved_branch = (
            branch_proc.stdout.strip()[:120]
            if branch_proc.returncode == 0
            and branch_proc.stdout.strip()
            and branch_proc.stdout.strip() != "HEAD"
            else branch
        )
        return commit_sha, resolved_branch

    def _clone_public_repo(
        self,
        repo_url: str,
        repo_host: str,
        repo_port: int,
        validated_ips: list[str],
        branch: str | None,
        clone_dir: str,
        clone_timeout: float,
    ) -> tuple[str | None, str | None]:
        return self._clone_repo(
            repo_url,
            repo_host,
            repo_port,
            validated_ips,
            branch,
            clone_dir,
            clone_timeout,
            git_token=None,
        )

    def inspect_git(self, payload: dict[str, Any]) -> dict[str, Any]:
        repo_url, repo_host, repo_port, validated_ips = validate_git_repo_url_with_ips(
            payload.get("gitRepoUrl"), dns_resolver=self.dns_resolver
        )
        git_token = validate_git_token(payload.get("gitToken"))
        if git_token:
            assert_github_host_for_token(repo_host, repo_port)
        branch = validate_git_branch(payload.get("gitBranch"))
        dockerfile_rel = validate_dockerfile_path(payload.get("dockerfilePath"))
        raw_timeout = payload.get("timeoutSeconds", 45)
        if (
            not isinstance(raw_timeout, (int, float))
            or isinstance(raw_timeout, bool)
            or raw_timeout < 5
            or raw_timeout > 120
        ):
            raise BridgeRequestError(
                400, "Field 'timeoutSeconds' must be between 5 and 120."
            )

        build_dir = tempfile.mkdtemp(prefix="vpsagent-inspect-")
        os.chmod(build_dir, 0o700)
        clone_dir = os.path.join(build_dir, "repo")
        try:
            commit_sha, resolved_branch = self._clone_repo(
                repo_url,
                repo_host,
                repo_port,
                validated_ips,
                branch,
                clone_dir,
                float(raw_timeout),
                git_token=git_token,
            )
            info = _inspect_cloned_repo(
                clone_dir, repo_url, resolved_branch, commit_sha, dockerfile_rel
            )
            info.pop("generatedDockerfile", None)
            info["usedAuth"] = bool(git_token)
            return info
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

    def build_git(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        repo_url, repo_host, repo_port, validated_ips = validate_git_repo_url_with_ips(
            payload.get("gitRepoUrl"), dns_resolver=self.dns_resolver
        )
        git_token = validate_git_token(payload.get("gitToken"))
        secret_values: list[str] = []
        if git_token:
            assert_github_host_for_token(repo_host, repo_port)
            basic_b64 = base64.b64encode(
                f"x-access-token:{git_token}".encode("utf-8")
            ).decode("ascii")
            secret_values = [git_token, basic_b64]
        branch = validate_git_branch(payload.get("gitBranch"))
        raw_df = payload.get("dockerfilePath")
        dockerfile_rel = (
            "auto"
            if isinstance(raw_df, str) and raw_df.strip() == "auto"
            else validate_dockerfile_path(raw_df)
        )
        allow_auto_detect = bool(
            payload.get("allowAutoDetect", dockerfile_rel in ("Dockerfile", "auto"))
        )

        raw_timeout = payload.get("timeoutSeconds", DEFAULT_BUILD_TIMEOUT_S)
        if (
            not isinstance(raw_timeout, (int, float))
            or isinstance(raw_timeout, bool)
            or raw_timeout < MIN_BUILD_TIMEOUT_S
            or raw_timeout > MAX_BUILD_TIMEOUT_S
        ):
            raise BridgeRequestError(
                400,
                f"Field 'timeoutSeconds' must be between {MIN_BUILD_TIMEOUT_S} and {MAX_BUILD_TIMEOUT_S}.",
            )
        total_timeout_s = float(raw_timeout)
        raw_previous_mode = payload.get("previousMode", "save")
        if raw_previous_mode not in ("save", "preserve", "clear"):
            raise BridgeRequestError(
                400,
                "Field 'previousMode' must be one of: save, preserve, clear.",
            )
        previous_mode = str(raw_previous_mode)
        image_tag = f"vpsagent-app-{slug}:latest"

        t0 = time.monotonic()
        deadline = t0 + total_timeout_s

        with self._lock_for(slug):
            prev_image_id: str | None = None
            if previous_mode == "clear":
                self._run_docker(
                    ["rmi", "-f", f"vpsagent-app-{slug}:previous"],
                    timeout=15,
                    check=False,
                )
            elif previous_mode == "save":
                prev_proc = self._run_docker(
                    ["image", "inspect", "--format", "{{.Id}}", image_tag],
                    timeout=15,
                    check=False,
                )
                if prev_proc.returncode == 0 and prev_proc.stdout.strip():
                    prev_image_id = prev_proc.stdout.strip().splitlines()[0].strip()

            build_dir = tempfile.mkdtemp(prefix=f"vpsagent-git-{slug}-")
            os.chmod(build_dir, 0o700)
            clone_dir = os.path.join(build_dir, "repo")
            try:
                clone_timeout = max(5.0, min(total_timeout_s * 0.4, 90.0))
                commit_sha, resolved_branch = self._clone_repo(
                    repo_url,
                    repo_host,
                    repo_port,
                    validated_ips,
                    branch,
                    clone_dir,
                    clone_timeout,
                    git_token=git_token,
                )

                inspected = _inspect_cloned_repo(
                    clone_dir, repo_url, resolved_branch, commit_sha, dockerfile_rel
                )
                real_clone_dir = os.path.realpath(clone_dir)
                used_auto_dockerfile = False
                if inspected["hasDockerfile"]:
                    check_rel = "Dockerfile" if dockerfile_rel == "auto" else dockerfile_rel
                    real_dockerfile = os.path.realpath(
                        os.path.join(real_clone_dir, check_rel)
                    )
                elif (
                    allow_auto_detect
                    and dockerfile_rel in ("Dockerfile", "auto")
                    and inspected.get("generatedDockerfile")
                ):
                    auto_df_path = os.path.join(build_dir, "Dockerfile.vpsagent")
                    with open(auto_df_path, "w", encoding="utf-8") as fh:
                        fh.write(str(inspected["generatedDockerfile"]))
                    os.chmod(auto_df_path, 0o600)
                    real_dockerfile = auto_df_path
                    used_auto_dockerfile = True
                else:
                    raise BridgeRequestError(
                        400,
                        f'Dockerfile "{dockerfile_rel}" was not found in repository, and no supported Node, Python, or static web project was detected.',
                    )

                remaining_s = deadline - time.monotonic()
                if remaining_s < 1.0:
                    raise BridgeRequestError(
                        504,
                        f"Git build timed out after {int(total_timeout_s)}s before Docker build.",
                    )

                # Strip .git metadata before docker build so private repo history never leaks into images.
                # Only preserve .git when a repository-supplied Dockerfile explicitly runs git or copies .git.
                if used_auto_dockerfile or not _dockerfile_needs_git_dir(real_dockerfile):
                    _strip_git_metadata_dir(real_clone_dir)

                # For auto-detected static sites without a custom .dockerignore, exclude all dotfiles/dotdirs
                # at every depth (except non-hidden files under root /.well-known) and repo metadata files.
                if used_auto_dockerfile and inspected["detectedRuntime"] == "static":
                    dockerignore_path = os.path.join(real_clone_dir, ".dockerignore")
                    if not os.path.lexists(dockerignore_path):
                        with open(dockerignore_path, "w", encoding="utf-8") as difh:
                            difh.write(
                                "\n".join(
                                    [
                                        ".git",
                                        ".*",
                                        ".*/**",
                                        "**/.*",
                                        "**/.*/**",
                                        "!.well-known",
                                        "!.well-known/**",
                                        ".well-known/.*",
                                        ".well-known/**/.*/**",
                                        ".well-known/**/.*",
                                        "**/.env*",
                                        "*.pem",
                                        "*.key",
                                        "README*",
                                        "LICENSE*",
                                        "Dockerfile*",
                                        "docker-compose*",
                                        "Makefile",
                                        "*.sh",
                                        "*.py",
                                        "",
                                    ]
                                )
                            )
                        os.chmod(dockerignore_path, 0o600)

                build_proc = self._run_docker(
                    [
                        "build",
                        "--label",
                        "vpsagent.managed=true",
                        "--label",
                        f"vpsagent.slug={slug}",
                        "-t",
                        image_tag,
                        "-f",
                        real_dockerfile,
                        real_clone_dir,
                    ],
                    timeout=remaining_s,
                    check=False,
                )
                combined = "\n".join(
                    p for p in (build_proc.stdout, build_proc.stderr) if p
                )
                redacted = _scrub_secret_values(combined, secret_values)
                log_tail = [
                    line[:MAX_LOG_LINE_CHARS]
                    for line in redacted.splitlines()
                    if line.strip()
                ][-MAX_BUILD_LOG_LINES:]

                if build_proc.returncode != 0:
                    err_excerpt = log_tail[-1] if log_tail else "unknown Docker build error"
                    raise BridgeRequestError(
                        502,
                        _scrub_secret_values(
                            f"Docker build failed (exit {build_proc.returncode}): {err_excerpt}",
                            secret_values,
                        ),
                        build_log_tail=log_tail,
                    )

                previous_image_saved = False
                if previous_mode == "save" and prev_image_id:
                    new_proc = self._run_docker(
                        ["image", "inspect", "--format", "{{.Id}}", image_tag],
                        timeout=15,
                        check=False,
                    )
                    new_image_id = (
                        new_proc.stdout.strip().splitlines()[0].strip()
                        if new_proc.returncode == 0 and new_proc.stdout.strip()
                        else ""
                    )
                    if new_image_id and new_image_id != prev_image_id:
                        prev_tag = f"vpsagent-app-{slug}:previous"
                        tag_proc = self._run_docker(
                            ["tag", prev_image_id, prev_tag], timeout=15, check=False
                        )
                        previous_image_saved = tag_proc.returncode == 0

                return {
                    "ok": True,
                    "slug": slug,
                    "image": image_tag,
                    "commitSha": commit_sha,
                    "durationMs": round((time.monotonic() - t0) * 1000, 1),
                    "buildLogTail": log_tail,
                    "detectedRuntime": inspected["detectedRuntime"],
                    "usedAutoDockerfile": used_auto_dockerfile,
                    "usedAuth": bool(git_token),
                    "suggestedPort": inspected["suggestedPort"],
                    "envExampleKeys": [
                        item["key"] for item in inspected["envExampleKeys"]
                    ],
                    "previousImageSaved": previous_image_saved,
                }
            finally:
                shutil.rmtree(build_dir, ignore_errors=True)

    def logs(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        tail = validate_tail(payload.get("tail"))

        app_dir = resolve_scoped_app_dir(self.apps_root, slug)
        with self._validated_compose_context(app_dir, slug) as (
            compose_path,
            project_dir,
        ):
            base = self._compose_cmd_base(slug, project_dir, compose_path)
            proc = self._run_docker(
                [*base, "logs", "--no-color", "--tail", str(tail)],
                timeout=20,
            )
            combined = "\n".join(part for part in (proc.stdout, proc.stderr) if part)
            redacted_blob = redact_secrets(combined)
            truncated = False
            raw_lines: list[str] = []
            for line in redacted_blob.splitlines():
                if not line:
                    continue
                if len(line) > MAX_LOG_LINE_CHARS:
                    raw_lines.append(line[:MAX_LOG_LINE_CHARS])
                    truncated = True
                else:
                    raw_lines.append(line)

            if len(raw_lines) > tail:
                raw_lines = raw_lines[-tail:]

            # Enforce strict UTF-8 JSON byte budget on the finished log list (keeping newest lines)
            kept_reversed: list[str] = []
            used_bytes = 256  # overhead for JSON wrapper
            for line in reversed(raw_lines):
                line_bytes = len(json.dumps(line).encode("utf-8")) + 1
                if used_bytes + line_bytes > MAX_LOGS_RESPONSE_BYTES:
                    truncated = True
                    break
                kept_reversed.append(line)
                used_bytes += line_bytes
            kept_reversed.reverse()
            return {"slug": slug, "lines": kept_reversed, "truncated": truncated}

    def _validate_and_reload_caddy(self) -> None:
        self._run_docker(
            [
                "exec",
                self.caddy_container,
                "caddy",
                "validate",
                "--config",
                "/etc/caddy/Caddyfile",
            ],
            timeout=20,
        )
        self._run_docker(
            [
                "exec",
                self.caddy_container,
                "caddy",
                "reload",
                "--config",
                "/etc/caddy/Caddyfile",
            ],
            timeout=20,
        )

    def _resolve_caddy_route_path(self, slug: str) -> str:
        real_caddy_dir = ensure_real_directory(self.caddy_apps_dir, "caddyAppsDir")
        route_path = os.path.join(real_caddy_dir, f"{slug}.caddy")
        if os.path.islink(route_path):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: Caddy route for "{slug}" cannot be a symlink.',
            )
        if os.path.lexists(route_path) and os.path.realpath(
            route_path
        ) != os.path.join(real_caddy_dir, f"{slug}.caddy"):
            raise BridgeRequestError(
                400,
                f'Security boundary violation: Caddy route for "{slug}" escapes directory.',
            )
        return route_path

    def _find_domain_owner(
        self, real_caddy_dir: str, domain: str, exclude_slug: str
    ) -> str | None:
        for entry in os.listdir(real_caddy_dir):
            if not entry.endswith(".caddy"):
                continue
            other_slug = entry[:-6]
            if other_slug == exclude_slug:
                continue
            full_path = os.path.join(real_caddy_dir, entry)
            if os.path.islink(full_path) or not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, "r", encoding="utf-8") as fh:
                    if domain in _extract_domains_from_caddy_text(fh.read()):
                        return other_slug
            except OSError:
                continue
        return None

    def _resolve_core_caddy_path(self) -> str:
        os.makedirs(self.caddy_core_dir, mode=0o755, exist_ok=True)
        real_core_dir = ensure_real_directory(self.caddy_core_dir, "caddyCoreDir")
        route_path = os.path.join(real_core_dir, "dashboard.caddy")
        if os.path.islink(route_path):
            raise BridgeRequestError(
                400,
                "Security boundary violation: core Caddy route cannot be a symlink.",
            )
        return route_path

    def route_core_domain(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Applies the dashboard/MCP domain directly to Caddy's core.d/dashboard.caddy,
        validates & reloads Caddy, and atomically restores the prior working config
        if validation or reload fails.
        """
        raw_domain = payload.get("domain")
        domain = None if raw_domain is None else validate_domain(raw_domain)
        acme_email = validate_email(payload.get("acmeEmail"))

        with self._caddy_lock:
            if domain is not None and os.path.isdir(self.caddy_apps_dir):
                real_apps_dir = ensure_real_directory(
                    self.caddy_apps_dir, "caddyAppsDir"
                )
                owner = self._find_domain_owner(real_apps_dir, domain, "__core__")
                if owner is not None:
                    raise BridgeRequestError(
                        409,
                        f'Domain "{domain}" is already routed to app "{owner}".',
                    )

            route_path = self._resolve_core_caddy_path()
            previous_content: str | None = None
            if os.path.exists(route_path):
                with open(route_path, "r", encoding="utf-8") as fh:
                    previous_content = fh.read()

            if domain is not None:
                tls_line = f"\ttls {acme_email}\n" if acme_email else ""
                route_body = (
                    "# Managed by VPSAgent Host Runtime Bridge (Core Dashboard & MCP)\n"
                    f"{domain} {{\n"
                    f"{tls_line}"
                    "\tencode zstd gzip\n"
                    "\thandle /mcp {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "\thandle {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "}\n"
                )
            else:
                route_body = (
                    "# Managed by VPSAgent Host Runtime Bridge (Local-only fallback)\n"
                    "127.0.0.1:80, localhost:80 {\n"
                    "\tencode zstd gzip\n"
                    "\thandle /mcp {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "\thandle {\n"
                    "\t\treverse_proxy vpsagent-core:3001\n"
                    "\t}\n"
                    "}\n"
                )

            try:
                with open(route_path, "w", encoding="utf-8") as fh:
                    fh.write(route_body)
                os.chmod(route_path, 0o644)
                self._validate_and_reload_caddy()
            except Exception as exc:
                if previous_content is not None:
                    with open(route_path, "w", encoding="utf-8") as fh:
                        fh.write(previous_content)
                    os.chmod(route_path, 0o644)
                elif os.path.exists(route_path):
                    os.unlink(route_path)
                if isinstance(exc, BridgeRequestError):
                    raise BridgeRequestError(
                        422, f"Caddy HTTPS domain update failed: {exc}"
                    ) from exc
                raise BridgeRequestError(
                    500, f"Failed updating core Caddy domain: {exc}"
                ) from exc

            if domain is None:
                return {
                    "ok": True,
                    "domain": None,
                    "acmeEmail": None,
                    "httpsActive": False,
                    "tlsStatus": "inactive",
                    "tlsError": None,
                }

            https_active, tls_status, tls_error = self.tls_checker(domain, 4.0)
            return {
                "ok": True,
                "domain": domain,
                "acmeEmail": acme_email,
                "httpsActive": https_active,
                "tlsStatus": tls_status,
                "tlsError": tls_error,
            }

    def check_core_tls(self, payload: dict[str, Any]) -> dict[str, Any]:
        domain = validate_domain(payload.get("domain"))
        https_active, tls_status, tls_error = self.tls_checker(domain, 4.0)
        return {
            "domain": domain,
            "httpsActive": https_active,
            "tlsStatus": tls_status,
            "tlsError": tls_error,
        }

    def route_caddy(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        raw_domain = payload.get("domain")
        domain = None if raw_domain is None else validate_domain(raw_domain)
        internal_port = validate_port(payload.get("internalPort"))
        network_name = f"vpsagent-{slug}_app_net"

        with self._lock_for(slug):
            with self._caddy_lock:
                route_path = self._resolve_caddy_route_path(slug)
                real_caddy_dir = os.path.dirname(route_path)
                previous_content: str | None = None
                if os.path.exists(route_path):
                    with open(route_path, "r", encoding="utf-8") as fh:
                        previous_content = fh.read()

                if domain is None:
                    if os.path.exists(route_path):
                        os.unlink(route_path)
                        try:
                            self._validate_and_reload_caddy()
                        except Exception:
                            if previous_content is not None:
                                with open(route_path, "w", encoding="utf-8") as fh:
                                    fh.write(previous_content)
                                os.chmod(route_path, 0o644)
                            raise
                    self._run_docker(
                        ["network", "disconnect", network_name, self.caddy_container],
                        timeout=15,
                        check=False,
                    )
                    return {"ok": True, "slug": slug, "domain": None, "routed": False}

                owner = self._find_domain_owner(real_caddy_dir, domain, slug)
                if owner is not None:
                    raise BridgeRequestError(
                        409,
                        f'Domain "{domain}" is already routed to app "{owner}".',
                    )

                inspect_proc = self._run_docker(
                    ["network", "inspect", network_name],
                    timeout=15,
                    check=False,
                )
                if inspect_proc.returncode != 0:
                    raise BridgeRequestError(
                        409,
                        f'App "{slug}" is not running yet (network "{network_name}" not found). Start the app before binding a public domain.',
                    )

                connected_here = False
                connect_proc = self._run_docker(
                    ["network", "connect", network_name, self.caddy_container],
                    timeout=15,
                    check=False,
                )
                if connect_proc.returncode == 0:
                    connected_here = True
                else:
                    err_text = (
                        connect_proc.stderr or connect_proc.stdout or ""
                    ).lower()
                    if (
                        "already exists" not in err_text
                        and "already connected" not in err_text
                    ):
                        raise BridgeRequestError(
                            502,
                            redact_secrets(
                                (
                                    connect_proc.stderr
                                    or connect_proc.stdout
                                    or "Failed to attach Caddy network."
                                ).strip()
                            ),
                        )

                route_body = (
                    f"# Managed by VPSAgent Runtime Bridge for app: {slug}\n"
                    f"{domain} {{\n"
                    f"\tencode zstd gzip\n"
                    f"\treverse_proxy vpsagent-app-{slug}:{internal_port}\n"
                    f"}}\n"
                )

                try:
                    with open(route_path, "w", encoding="utf-8") as fh:
                        fh.write(route_body)
                    os.chmod(route_path, 0o644)
                    self._validate_and_reload_caddy()
                except Exception as exc:
                    if previous_content is not None:
                        with open(route_path, "w", encoding="utf-8") as fh:
                            fh.write(previous_content)
                        os.chmod(route_path, 0o644)
                    elif os.path.exists(route_path):
                        os.unlink(route_path)
                    if connected_here:
                        self._run_docker(
                            [
                                "network",
                                "disconnect",
                                network_name,
                                self.caddy_container,
                            ],
                            timeout=15,
                            check=False,
                        )
                    if isinstance(exc, BridgeRequestError):
                        raise BridgeRequestError(
                            422, f"Caddy route validation failed: {exc}"
                        ) from exc
                    raise BridgeRequestError(
                        500, f"Failed writing Caddy route: {exc}"
                    ) from exc

                return {"ok": True, "slug": slug, "domain": domain, "routed": True}

    def remove_workload(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        raw_remove = payload.get("removeFiles", False)
        if not isinstance(raw_remove, bool):
            raise BridgeRequestError(400, "Field 'removeFiles' must be a boolean.")
        remove_files = raw_remove
        network_name = f"vpsagent-{slug}_app_net"

        with self._lock_for(slug):
            app_dir = resolve_scoped_app_dir(
                self.apps_root, slug, require_exists=False
            )
            compose_path = os.path.join(app_dir, "docker-compose.yml")
            if os.path.exists(app_dir) and os.path.lexists(compose_path):
                try:
                    with self._validated_compose_context(app_dir, slug) as (
                        validated_compose,
                        project_dir,
                    ):
                        self._run_docker(
                            [
                                *self._compose_cmd_base(
                                    slug, project_dir, validated_compose
                                ),
                                "down",
                                "--remove-orphans",
                            ],
                            timeout=60,
                            check=True,
                        )
                except BridgeRequestError as exc:
                    if exc.status_code != 400:
                        raise
                    self._compose_down_by_project(slug)
            else:
                self._compose_down_by_project(slug)

            with self._caddy_lock:
                self._run_docker(
                    ["network", "disconnect", network_name, self.caddy_container],
                    timeout=15,
                    check=False,
                )
                route_path = self._resolve_caddy_route_path(slug)
                if os.path.exists(route_path):
                    with open(route_path, "r", encoding="utf-8") as fh:
                        previous_content = fh.read()
                    os.unlink(route_path)
                    try:
                        self._validate_and_reload_caddy()
                    except Exception:
                        with open(route_path, "w", encoding="utf-8") as fh:
                            fh.write(previous_content)
                        os.chmod(route_path, 0o644)
                        raise

            if remove_files and os.path.exists(app_dir):
                shutil.rmtree(app_dir)

            self._run_docker(
                [
                    "rmi",
                    "-f",
                    f"vpsagent-app-{slug}:latest",
                    f"vpsagent-app-{slug}:previous",
                ],
                timeout=20,
                check=False,
            )

            self._clear_host_health(slug)
            return {"ok": True, "slug": slug}

    def rollback_app(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        latest_tag = f"vpsagent-app-{slug}:latest"
        prev_tag = f"vpsagent-app-{slug}:previous"

        with self._lock_for(slug):
            prev_proc = self._run_docker(
                ["image", "inspect", "--format", "{{.Id}}", prev_tag],
                timeout=15,
                check=False,
            )
            if prev_proc.returncode != 0 or not prev_proc.stdout.strip():
                raise BridgeRequestError(
                    404,
                    f'No previous build image is available to roll back "{slug}".',
                )
            prev_id = prev_proc.stdout.strip().splitlines()[0].strip()

            cur_proc = self._run_docker(
                ["image", "inspect", "--format", "{{.Id}}", latest_tag],
                timeout=15,
                check=False,
            )
            cur_id = (
                cur_proc.stdout.strip().splitlines()[0].strip()
                if cur_proc.returncode == 0 and cur_proc.stdout.strip()
                else None
            )

            self._run_docker(["tag", prev_id, latest_tag], timeout=15, check=True)
            swapped = False
            if cur_id and cur_id != prev_id:
                swap_proc = self._run_docker(
                    ["tag", cur_id, prev_tag], timeout=15, check=False
                )
                swapped = swap_proc.returncode == 0

            app_dir = resolve_scoped_app_dir(self.apps_root, slug)
            try:
                with self._validated_compose_context(
                    app_dir, slug, prepare_volumes=True
                ) as (compose_path, project_dir):
                    base = self._compose_cmd_base(slug, project_dir, compose_path)
                    self._clear_host_health(slug)
                    self._run_docker(
                        [*base, "up", "-d", "--remove-orphans"], timeout=180
                    )
                    status = self._compose_status(slug, project_dir, compose_path)
                    status = self._resolve_overall_status(slug, status)
            except Exception:
                if cur_id:
                    self._run_docker(
                        ["tag", cur_id, latest_tag], timeout=15, check=False
                    )
                self._run_docker(
                    ["tag", prev_id, prev_tag], timeout=15, check=False
                )
                raise
            return {
                "ok": True,
                "slug": slug,
                "status": status,
                "swapped": swapped,
            }

    @staticmethod
    def _is_backup_excluded_filename(name: str) -> bool:
        return name in SECRET_FILE_BASENAMES or bool(
            BACKUP_SECRET_BASENAME_RE.match(name)
        )

    def _copy_regular_file_for_backup(
        self, src_path: str, dst_path: str, remaining_budget: list[int]
    ) -> bool:
        if not os.path.lexists(src_path) or os.path.islink(src_path):
            return False
        if not os.path.isfile(src_path):
            return False
        name = os.path.basename(src_path)
        if self._is_backup_excluded_filename(name):
            return False
        st = os.lstat(src_path)
        if not stat.S_ISREG(st.st_mode):
            return False
        remaining_budget[0] -= st.st_size
        if remaining_budget[0] < 0:
            raise BridgeRequestError(
                413,
                "Backup data exceeds maximum staging size limit (200 MB).",
            )
        os.makedirs(os.path.dirname(dst_path), mode=0o750, exist_ok=True)
        shutil.copyfile(src_path, dst_path)
        return True

    def _copy_safe_tree_for_backup(
        self,
        src_dir: str,
        dst_dir: str,
        *,
        remaining_budget: list[int],
        skip_rel_prefixes: tuple[str, ...] = (),
    ) -> int:
        if not os.path.lexists(src_dir) or os.path.islink(src_dir) or not os.path.isdir(src_dir):
            return 0
        copied = 0
        for root, dirs, files in os.walk(src_dir, followlinks=False):
            rel_root = os.path.relpath(root, src_dir)
            if rel_root == ".":
                rel_root = ""
            # Prune symlinks and skipped prefixes
            kept_dirs: list[str] = []
            for d in sorted(dirs):
                full_d = os.path.join(root, d)
                if os.path.islink(full_d):
                    continue
                rel_d = os.path.join(rel_root, d) if rel_root else d
                norm_d = rel_d.replace(os.sep, "/")
                if any(
                    norm_d == p or norm_d.startswith(p + "/")
                    for p in skip_rel_prefixes
                ):
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs

            for fname in sorted(files):
                full_f = os.path.join(root, fname)
                if os.path.islink(full_f):
                    continue
                if self._is_backup_excluded_filename(fname):
                    continue
                rel_f = os.path.join(rel_root, fname) if rel_root else fname
                out_f = os.path.join(dst_dir, rel_f)
                if self._copy_regular_file_for_backup(
                    full_f, out_f, remaining_budget
                ):
                    copied += 1
        return copied

    def _postgres_service_state(
        self, slug: str, project_dir: str, compose_path: str
    ) -> str:
        proc = self._run_docker(
            [
                *self._compose_cmd_base(slug, project_dir, compose_path),
                "ps",
                "-a",
                "--format",
                "json",
                "postgres",
            ],
            timeout=20,
            check=False,
        )
        if proc.returncode != 0:
            return "unknown"
        rows = parse_compose_ps_output(proc.stdout)
        if not rows:
            return "stopped"
        matched = [
            r
            for r in rows
            if str(r.get("Service", "")).strip().lower() == "postgres"
            or "postgres" in str(r.get("Name", "")).strip().lower()
        ]
        if not matched:
            has_service_field = any(
                bool(str(r.get("Service", "")).strip()) for r in rows
            )
            if has_service_field:
                return "stopped"
            matched = rows
        for r in matched:
            state = str(r.get("State", "")).strip().lower()
            if state in ("running", "restarting", "paused", "created"):
                return "running"
        return "stopped"

    def _collect_app_backup_into(
        self, slug: str, target_dir: str, remaining_budget: list[int]
    ) -> dict[str, Any]:
        app_dir = resolve_scoped_app_dir(self.apps_root, slug, require_exists=True)
        os.makedirs(target_dir, mode=0o750, exist_ok=True)
        copied_compose = self._copy_regular_file_for_backup(
            os.path.join(app_dir, "docker-compose.yml"),
            os.path.join(target_dir, "docker-compose.yml"),
            remaining_budget,
        )
        self._copy_regular_file_for_backup(
            os.path.join(app_dir, "probe.json"),
            os.path.join(target_dir, "probe.json"),
            remaining_budget,
        )

        pg_status = "none"
        pg_state = "none"
        has_postgres = False
        compose_path = os.path.join(app_dir, "docker-compose.yml")
        if os.path.lexists(compose_path) and not os.path.islink(compose_path):
            try:
                with self._validated_compose_context(app_dir, slug) as (
                    tmp_compose,
                    project_dir,
                ):
                    with open(tmp_compose, "r", encoding="utf-8") as cfh:
                        rendered_doc = json.load(cfh)
                    services = (
                        rendered_doc.get("services")
                        if isinstance(rendered_doc, dict)
                        else None
                    )
                    has_postgres = isinstance(services, dict) and "postgres" in services
                    if has_postgres:
                        pg_state = self._postgres_service_state(
                            slug, project_dir, tmp_compose
                        )
                        if pg_state == "running":
                            dump_path = os.path.join(target_dir, "postgres.sql")
                            base = self._compose_cmd_base(slug, project_dir, tmp_compose)
                            proc: subprocess.Popen[bytes] | None = None
                            timed_out = False
                            timer: threading.Timer | None = None
                            try:
                                proc = subprocess.Popen(
                                    [
                                        self.docker_bin,
                                        *base,
                                        "exec",
                                        "-T",
                                        "postgres",
                                        "sh",
                                        "-c",
                                        'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                                    ],
                                    shell=False,
                                    env=_sanitized_subprocess_env(),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                )

                                def _kill_on_timeout() -> None:
                                    nonlocal timed_out
                                    timed_out = True
                                    if proc is not None and proc.poll() is None:
                                        try:
                                            proc.kill()
                                        except OSError:
                                            pass

                                timer = threading.Timer(90.0, _kill_on_timeout)
                                timer.daemon = True
                                timer.start()

                                written = 0
                                assert proc.stdout is not None
                                with open(dump_path, "wb") as dfh:
                                    while True:
                                        chunk = proc.stdout.read(65536)
                                        if not chunk:
                                            break
                                        if written + len(chunk) > remaining_budget[0]:
                                            proc.kill()
                                            raise BridgeRequestError(
                                                413,
                                                "Database dump exceeds backup size limit (200 MB).",
                                            )
                                        dfh.write(chunk)
                                        written += len(chunk)

                                stderr_bytes = (
                                    proc.stderr.read(4096)
                                    if proc.stderr is not None
                                    else b""
                                )
                                rc = proc.wait(timeout=10)
                                if timed_out or rc != 0:
                                    err_detail = redact_secrets(
                                        stderr_bytes.decode(
                                            "utf-8", errors="replace"
                                        ).strip()
                                    )[:200]
                                    raise BridgeRequestError(
                                        502,
                                        f'Failed to dump running Postgres database for "{slug}"'
                                        + (f": {err_detail}" if err_detail else "")
                                        + "; refusing to copy live database files.",
                                    )
                                remaining_budget[0] -= written
                                pg_status = "pg_dump"
                            except BridgeRequestError:
                                if proc is not None and proc.poll() is None:
                                    proc.kill()
                                    try:
                                        proc.wait(timeout=5)
                                    except (OSError, subprocess.TimeoutExpired):
                                        pass
                                if os.path.exists(dump_path):
                                    os.unlink(dump_path)
                                raise
                            except (OSError, subprocess.TimeoutExpired) as exc:
                                if proc is not None and proc.poll() is None:
                                    proc.kill()
                                    try:
                                        proc.wait(timeout=5)
                                    except (OSError, subprocess.TimeoutExpired):
                                        pass
                                if os.path.exists(dump_path):
                                    os.unlink(dump_path)
                                raise BridgeRequestError(
                                    502,
                                    f'Failed to dump running Postgres database for "{slug}": {exc}; refusing to copy live database files.',
                                ) from exc
                            finally:
                                if timer is not None:
                                    timer.cancel()
                                if proc is not None:
                                    if proc.stdout is not None:
                                        proc.stdout.close()
                                    if proc.stderr is not None:
                                        proc.stderr.close()
                        elif pg_state == "unknown":
                            raise BridgeRequestError(
                                502,
                                f'Could not verify Postgres container state for "{slug}"; refusing to copy potentially live database files.',
                            )
                        else:
                            pg_status = "skipped_stopped"
            except BridgeRequestError as exc:
                if exc.status_code in (413, 502):
                    raise
                pg_state = "unknown"
                pg_status = "skipped_stopped" if has_postgres else "none"

        skip_prefixes = ("postgres",) if (has_postgres and pg_state != "stopped") else ()
        data_files = self._copy_safe_tree_for_backup(
            os.path.join(app_dir, "data"),
            os.path.join(target_dir, "data"),
            remaining_budget=remaining_budget,
            skip_rel_prefixes=skip_prefixes,
        )
        return {
            "slug": slug,
            "composeIncluded": copied_compose,
            "postgresDump": pg_status,
            "dataFilesCopied": data_files,
        }

    def _package_staging_dir_to_tar_gz(
        self, staging_dir: str, prefix_name: str
    ) -> str:
        fd, tar_path = tempfile.mkstemp(prefix="vpsagent-backup-", suffix=".tar.gz")
        os.close(fd)
        os.chmod(tar_path, 0o600)
        try:
            with tarfile.open(tar_path, "w:gz") as tf:
                for root, dirs, files in os.walk(staging_dir, followlinks=False):
                    dirs.sort()
                    for fname in sorted(files):
                        full_path = os.path.join(root, fname)
                        if os.path.islink(full_path):
                            continue
                        rel = os.path.relpath(full_path, staging_dir)
                        arcname = f"{prefix_name}/{rel.replace(os.sep, '/')}"
                        tf.add(full_path, arcname=arcname, recursive=False)
            archive_size = os.path.getsize(tar_path)
            if archive_size > MAX_BACKUP_ARCHIVE_BYTES:
                raise BridgeRequestError(
                    413,
                    "Backup archive exceeds the 100 MB download limit.",
                )
            return tar_path
        except Exception:
            if os.path.exists(tar_path):
                os.unlink(tar_path)
            raise

    def create_app_backup(self, payload: dict[str, Any]) -> tuple[str, str]:
        slug = validate_slug(payload.get("slug"))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        archive_stem = f"vpsagent-app-{slug}-{timestamp}"
        filename = f"{archive_stem}.tar.gz"
        budget = [MAX_BACKUP_STAGING_BYTES]
        staging_dir = tempfile.mkdtemp(prefix=f"vpsagent-appbak-{slug}-")
        os.chmod(staging_dir, 0o700)
        try:
            with self._lock_for(slug):
                info = self._collect_app_backup_into(slug, staging_dir, budget)
            manifest = {
                "type": "app-backup",
                "createdAt": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "excludesSecrets": True,
                **info,
            }
            with open(
                os.path.join(staging_dir, "manifest.json"), "w", encoding="utf-8"
            ) as mfh:
                json.dump(manifest, mfh, indent=2)
                mfh.write("\n")
            with open(
                os.path.join(staging_dir, "RESTORE.txt"), "w", encoding="utf-8"
            ) as rfh:
                rfh.write(
                    f"VPSAgent App Backup ({slug})\n"
                    "=============================\n\n"
                    "For your security, secret environment variables (.env) are NOT inside this archive.\n"
                    "Keep a separate copy of your app secrets or re-enter them in the dashboard.\n\n"
                    "Contents:\n"
                    "- docker-compose.yml & probe.json: container blueprint & health check settings\n"
                    "- data/: persistent files stored in /app/data\n"
                    "- postgres.sql (if Postgres was running): clean database dump\n\n"
                    "To restore a Postgres dump into a running Postgres companion:\n"
                    f"  docker compose -p vpsagent-{slug} exec -T postgres sh -c 'psql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\"' < postgres.sql\n"
                )
            tar_path = self._package_staging_dir_to_tar_gz(staging_dir, archive_stem)
            return tar_path, filename
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def create_core_backup(self, payload: dict[str, Any]) -> tuple[str, str]:
        include_app_data = bool(payload.get("includeAppData", False))
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        archive_stem = f"vpsagent-server-backup-{timestamp}"
        filename = f"{archive_stem}.tar.gz"
        budget = [MAX_BACKUP_STAGING_BYTES]
        staging_dir = tempfile.mkdtemp(prefix="vpsagent-corebak-")
        os.chmod(staging_dir, 0o700)
        try:
            db_candidates = [
                os.path.join(self.vpsagent_root, "data", "registry.db"),
                os.path.join(self.vpsagent_root, "registry.db"),
            ]
            db_path = next(
                (
                    p
                    for p in db_candidates
                    if os.path.lexists(p)
                    and not os.path.islink(p)
                    and os.path.isfile(p)
                ),
                None,
            )
            registry_included = False
            if db_path:
                dst_db = os.path.join(staging_dir, "registry.db")
                src_conn: sqlite3.Connection | None = None
                dst_conn: sqlite3.Connection | None = None
                try:
                    src_conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
                    dst_conn = sqlite3.connect(dst_db)
                    src_conn.backup(dst_conn)
                    dst_conn.commit()
                    registry_included = True
                finally:
                    if dst_conn is not None:
                        dst_conn.close()
                    if src_conn is not None:
                        src_conn.close()
                budget[0] -= os.path.getsize(dst_db)
                if budget[0] < 0:
                    raise BridgeRequestError(
                        413, "Registry database exceeds backup staging size limit."
                    )

            for sub_name, dir_path in (
                ("core.d", self.caddy_core_dir),
                ("apps.d", self.caddy_apps_dir),
            ):
                if dir_path and os.path.isdir(dir_path) and not os.path.islink(dir_path):
                    for fname in sorted(os.listdir(dir_path)):
                        if not fname.endswith(".caddy"):
                            continue
                        self._copy_regular_file_for_backup(
                            os.path.join(dir_path, fname),
                            os.path.join(staging_dir, "caddy", sub_name, fname),
                            budget,
                        )

            app_summaries: list[dict[str, Any]] = []
            if os.path.isdir(self.apps_root) and not os.path.islink(self.apps_root):
                for entry in sorted(os.listdir(self.apps_root)):
                    if not SLUG_PATTERN.match(entry) or entry in RESERVED_SLUGS:
                        continue
                    app_dir = os.path.join(self.apps_root, entry)
                    if os.path.islink(app_dir) or not os.path.isdir(app_dir):
                        continue
                    target_app_dir = os.path.join(staging_dir, "apps", entry)
                    if include_app_data:
                        with self._lock_for(entry):
                            info = self._collect_app_backup_into(
                                entry, target_app_dir, budget
                            )
                        app_summaries.append(info)
                    else:
                        os.makedirs(target_app_dir, mode=0o750, exist_ok=True)
                        composed = self._copy_regular_file_for_backup(
                            os.path.join(app_dir, "docker-compose.yml"),
                            os.path.join(target_app_dir, "docker-compose.yml"),
                            budget,
                        )
                        self._copy_regular_file_for_backup(
                            os.path.join(app_dir, "probe.json"),
                            os.path.join(target_app_dir, "probe.json"),
                            budget,
                        )
                        app_summaries.append(
                            {
                                "slug": entry,
                                "composeIncluded": composed,
                                "postgresDump": "none",
                                "dataFilesCopied": 0,
                            }
                        )

            manifest = {
                "type": "core-backup",
                "createdAt": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "excludesSecrets": True,
                "includeAppData": include_app_data,
                "registryDbIncluded": registry_included,
                "apps": app_summaries,
            }
            with open(
                os.path.join(staging_dir, "manifest.json"), "w", encoding="utf-8"
            ) as mfh:
                json.dump(manifest, mfh, indent=2)
                mfh.write("\n")
            with open(
                os.path.join(staging_dir, "RESTORE.txt"), "w", encoding="utf-8"
            ) as rfh:
                rfh.write(
                    "VPSAgent Server Backup\n"
                    "======================\n\n"
                    "IMPORTANT SECURITY NOTE:\n"
                    "This backup intentionally EXCLUDES /var/lib/vpsagent/.env and per-app .env files\n"
                    "so encryption keys and raw secrets are never stored in a downloadable file.\n\n"
                    "If you move to a brand-new server, also save a separate offline copy of\n"
                    "/var/lib/vpsagent/.env (especially VPSAGENT_ENCRYPTION_SECRET) so VPSAgent can\n"
                    "decrypt your saved app variables, alert webhooks, and GitHub tokens.\n\n"
                    "Contents:\n"
                    "- registry.db: clean SQLite snapshot of apps, deployments, approvals, and settings\n"
                    "- caddy/: reverse-proxy site routes\n"
                    "- apps/<slug>/: compose blueprints (plus /data and postgres.sql if selected)\n"
                )
            tar_path = self._package_staging_dir_to_tar_gz(staging_dir, archive_stem)
            return tar_path, filename
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def _single_status(self, slug: str) -> tuple[str, str]:
        app_dir = resolve_scoped_app_dir(self.apps_root, slug, require_exists=False)
        compose_path = os.path.join(app_dir, "docker-compose.yml")
        if not os.path.exists(app_dir) or not os.path.lexists(compose_path):
            return slug, "stopped"
        try:
            with self._validated_compose_context(app_dir, slug) as (
                validated_compose,
                project_dir,
            ):
                status = self._compose_status(slug, project_dir, validated_compose)
                return slug, self._resolve_overall_status(slug, status)
        except BridgeRequestError:
            return slug, "error"

    def statuses(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw_slugs = payload.get("slugs")
        if not isinstance(raw_slugs, list):
            raise BridgeRequestError(400, "Field 'slugs' must be an array.")
        if len(raw_slugs) > MAX_STATUS_SLUGS:
            raise BridgeRequestError(
                400, f"At most {MAX_STATUS_SLUGS} slugs may be queried at once."
            )

        validated_slugs = [validate_slug(item) for item in raw_slugs]
        if not validated_slugs:
            return {"statuses": {}}

        out: dict[str, str] = {}
        pool = ThreadPoolExecutor(max_workers=4)
        pending_or_timed_out = True
        try:
            futures = {pool.submit(self._single_status, s): s for s in validated_slugs}
            done, not_done = wait_futures(
                futures.keys(),
                timeout=self.status_deadline_s,
                return_when=ALL_COMPLETED,
            )
            if not_done:
                for fut in not_done:
                    fut.cancel()
                raise BridgeRequestError(504, "Status sync exceeded overall deadline.")
            for fut in done:
                resolved_slug, status = fut.result()
                out[resolved_slug] = status
            pending_or_timed_out = False
        finally:
            pool.shutdown(
                wait=not pending_or_timed_out,
                cancel_futures=pending_or_timed_out,
            )
        return {"statuses": out}

    def _select_primary_container(
        self, slug: str, containers: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        primary_name = f"vpsagent-app-{slug}"
        exact = next(
            (
                c
                for c in containers
                if c["name"] == primary_name and c["running"] and c["ipAddress"]
            ),
            None,
        )
        if exact is not None:
            return exact
        return next((c for c in containers if c["running"] and c["ipAddress"]), None)

    def inspect_workload(
        self,
        payload: dict[str, Any],
        *,
        timeout_budget_s: float | None = None,
        _apply_host_health: bool = True,
    ) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        raw_probe_http = payload.get("probeHttp", False)
        if not isinstance(raw_probe_http, bool):
            raise BridgeRequestError(400, "Field 'probeHttp' must be a boolean.")
        probe_http = raw_probe_http
        probe_path = validate_probe_path(payload.get("probePath"))
        raw_port = payload.get("internalPort")
        internal_port = 8080 if raw_port is None else validate_port(raw_port)

        deadline = (
            time.monotonic() + max(0.05, float(timeout_budget_s))
            if timeout_budget_s is not None
            else None
        )

        def _budget(default_s: float) -> float:
            if deadline is None:
                return default_s
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise BridgeRequestError(504, "Readiness timeout budget exhausted.")
            return min(default_s, rem)

        app_dir = resolve_scoped_app_dir(self.apps_root, slug, require_exists=False)
        workspace_exists = os.path.isdir(app_dir)
        compose_exists = os.path.lexists(os.path.join(app_dir, "docker-compose.yml"))

        route_path = self._resolve_caddy_route_path(slug)
        caddy_route_configured = os.path.isfile(route_path)
        caddy_domains: list[str] = []
        if caddy_route_configured:
            try:
                route_text = _read_regular_file_nofollow(
                    route_path, MAX_BODY_BYTES, f'Caddy route for "{slug}"'
                )
                caddy_domains = sorted(_extract_domains_from_caddy_text(route_text))
            except BridgeRequestError:
                caddy_domains = []

        ps_proc = self._run_docker(
            [
                "ps",
                "-a",
                "--filter",
                f"label=com.docker.compose.project=vpsagent-{slug}",
                "--format",
                "{{.ID}}",
            ],
            timeout=_budget(15.0),
            check=False,
        )
        targets: list[str] = []
        if ps_proc.returncode == 0 and ps_proc.stdout.strip():
            seen_ids: set[str] = set()
            for raw_line in ps_proc.stdout.splitlines():
                cid = raw_line.strip()
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    targets.append(cid)
                    if len(targets) >= 4:
                        break
        if not targets:
            targets = [f"vpsagent-app-{slug}"]

        inspect_proc = self._run_docker(
            ["inspect", *targets], timeout=_budget(15.0), check=False
        )
        containers: list[dict[str, Any]] = []
        expected_net = f"vpsagent-{slug}_app_net"

        if inspect_proc.returncode == 0 and inspect_proc.stdout.strip():
            try:
                inspected_raw = json.loads(inspect_proc.stdout)
            except json.JSONDecodeError:
                inspected_raw = []
            if isinstance(inspected_raw, list):
                for item in inspected_raw:
                    if not isinstance(item, dict):
                        continue
                    state_obj = item.get("State")
                    if not isinstance(state_obj, dict):
                        state_obj = {}
                    host_cfg = item.get("HostConfig")
                    if not isinstance(host_cfg, dict):
                        host_cfg = {}
                    config_obj = item.get("Config")
                    if not isinstance(config_obj, dict):
                        config_obj = {}
                    net_settings = item.get("NetworkSettings")
                    if not isinstance(net_settings, dict):
                        net_settings = {}
                    networks_map = net_settings.get("Networks")
                    if not isinstance(networks_map, dict):
                        networks_map = {}

                    networks = sorted(str(k) for k in networks_map.keys())
                    ip_address: str | None = None
                    preferred_net = networks_map.get(expected_net)
                    if isinstance(preferred_net, dict):
                        candidate_ip = str(
                            preferred_net.get("IPAddress") or ""
                        ).strip()
                        if candidate_ip:
                            ip_address = candidate_ip
                    if ip_address is None:
                        for net_entry in networks_map.values():
                            if isinstance(net_entry, dict):
                                candidate_ip = str(
                                    net_entry.get("IPAddress") or ""
                                ).strip()
                                if candidate_ip:
                                    ip_address = candidate_ip
                                    break

                    cap_drop_raw = host_cfg.get("CapDrop")
                    cap_drop_list = (
                        [str(x).upper() for x in cap_drop_raw]
                        if isinstance(cap_drop_raw, list)
                        else []
                    )
                    cap_drop_all = "ALL" in cap_drop_list

                    sec_opt_raw = host_cfg.get("SecurityOpt")
                    sec_opt_list = (
                        [str(x).lower() for x in sec_opt_raw]
                        if isinstance(sec_opt_raw, list)
                        else []
                    )
                    no_new_privileges = any(
                        opt in ("no-new-privileges:true", "no-new-privileges=true")
                        for opt in sec_opt_list
                    )
                    privileged = bool(host_cfg.get("Privileged", False))

                    has_docker_socket_mount = False
                    mounts = item.get("Mounts")
                    if isinstance(mounts, list):
                        for mount in mounts:
                            if isinstance(mount, dict):
                                src = str(mount.get("Source") or "")
                                dst = str(mount.get("Destination") or "")
                                if "docker.sock" in src or "docker.sock" in dst:
                                    has_docker_socket_mount = True
                                    break
                    if not has_docker_socket_mount:
                        binds = host_cfg.get("Binds")
                        if isinstance(binds, list):
                            for bind in binds:
                                if "docker.sock" in str(bind):
                                    has_docker_socket_mount = True
                                    break

                    mem_bytes = host_cfg.get("Memory")
                    memory_limit_mb = (
                        round(mem_bytes / (1024 * 1024))
                        if isinstance(mem_bytes, (int, float))
                        and not isinstance(mem_bytes, bool)
                        and mem_bytes > 0
                        else None
                    )
                    nano_cpus_raw = host_cfg.get("NanoCpus")
                    nano_cpus = (
                        int(nano_cpus_raw)
                        if isinstance(nano_cpus_raw, (int, float))
                        and not isinstance(nano_cpus_raw, bool)
                        and nano_cpus_raw > 0
                        else None
                    )

                    isolated_network_only = len(networks) > 0 and all(
                        n == expected_net for n in networks
                    )
                    locked_compliant = (
                        cap_drop_all
                        and no_new_privileges
                        and (not privileged)
                        and (not has_docker_socket_mount)
                        and (not bool(host_cfg.get("CapAdd")))
                        and ((host_cfg.get("PidMode") or "") != "host")
                        and ((host_cfg.get("IpcMode") or "") != "host")
                        and isolated_network_only
                    )

                    health_obj = state_obj.get("Health")
                    if not isinstance(health_obj, dict):
                        health_obj = {}
                    raw_health = str(health_obj.get("Status") or "none").strip().lower()
                    health_status = (
                        raw_health
                        if raw_health in ("healthy", "unhealthy", "starting", "none")
                        else "none"
                    )
                    health_log = health_obj.get("Log")
                    last_health_output: str | None = None
                    if (
                        isinstance(health_log, list)
                        and health_log
                        and isinstance(health_log[-1], dict)
                    ):
                        raw_out = str(health_log[-1].get("Output") or "").strip()
                        if raw_out:
                            last_health_output = redact_secrets(raw_out)[:300] or None

                    raw_state = str(state_obj.get("Status") or "unknown").strip().lower()
                    running = bool(state_obj.get("Running", raw_state == "running"))
                    raw_exit = state_obj.get("ExitCode", 0)
                    exit_code = (
                        int(raw_exit)
                        if isinstance(raw_exit, int) and not isinstance(raw_exit, bool)
                        else 0
                    )
                    raw_restarts = item.get("RestartCount", 0)
                    restart_count = (
                        int(raw_restarts)
                        if isinstance(raw_restarts, int)
                        and not isinstance(raw_restarts, bool)
                        and raw_restarts >= 0
                        else 0
                    )
                    raw_started = state_obj.get("StartedAt")
                    started_at = (
                        raw_started
                        if isinstance(raw_started, str) and raw_started
                        else None
                    )

                    containers.append(
                        {
                            "id": str(item.get("Id") or "")[:12],
                            "name": str(item.get("Name") or "").lstrip("/"),
                            "image": str(config_obj.get("Image") or ""),
                            "state": raw_state,
                            "running": running,
                            "exitCode": exit_code,
                            "restartCount": restart_count,
                            "startedAt": started_at,
                            "healthStatus": health_status,
                            "lastHealthOutput": last_health_output,
                            "networks": networks,
                            "ipAddress": ip_address,
                            "security": {
                                "capDropAll": cap_drop_all,
                                "noNewPrivileges": no_new_privileges,
                                "privileged": privileged,
                                "hasDockerSocketMount": has_docker_socket_mount,
                                "isolatedNetworkOnly": isolated_network_only,
                                "memoryLimitMb": memory_limit_mb,
                                "nanoCpus": nano_cpus,
                                "lockedApartmentCompliant": locked_compliant,
                            },
                        }
                    )

        status = derive_app_status(
            [
                {
                    "State": c["state"],
                    "Health": "" if c["healthStatus"] == "none" else c["healthStatus"],
                    "ExitCode": c["exitCode"],
                }
                for c in containers
            ]
        )
        locked_apartment_compliant = len(containers) > 0 and all(
            c["security"]["lockedApartmentCompliant"] for c in containers
        )

        http_probe: dict[str, Any] | None = None
        target_container = self._select_primary_container(slug, containers)
        if probe_http:
            if target_container is not None:
                if deadline is not None and deadline - time.monotonic() <= 0:
                    http_probe = {
                        "attempted": False,
                        "ok": False,
                        "statusCode": None,
                        "latencyMs": None,
                        "contentType": None,
                        "error": "Readiness timeout budget exhausted before HTTP probe.",
                    }
                else:
                    http_probe = _probe_container_http(
                        str(target_container["ipAddress"]),
                        internal_port,
                        probe_path,
                        timeout_s=_budget(DEFAULT_PROBE_TIMEOUT_S),
                    )
            else:
                http_probe = {
                    "attempted": False,
                    "ok": False,
                    "statusCode": None,
                    "latencyMs": None,
                    "contentType": None,
                    "error": "Container is not running or has no bridge IP.",
                }

        # Keep Docker container liveness (`containers[i].healthStatus`) separate from
        # VPSAgent's recurring host HTTP monitor (`hostHttpHealth`) and the live
        # `httpProbe`, while applying the exact same overall status rule used by
        # `/v1/apps/statuses` so the Apps list and Safety Check never disagree.
        host_http_health: dict[str, Any] | None = None
        if _apply_host_health:
            probe_cfg = self._read_app_probe_config(app_dir, slug)
            if probe_cfg is not None and not probe_cfg["probeHttp"]:
                self._clear_host_health(slug)
            cached_host_health = self._get_host_health(slug)
            if cached_host_health is not None:
                host_http_health = {
                    "status": str(cached_host_health.get("status") or "none"),
                    "consecutiveFailures": int(
                        cached_host_health.get("consecutiveFailures") or 0
                    ),
                    "lastOutput": cached_host_health.get("lastOutput"),
                }
            else:
                monitoring_enabled = (
                    probe_cfg["probeHttp"]
                    if probe_cfg is not None
                    else bool(probe_http)
                )
                if monitoring_enabled:
                    # Recurring monitor is enabled but has not completed its first
                    # pass yet — never synthesize a monitor failure from live `httpProbe`.
                    host_http_health = {
                        "status": "starting",
                        "consecutiveFailures": 0,
                        "lastOutput": None,
                    }
            status = self._resolve_overall_status(slug, status)

        return {
            "slug": slug,
            "status": status,
            "workspaceExists": workspace_exists,
            "composeExists": compose_exists,
            "caddyRouteConfigured": caddy_route_configured,
            "caddyDomains": caddy_domains,
            "containers": containers,
            "lockedApartmentCompliant": locked_apartment_compliant,
            "httpProbe": http_probe,
            "hostHttpHealth": host_http_health,
        }

    def check_readiness(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Bounded startup readiness wait:
        - Fails fast if container is stopped/error or reports healthStatus == 'unhealthy'.
        - Waits while any configured container health check is still 'starting'.
        - When probeHttp is True (default), retries while the app is still binding its port
          and accepts any non-5xx HTTP response (100 <= status < 500, including 4xx API roots).
        - When probeHttp is False (non-HTTP workers), completes once running and healthy.
        - Strictly budgets remaining time before and after each inspection.
        """
        slug = validate_slug(payload.get("slug"))
        internal_port = validate_port(payload.get("internalPort"))
        raw_probe_http = payload.get("probeHttp", True)
        if not isinstance(raw_probe_http, bool):
            raise BridgeRequestError(400, "Field 'probeHttp' must be a boolean.")
        probe_http = raw_probe_http
        probe_path = validate_probe_path(payload.get("probePath"))

        raw_timeout = payload.get("timeoutSeconds", DEFAULT_READINESS_TIMEOUT_S)
        if (
            not isinstance(raw_timeout, (int, float))
            or isinstance(raw_timeout, bool)
            or raw_timeout < 0.1
            or raw_timeout > 60.0
        ):
            raise BridgeRequestError(
                400, "Field 'timeoutSeconds' must be between 0.1 and 60."
            )
        timeout_s = float(raw_timeout)

        raw_poll_ms = payload.get("pollIntervalMs", DEFAULT_READINESS_POLL_MS)
        if (
            not isinstance(raw_poll_ms, int)
            or isinstance(raw_poll_ms, bool)
            or raw_poll_ms < 10
            or raw_poll_ms > 5000
        ):
            raise BridgeRequestError(
                400, "Field 'pollIntervalMs' must be an integer between 10 and 5000."
            )
        poll_s = raw_poll_ms / 1000.0

        t0 = time.monotonic()
        deadline = t0 + timeout_s
        attempts = 0
        last_status = "stopped"
        last_probe: dict[str, Any] | None = None
        last_reason = "Readiness probe did not succeed before timeout."

        while True:
            remaining_before = deadline - time.monotonic()
            if attempts > 0 and remaining_before <= 0:
                return {
                    "ready": False,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe,
                    "reason": redact_secrets(
                        f'Timed out waiting for "{slug}" on port {internal_port}: {last_reason}'
                    ),
                }

            attempts += 1
            try:
                inspected = self.inspect_workload(
                    {
                        "slug": slug,
                        "probeHttp": probe_http,
                        "internalPort": internal_port,
                        "probePath": probe_path,
                    },
                    timeout_budget_s=max(0.05, remaining_before),
                    _apply_host_health=False,
                )
            except BridgeRequestError as exc:
                if exc.status_code == 504:
                    if attempts == 1:
                        last_reason = str(exc)
                    return {
                        "ready": False,
                        "slug": slug,
                        "status": last_status,
                        "attempts": attempts,
                        "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                        "httpProbe": last_probe,
                        "reason": redact_secrets(
                            f'Timed out waiting for "{slug}" on port {internal_port}: {last_reason}'
                        ),
                    }
                raise

            last_status = str(inspected["status"])
            last_probe = inspected.get("httpProbe")
            containers = inspected.get("containers") or []
            any_unhealthy = any(
                c.get("healthStatus") == "unhealthy" for c in containers
            )
            any_starting = any(
                c.get("healthStatus") == "starting" for c in containers
            )

            if last_status != "running" or any_unhealthy:
                reason = (
                    f'Container for "{slug}" failed readiness check '
                    f"(status={last_status}, unhealthy={str(any_unhealthy).lower()})."
                )
                return {
                    "ready": False,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe,
                    "reason": reason,
                }

            candidate_ready = False
            if any_starting:
                last_reason = "Waiting for container health check to finish starting."
            elif not probe_http:
                candidate_ready = True
            elif isinstance(last_probe, dict) and last_probe.get("attempted"):
                code = last_probe.get("statusCode")
                if last_probe.get("ok") or (
                    isinstance(code, int) and 100 <= code < 500
                ):
                    candidate_ready = True
                elif last_probe.get("error"):
                    last_reason = f"HTTP probe error: {last_probe['error']}"
                else:
                    last_reason = f"HTTP probe returned status {code}."
            elif isinstance(last_probe, dict) and last_probe.get("error"):
                last_reason = str(last_probe["error"])

            # Strictly check remaining deadline AFTER inspection and BEFORE any success return,
            # while preserving any more specific diagnostic (e.g. still starting / probe error).
            remaining_after = deadline - time.monotonic()
            if remaining_after <= 0:
                timeout_detail = (
                    f"readiness deadline ({timeout_s}s) exceeded during inspection."
                    if candidate_ready
                    else last_reason
                )
                return {
                    "ready": False,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe,
                    "reason": redact_secrets(
                        f'Timed out waiting for "{slug}" on port {internal_port}: {timeout_detail}'
                    ),
                }

            if candidate_ready:
                if probe_http and isinstance(last_probe, dict):
                    self._record_host_health(slug, probe_path, last_probe)
                return {
                    "ready": True,
                    "slug": slug,
                    "status": last_status,
                    "attempts": attempts,
                    "elapsedMs": round((time.monotonic() - t0) * 1000, 1),
                    "httpProbe": last_probe if probe_http else None,
                    "reason": None,
                }

            time.sleep(min(poll_s, remaining_after))

    # -------------------------------------------------------------------------
    # VPS Manager Endpoints (Command Exec, File Management, Services, Cleanup)
    # -------------------------------------------------------------------------

    @staticmethod
    def _truncate_redacted_output(
        text: str, max_bytes: int = MAX_COMMAND_OUTPUT_BYTES
    ) -> tuple[str, bool]:
        redacted = redact_secrets(text)
        encoded = redacted.encode("utf-8", errors="replace")
        if len(encoded) <= max_bytes:
            return redacted, False
        clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return clipped + "\n...[output truncated]", True

    @staticmethod
    def _validate_abs_path(raw: Any, field: str = "path") -> str:
        if not isinstance(raw, str) or not raw.strip():
            raise BridgeRequestError(400, f"Field '{field}' must be a non-empty string.")
        cleaned = raw.strip()
        if "\x00" in cleaned or len(cleaned) > 1024:
            raise BridgeRequestError(400, f"Field '{field}' is invalid.")
        if not os.path.isabs(cleaned):
            raise BridgeRequestError(400, f"Field '{field}' must be an absolute path.")
        return os.path.normpath(cleaned)

    @staticmethod
    def _is_secret_path(target_path: str) -> bool:
        for candidate in (target_path, os.path.realpath(target_path)):
            base = os.path.basename(candidate)
            lower_base = base.lower()
            if (
                base in SECRET_FILE_BASENAMES
                or lower_base == ".env"
                or lower_base.startswith(".env.")
                or lower_base.endswith(".pem")
                or lower_base.endswith(".key")
                or lower_base.endswith(".sqlite")
                or lower_base.endswith(".sqlite-wal")
                or lower_base.endswith(".sqlite-shm")
                or lower_base == "registry.db"
                or lower_base.startswith("registry.db-")
            ):
                return True
            if (
                candidate in ("/etc/shadow", "/etc/gshadow")
                or candidate.startswith("/var/lib/vpsagent/run/")
                or candidate == "/var/lib/vpsagent/run"
                or candidate.startswith("/var/lib/vpsagent/data/")
                or candidate == "/var/lib/vpsagent/data"
            ):
                return True
        return False

    def _assert_not_secret_file(self, abs_path: str) -> None:
        if self._is_secret_path(abs_path):
            raise BridgeRequestError(
                403,
                "Access to sensitive secret or credential files is blocked for safety.",
            )

    def _is_within_allowed_roots(self, resolved_path: str) -> bool:
        for root in self.allowed_file_roots:
            try:
                if os.path.commonpath([resolved_path, root]) == root:
                    return True
            except ValueError:
                continue
        return False

    def _assert_allowed_file_path(
        self, abs_path: str, *, allow_root_self: bool = True
    ) -> str:
        resolved = os.path.realpath(abs_path)
        if not self._is_within_allowed_roots(resolved):
            raise BridgeRequestError(
                403,
                f"Path '{abs_path}' is outside the allowed file directories ({', '.join(self.allowed_file_roots)}).",
            )
        if not allow_root_self and resolved in self.allowed_file_roots:
            raise BridgeRequestError(
                403, f"Refusing to delete an allowed root directory: {abs_path}"
            )
        self._assert_not_secret_file(abs_path)
        return resolved

    def _run_cmd_bounded(
        self,
        cmd: list[str],
        *,
        label: str,
        timeout: float,
        cwd: str | None = None,
        max_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    ) -> tuple[int, str, str, bool]:
        """Run a subprocess in its own process group, streaming output with a hard memory cap."""
        buf_cap = max_bytes + 4096
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                shell=False,
                env=_sanitized_subprocess_env(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise BridgeRequestError(
                503, f"{label} CLI binary not found ({cmd[0]})."
            ) from exc

        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        trunc_flags = [False, False]

        def _drain(stream: Any, bucket: list[bytes], flag_idx: int) -> None:
            kept = 0
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    if kept < buf_cap:
                        take = min(len(chunk), buf_cap - kept)
                        bucket.append(chunk[:take])
                        kept += take
                        if take < len(chunk):
                            trunc_flags[flag_idx] = True
                    else:
                        trunc_flags[flag_idx] = True
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        t_out = threading.Thread(
            target=_drain, args=(proc.stdout, out_chunks, 0), daemon=True
        )
        t_err = threading.Thread(
            target=_drain, args=(proc.stderr, err_chunks, 1), daemon=True
        )
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            t_out.join(timeout=2)
            t_err.join(timeout=2)
            raise BridgeRequestError(
                504, f"{label} command timed out after {int(timeout)}s."
            ) from exc

        t_out.join(timeout=2)
        t_err.join(timeout=2)
        raw_out = b"".join(out_chunks).decode("utf-8", errors="replace")
        raw_err = b"".join(err_chunks).decode("utf-8", errors="replace")
        stdout, out_trunc = self._truncate_redacted_output(raw_out, max_bytes=max_bytes)
        stderr, err_trunc = self._truncate_redacted_output(raw_err, max_bytes=max_bytes)
        return (
            int(proc.returncode or 0),
            stdout,
            stderr,
            out_trunc or err_trunc or trunc_flags[0] or trunc_flags[1],
        )

    def exec_in_app(self, payload: dict[str, Any]) -> dict[str, Any]:
        slug = validate_slug(payload.get("slug"))
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 8000:
            raise BridgeRequestError(
                400, "Field 'command' must be a non-empty string (max 8000 chars)."
            )
        service = payload.get("service", "app")
        if not isinstance(service, str) or not SERVICE_NAME_PATTERN.fullmatch(service):
            raise BridgeRequestError(400, "Field 'service' is invalid.")
        raw_timeout = payload.get("timeoutSeconds", DEFAULT_HOST_CMD_TIMEOUT_S)
        if not isinstance(raw_timeout, (int, float)) or isinstance(raw_timeout, bool):
            raise BridgeRequestError(400, "Field 'timeoutSeconds' must be a number.")
        timeout_s = max(1, min(int(raw_timeout), MAX_HOST_CMD_TIMEOUT_S))

        with self._lock_for(slug):
            app_dir = resolve_scoped_app_dir(self.apps_root, slug)
            with self._validated_compose_context(app_dir, slug) as (
                compose_path,
                project_dir,
            ):
                base = self._compose_cmd_base(slug, project_dir, compose_path)
                # Enforce timeout INSIDE the container using a dedicated process group
                # (`setsid`) so both the shell and all child processes are killed on timeout,
                # and emit a unique per-call sentinel only when the deadline actually expires
                # (avoiding false positives on commands that intentionally exit 124).
                sentinel = f"__VPSAGENT_EXEC_TIMEOUT_{os.urandom(8).hex()}__"
                inner_wrapper = (
                    'if command -v setsid >/dev/null 2>&1; then '
                    'setsid sh -lc "$1" & pid=$!; '
                    'else sh -lc "$1" & pid=$!; fi; '
                    f'(sleep {timeout_s}; '
                    'if kill -0 "$pid" 2>/dev/null; then '
                    f'printf "\\n{sentinel}\\n" >&2; '
                    'kill -TERM -"$pid" 2>/dev/null; kill -TERM "$pid" 2>/dev/null; '
                    'sleep 1; '
                    'kill -KILL -"$pid" 2>/dev/null; kill -KILL "$pid" 2>/dev/null; '
                    'fi) & watcher=$!; '
                    'wait "$pid"; rc=$?; '
                    'kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null; '
                    'exit "$rc"'
                )
                t0 = time.monotonic()
                rc, stdout, stderr, truncated = self._run_cmd_bounded(
                    [
                        self.docker_bin,
                        *base,
                        "exec",
                        "-T",
                        service,
                        "sh",
                        "-c",
                        inner_wrapper,
                        "vpsagent-exec",
                        command,
                    ],
                    label="Docker exec",
                    timeout=timeout_s + 4,
                )
                if sentinel in stderr:
                    raise BridgeRequestError(
                        504,
                        f'Command inside "{slug}" timed out after {timeout_s}s.',
                    )
                elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
                return {
                    "exitCode": rc,
                    "stdout": stdout,
                    "stderr": stderr,
                    "durationMs": elapsed_ms,
                    "truncated": truncated,
                }

    def host_exec(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = payload.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > 8000:
            raise BridgeRequestError(
                400, "Field 'command' must be a non-empty string (max 8000 chars)."
            )
        cwd_raw = payload.get("cwd")
        cwd: str | None = None
        if cwd_raw is not None:
            cwd = self._validate_abs_path(cwd_raw, "cwd")
            if not os.path.isdir(cwd):
                raise BridgeRequestError(
                    400, f"Working directory does not exist: {cwd}"
                )
        raw_timeout = payload.get("timeoutSeconds", DEFAULT_HOST_CMD_TIMEOUT_S)
        if not isinstance(raw_timeout, (int, float)) or isinstance(raw_timeout, bool):
            raise BridgeRequestError(400, "Field 'timeoutSeconds' must be a number.")
        timeout_s = max(1, min(int(raw_timeout), MAX_HOST_CMD_TIMEOUT_S))

        shell_bin = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
        t0 = time.monotonic()
        rc, stdout, stderr, truncated = self._run_cmd_bounded(
            [shell_bin, "-lc", command],
            label="Host shell",
            timeout=timeout_s,
            cwd=cwd,
        )
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        return {
            "exitCode": rc,
            "stdout": stdout,
            "stderr": stderr,
            "durationMs": elapsed_ms,
            "truncated": truncated,
        }

    def list_files(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        self._assert_allowed_file_path(target_path)
        show_hidden = bool(payload.get("showHidden", False))
        raw_max = payload.get("maxEntries", 200)
        if not isinstance(raw_max, int) or isinstance(raw_max, bool):
            raise BridgeRequestError(400, "Field 'maxEntries' must be an integer.")
        max_entries = max(1, min(raw_max, 500))

        if not os.path.exists(target_path):
            raise BridgeRequestError(404, f"Directory not found: {target_path}")
        if not os.path.isdir(target_path):
            raise BridgeRequestError(400, f"Path is not a directory: {target_path}")

        try:
            with os.scandir(target_path) as it:
                raw_entries = list(it)
        except OSError as exc:
            raise BridgeRequestError(500, redact_secrets(str(exc))) from exc

        entries: list[dict[str, Any]] = []
        for item in raw_entries:
            if not show_hidden and item.name.startswith("."):
                continue
            try:
                st = item.stat(follow_symlinks=False)
                if stat.S_ISLNK(st.st_mode):
                    entry_type = "symlink"
                elif stat.S_ISDIR(st.st_mode):
                    entry_type = "dir"
                elif stat.S_ISREG(st.st_mode):
                    entry_type = "file"
                else:
                    entry_type = "other"
                size_bytes = int(st.st_size) if entry_type == "file" else 0
                mod_at = datetime.fromtimestamp(
                    st.st_mtime, tz=timezone.utc
                ).isoformat()
            except OSError:
                entry_type = "other"
                size_bytes = 0
                mod_at = None
            entries.append(
                {
                    "name": item.name,
                    "path": os.path.join(target_path, item.name),
                    "type": entry_type,
                    "sizeBytes": size_bytes,
                    "modifiedAt": mod_at,
                }
            )

        entries.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
        truncated = len(entries) > max_entries
        return {
            "path": target_path,
            "entries": entries[:max_entries],
            "truncated": truncated,
        }

    def read_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        self._assert_allowed_file_path(target_path)

        if not os.path.exists(target_path):
            raise BridgeRequestError(404, f"File not found: {target_path}")
        if not os.path.isfile(target_path):
            raise BridgeRequestError(400, f"Path is not a regular file: {target_path}")

        raw_start = payload.get("startLine", 1)
        raw_end = payload.get("endLine")
        raw_max_bytes = payload.get("maxBytes", 65536)
        if not isinstance(raw_start, int) or isinstance(raw_start, bool) or raw_start < 1:
            raise BridgeRequestError(400, "Field 'startLine' must be an integer >= 1.")
        if raw_end is not None and (
            not isinstance(raw_end, int)
            or isinstance(raw_end, bool)
            or raw_end < raw_start
        ):
            raise BridgeRequestError(
                400, "Field 'endLine' must be an integer >= startLine."
            )
        if not isinstance(raw_max_bytes, int) or isinstance(raw_max_bytes, bool):
            raise BridgeRequestError(400, "Field 'maxBytes' must be an integer.")
        max_bytes = max(256, min(raw_max_bytes, MAX_READ_FILE_BYTES))

        try:
            size_bytes = os.path.getsize(target_path)
            with open(target_path, "rb") as fh:
                raw_chunk = fh.read(MAX_READ_SCAN_BYTES + 1)
        except OSError as exc:
            raise BridgeRequestError(500, redact_secrets(str(exc))) from exc

        scan_truncated = len(raw_chunk) > MAX_READ_SCAN_BYTES
        if scan_truncated:
            raw_chunk = raw_chunk[:MAX_READ_SCAN_BYTES]
        decoded = raw_chunk.decode("utf-8", errors="replace")
        all_lines = decoded.splitlines()

        total_lines = len(all_lines)
        start_idx = raw_start - 1
        end_idx = raw_end if raw_end is not None else total_lines
        selected = all_lines[start_idx:end_idx]
        joined = "\n".join(selected)
        content, truncated = self._truncate_redacted_output(joined, max_bytes=max_bytes)
        actual_end = min(end_idx, total_lines)
        return {
            "path": target_path,
            "content": content,
            "sizeBytes": int(size_bytes),
            "totalLines": total_lines,
            "startLine": raw_start,
            "endLine": actual_end,
            "truncated": scan_truncated or truncated or (actual_end < total_lines),
        }

    def write_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        self._assert_allowed_file_path(target_path)

        content = payload.get("content")
        if not isinstance(content, str):
            raise BridgeRequestError(400, "Field 'content' must be a string.")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_WRITE_FILE_BYTES:
            raise BridgeRequestError(
                413,
                f"File content exceeds maximum size ({MAX_WRITE_FILE_BYTES} bytes).",
            )
        append = bool(payload.get("append", False))
        create_dirs = bool(payload.get("createDirs", False))

        parent_dir = os.path.dirname(target_path)
        if parent_dir and not os.path.exists(parent_dir):
            if create_dirs:
                os.makedirs(parent_dir, exist_ok=True)
            else:
                raise BridgeRequestError(
                    400, f"Parent directory does not exist: {parent_dir}"
                )
        # Re-verify resolved path after optional parent creation
        self._assert_allowed_file_path(target_path)

        mode = "a" if append else "w"
        try:
            with open(target_path, mode, encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:
            raise BridgeRequestError(500, redact_secrets(str(exc))) from exc

        return {
            "ok": True,
            "path": target_path,
            "bytesWritten": len(encoded),
            "appended": append,
        }

    def delete_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        target_path = self._validate_abs_path(payload.get("path"))
        if target_path in PROTECTED_DELETE_PATHS or os.path.realpath(
            target_path
        ) in PROTECTED_DELETE_PATHS:
            raise BridgeRequestError(
                403, f"Refusing to delete protected system path: {target_path}"
            )
        self._assert_allowed_file_path(target_path, allow_root_self=False)

        recursive = bool(payload.get("recursive", False))
        if not os.path.lexists(target_path):
            raise BridgeRequestError(404, f"Path not found: {target_path}")

        if os.path.isdir(target_path) and not os.path.islink(target_path) and recursive:
            for dirpath, dirnames, filenames in os.walk(target_path, followlinks=False):
                for entry_name in (*dirnames, *filenames):
                    entry_path = os.path.join(dirpath, entry_name)
                    if self._is_secret_path(entry_path):
                        raise BridgeRequestError(
                            403,
                            f"Refusing recursive delete because directory contains protected file: {entry_name}",
                        )
                    if not self._is_within_allowed_roots(os.path.realpath(entry_path)):
                        raise BridgeRequestError(
                            403,
                            f"Refusing recursive delete because entry resolves outside allowed directories: {entry_name}",
                        )

        try:
            if os.path.islink(target_path):
                os.unlink(target_path)
                deleted_type = "symlink"
            elif os.path.isdir(target_path):
                if recursive:
                    shutil.rmtree(target_path)
                else:
                    os.rmdir(target_path)
                deleted_type = "dir"
            else:
                os.unlink(target_path)
                deleted_type = "file"
        except OSError as exc:
            raise BridgeRequestError(400, redact_secrets(str(exc))) from exc

        return {
            "ok": True,
            "path": target_path,
            "deletedType": deleted_type,
        }

    def list_services(self, payload: dict[str, Any]) -> dict[str, Any]:
        filter_str = payload.get("filter")
        if filter_str is not None and not isinstance(filter_str, str):
            raise BridgeRequestError(400, "Field 'filter' must be a string.")
        filter_lower = filter_str.strip().lower() if filter_str else ""

        state = payload.get("state", "all")
        if state not in ("all", "running", "failed"):
            raise BridgeRequestError(
                400, "Field 'state' must be one of: all, running, failed."
            )

        raw_limit = payload.get("limit", 100)
        if not isinstance(raw_limit, int) or isinstance(raw_limit, bool):
            raise BridgeRequestError(400, "Field 'limit' must be an integer.")
        limit = max(1, min(raw_limit, 300))

        cmd = [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-pager",
            "--no-legend",
            "--plain",
        ]
        if state == "running":
            cmd.append("--state=running")
        elif state == "failed":
            cmd.append("--state=failed")

        proc = self._run_cmd(cmd, label="systemd", timeout=20, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "systemctl failed").strip()
            raise BridgeRequestError(502, redact_secrets(detail))

        services: list[dict[str, str]] = []
        for line in (proc.stdout or "").splitlines():
            parts = line.strip().split(None, 4)
            if len(parts) < 4:
                continue
            name, load_state, active_state, sub_state = parts[:4]
            description = parts[4] if len(parts) > 4 else ""
            if filter_lower and filter_lower not in name.lower() and filter_lower not in description.lower():
                continue
            services.append(
                {
                    "name": name,
                    "loadState": load_state,
                    "activeState": active_state,
                    "subState": sub_state,
                    "description": redact_secrets(description),
                }
            )

        truncated = len(services) > limit
        return {
            "services": services[:limit],
            "truncated": truncated,
        }

    def manage_service(self, payload: dict[str, Any]) -> dict[str, Any]:
        service = payload.get("service")
        if not isinstance(service, str) or not SERVICE_UNIT_PATTERN.fullmatch(
            service.strip()
        ):
            raise BridgeRequestError(400, "Field 'service' is invalid.")
        service = service.strip()
        action = payload.get("action")
        if not isinstance(action, str) or action not in ALLOWED_SERVICE_ACTIONS:
            raise BridgeRequestError(
                400,
                "Field 'action' must be one of: start, stop, restart, reload, enable, disable, status.",
            )
        if service in PROTECTED_SERVICES and action in ("stop", "disable"):
            raise BridgeRequestError(
                403,
                f"Cannot {action} protected service '{service}' because it would disconnect VPSAgent.",
            )

        cmd = ["systemctl", action, service]
        if action == "status":
            cmd.insert(1, "--no-pager")
        proc = self._run_cmd(cmd, label="systemd", timeout=60, check=False)
        state_proc = self._run_cmd(
            ["systemctl", "is-active", service],
            label="systemd",
            timeout=10,
            check=False,
        )
        active_state = (state_proc.stdout or state_proc.stderr or "unknown").strip()
        raw_out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        output, _ = self._truncate_redacted_output(raw_out.strip(), max_bytes=16 * 1024)
        ok = proc.returncode == 0 or (action == "status" and proc.returncode in (0, 3))
        return {
            "ok": ok,
            "service": service,
            "action": action,
            "activeState": active_state,
            "output": output,
        }

    def docker_cleanup(self, payload: dict[str, Any]) -> dict[str, Any]:
        prune_images = payload.get("pruneImages", True) is not False
        prune_build_cache = payload.get("pruneBuildCache", True) is not False
        prune_volumes = bool(payload.get("pruneVolumes", False))

        outputs: list[str] = []
        reclaimed_lines: list[str] = []

        steps: list[tuple[str, list[str]]] = [
            ("containers", ["container", "prune", "-f"]),
        ]
        if prune_images:
            steps.append(("dangling-images", ["image", "prune", "-f"]))
            steps.append(
                ("images", ["image", "prune", "-af", "--filter", "label!=vpsagent.managed=true"])
            )
        if prune_build_cache:
            steps.append(("build-cache", ["builder", "prune", "-f"]))
        if prune_volumes:
            steps.append(("volumes", ["volume", "prune", "-f"]))

        all_ok = True
        failed_steps: list[str] = []
        for label, docker_args in steps:
            proc = self._run_docker(docker_args, timeout=120, check=False)
            if proc.returncode != 0:
                all_ok = False
                failed_steps.append(f"{label} (exit {proc.returncode})")
            combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            outputs.append(f"[{label}] (exit {proc.returncode})\n{combined}")
            for line in combined.splitlines():
                if "reclaimed" in line.lower() or "total" in line.lower():
                    reclaimed_lines.append(f"{label}: {line.strip()}")

        full_output, _ = self._truncate_redacted_output(
            "\n\n".join(outputs), max_bytes=32 * 1024
        )
        if not all_ok:
            reclaimed_summary = (
                f"Docker cleanup failed on: {', '.join(failed_steps)}"
                + (f"; {'; '.join(reclaimed_lines)}" if reclaimed_lines else "")
            )
        else:
            reclaimed_summary = (
                "; ".join(reclaimed_lines)
                if reclaimed_lines
                else "Docker cleanup completed."
            )
        return {
            "ok": all_ok,
            "output": full_output,
            "reclaimedSummary": redact_secrets(reclaimed_summary),
        }

    # ------------------------------------------------------------------
    # Tailscale Status & Serve Management (Allowlisted Host Integration)
    # ------------------------------------------------------------------

    def _is_tailscale_installed(self) -> bool:
        if os.sep in self.tailscale_bin:
            return os.path.isfile(self.tailscale_bin) and os.access(
                self.tailscale_bin, os.X_OK
            )
        return shutil.which(self.tailscale_bin) is not None

    def _is_matching_serve_target(self, proxy_val: str) -> bool:
        normalized = proxy_val.strip().rstrip("/").lower()
        port = self._tailscale_target_port
        return normalized in (
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
        )

    def _is_matching_mcp_serve_target(self, proxy_val: str) -> bool:
        # Tailscale strips the /mcp mount prefix before forwarding, so an explicit /mcp
        # mount only reaches VPSAgent's /mcp endpoint when its upstream target keeps /mcp.
        normalized = proxy_val.strip().lower()
        port = self._tailscale_target_port
        return normalized in (
            f"http://127.0.0.1:{port}/mcp",
            f"http://localhost:{port}/mcp",
        )

    def _inspect_tailscale_serve_details(
        self, dns_name: str | None
    ) -> dict[str, Any]:
        default_details: dict[str, Any] = {
            "serve_enabled": False,
            "serve_target": None,
            "serve_conflict": None,
            "serve_conflict_details": None,
            "root_matched": False,
            "mcp_conflict": None,
            "mcp_explicit_match": False,
            "funnel_active": False,
            "funnel_siblings": [],
        }
        proc = self._run_cmd(
            [self.tailscale_bin, "serve", "status", "--json"],
            label="Tailscale",
            timeout=8,
            check=False,
        )
        raw = (proc.stdout or "").strip()
        if not raw or proc.returncode != 0:
            return default_details
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return default_details
        if not isinstance(data, dict):
            return default_details
        web = data.get("Web")
        allow_funnel = data.get("AllowFunnel")
        preferred_key = f"{dns_name}:443" if dns_name else None
        candidate_keys: list[str] = []
        if isinstance(web, dict):
            if preferred_key and preferred_key in web:
                candidate_keys.append(preferred_key)
            for key in web:
                if (
                    isinstance(key, str)
                    and key.endswith(":443")
                    and key not in candidate_keys
                ):
                    candidate_keys.append(key)

        funnel_active = False
        if isinstance(allow_funnel, dict):
            for fk, fv in allow_funnel.items():
                if bool(fv) is True and isinstance(fk, str) and (
                    fk in candidate_keys or fk.endswith(":443")
                ):
                    funnel_active = True
                    break

        if not isinstance(web, dict) or not web:
            default_details["funnel_active"] = funnel_active
            return default_details

        other_proxy: str | None = None
        root_matched = False
        root_proxy: str | None = None
        mcp_conflict: str | None = None
        mcp_explicit_match = False
        any_handler_key: str | None = None
        funnel_siblings: list[str] = []
        for key in candidate_keys:
            entry = web.get(key)
            if not isinstance(entry, dict):
                continue
            handlers = entry.get("Handlers")
            if not isinstance(handlers, dict):
                continue
            if handlers and any_handler_key is None:
                any_handler_key = key
            root_handler = handlers.get("/")
            if isinstance(root_handler, dict):
                proxy = root_handler.get("Proxy")
                if isinstance(proxy, str) and proxy.strip():
                    cleaned_proxy = proxy.strip()
                    if self._is_matching_serve_target(cleaned_proxy):
                        root_matched = True
                        root_proxy = cleaned_proxy
                    elif other_proxy is None:
                        other_proxy = _sanitize_proxy_target_for_display(cleaned_proxy)
                elif other_proxy is None:
                    other_proxy = f"existing handler on {key}"
            mcp_handler = handlers.get("/mcp")
            if isinstance(mcp_handler, dict):
                mcp_proxy = mcp_handler.get("Proxy")
                if isinstance(mcp_proxy, str) and mcp_proxy.strip():
                    cleaned_mcp = mcp_proxy.strip()
                    if self._is_matching_mcp_serve_target(cleaned_mcp):
                        mcp_explicit_match = True
                    elif mcp_conflict is None:
                        mcp_conflict = (
                            f"/mcp -> {_sanitize_proxy_target_for_display(cleaned_mcp)}"
                        )
                elif mcp_conflict is None:
                    mcp_conflict = f"/mcp on {key}"
            for path_key, handler_val in sorted(handlers.items()):
                if not isinstance(path_key, str) or path_key in ("/", "/mcp"):
                    continue
                if isinstance(handler_val, dict):
                    sib_proxy = handler_val.get("Proxy")
                    if isinstance(sib_proxy, str) and sib_proxy.strip():
                        summary = (
                            f"{path_key} -> "
                            f"{_sanitize_proxy_target_for_display(sib_proxy)}"
                        )
                    else:
                        summary = f"{path_key} on {key}"
                else:
                    summary = f"{path_key} on {key}"
                if summary not in funnel_siblings:
                    funnel_siblings.append(summary)

        root_display = (
            f"/ ({other_proxy})"
            if other_proxy is not None and other_proxy.startswith("existing handler on ")
            else (f"/ -> {other_proxy}" if other_proxy is not None else None)
        )
        serve_conflict_details: dict[str, Any] | None = None
        if funnel_active and funnel_siblings:
            parts = [f"public Funnel sibling routes ({', '.join(funnel_siblings)})"]
            if root_display is not None:
                parts.append(f"replaced root route ({root_display})")
            if mcp_conflict is not None:
                parts.append(f"removed /mcp route ({mcp_conflict})")
            funnel_conflict = "; ".join(parts)
            serve_enabled = False
            serve_target: str | None = funnel_conflict
            serve_conflict: str | None = funnel_conflict
            serve_conflict_details = {
                "funnelActive": True,
                "preservedFunnelSiblings": list(funnel_siblings),
                "replacedRootRoute": root_display,
                "removedMcpRoute": mcp_conflict,
            }
        elif other_proxy is not None and mcp_conflict is not None:
            both_conflict = f"{root_display}; {mcp_conflict}"
            serve_enabled = False
            serve_target = both_conflict
            serve_conflict = both_conflict
            serve_conflict_details = {
                "funnelActive": funnel_active,
                "preservedFunnelSiblings": [],
                "replacedRootRoute": root_display,
                "removedMcpRoute": mcp_conflict,
            }
        elif mcp_conflict is not None:
            serve_enabled = False
            serve_target = mcp_conflict
            serve_conflict = mcp_conflict
            serve_conflict_details = {
                "funnelActive": funnel_active,
                "preservedFunnelSiblings": [],
                "replacedRootRoute": None,
                "removedMcpRoute": mcp_conflict,
            }
        elif root_matched:
            if funnel_active:
                serve_enabled = False
                serve_target = root_proxy
                serve_conflict = None
            else:
                serve_enabled = True
                serve_target = root_proxy
                serve_conflict = None
        elif other_proxy is not None:
            serve_enabled = False
            serve_target = other_proxy
            serve_conflict = other_proxy
            serve_conflict_details = {
                "funnelActive": funnel_active,
                "preservedFunnelSiblings": [],
                "replacedRootRoute": root_display,
                "removedMcpRoute": None,
            }
        elif any_handler_key is not None:
            serve_enabled = False
            serve_target = f"tailscale-serve:{any_handler_key}"
            serve_conflict = f"existing handler on {any_handler_key}"
        else:
            serve_enabled = False
            serve_target = None
            serve_conflict = None

        return {
            "serve_enabled": serve_enabled,
            "serve_target": serve_target,
            "serve_conflict": serve_conflict,
            "serve_conflict_details": serve_conflict_details,
            "root_matched": root_matched,
            "mcp_conflict": mcp_conflict,
            "mcp_explicit_match": mcp_explicit_match,
            "funnel_active": funnel_active,
            "funnel_siblings": funnel_siblings,
        }

    def _format_tailscale_conflict_summary(
        self,
        serve_conflict: str,
        conflict_details: dict[str, Any] | None,
        *,
        for_error: bool = False,
    ) -> str:
        if isinstance(conflict_details, dict):
            funnel_active = bool(conflict_details.get("funnelActive"))
            preserved = [
                str(item)
                for item in (conflict_details.get("preservedFunnelSiblings") or [])
                if isinstance(item, str) and item.strip()
            ]
            replaced_root = conflict_details.get("replacedRootRoute")
            removed_mcp = conflict_details.get("removedMcpRoute")
            parts: list[str] = []
            if funnel_active and preserved:
                parts.append(
                    "Port 443 is currently open to the public internet via Tailscale Funnel. "
                    "Switching port 443 to private Tailscale HTTPS turns off public Funnel for the "
                    "entire port 443 listener, keeping sibling routes ("
                    + ", ".join(preserved)
                    + ") available privately inside your tailnet only (stopping public internet access)."
                )
            elif funnel_active:
                parts.append(
                    "Port 443 is currently open to the public internet via Tailscale Funnel. "
                    "Switching port 443 to private Tailscale HTTPS turns off public Funnel for the "
                    "entire port 443 listener."
                )
            if isinstance(replaced_root, str) and replaced_root:
                parts.append(
                    f"The existing root route ({replaced_root}) will be replaced by VPSAgent, "
                    "so that service will lose / access even inside your tailnet."
                )
            if isinstance(removed_mcp, str) and removed_mcp:
                parts.append(
                    f"The conflicting /mcp route ({removed_mcp}) will be removed so VPSAgent's /mcp works, "
                    "so that service will lose /mcp access even inside your tailnet."
                )
            if parts:
                if for_error:
                    if funnel_active and preserved and not replaced_root and not removed_mcp:
                        parts.append("Confirm to make port 443 private anyway.")
                    elif funnel_active and (replaced_root or removed_mcp):
                        parts.append(
                            "Confirm to make port 443 private and apply these route changes."
                        )
                    else:
                        parts.append(
                            "Confirm to apply these port 443 route changes for VPSAgent."
                        )
                return " ".join(parts)

        if for_error:
            return (
                f"Tailscale Serve port 443 is currently forwarding to {serve_conflict}. "
                "Confirm replacement to switch port 443 to VPSAgent."
            )
        return f"Tailscale Serve port 443 is currently forwarding to {serve_conflict}."

    def _inspect_tailscale_serve(
        self, dns_name: str | None
    ) -> tuple[bool, str | None, str | None]:
        details = self._inspect_tailscale_serve_details(dns_name)
        return (
            bool(details["serve_enabled"]),
            details["serve_target"],
            details["serve_conflict"],
        )

    def tailscale_status(self) -> dict[str, Any]:
        if not self._is_tailscale_installed():
            return {
                "installed": False,
                "serviceActive": False,
                "connected": False,
                "backendState": "not_installed",
                "tailscaleIp": None,
                "tailscaleIps": [],
                "hostname": None,
                "dnsName": None,
                "tailnetName": None,
                "magicDnsEnabled": False,
                "httpsCertsAvailable": False,
                "loginUrl": None,
                "serveEnabled": False,
                "serveTarget": None,
                "serveUrl": None,
                "mcpUrl": None,
                "serveConflict": None,
                "serveConflictDetails": None,
                "cliVersion": None,
                "detail": None,
            }

        proc = self._run_cmd(
            [self.tailscale_bin, "status", "--json"],
            label="Tailscale",
            timeout=8,
            check=False,
        )
        parsed_status: dict[str, Any] | None = None
        raw_stdout = (proc.stdout or "").strip()
        if raw_stdout:
            try:
                loaded = json.loads(raw_stdout)
                if isinstance(loaded, dict):
                    parsed_status = loaded
            except json.JSONDecodeError:
                parsed_status = None

        if parsed_status is None:
            combined_err = redact_secrets(
                ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
            )
            err_lower = combined_err.lower()
            service_active = False
            if not any(
                marker in err_lower
                for marker in (
                    "failed to connect to local tailscaled",
                    "not running",
                    "stopped",
                )
            ):
                try:
                    svc_proc = self._run_cmd(
                        [self.systemctl_bin, "is-active", "tailscaled"],
                        label="systemd",
                        timeout=5,
                        check=False,
                    )
                    service_active = (
                        svc_proc.returncode == 0
                        and (svc_proc.stdout or "").strip() == "active"
                    )
                except BridgeRequestError:
                    service_active = False
            return {
                "installed": True,
                "serviceActive": service_active,
                "connected": False,
                "backendState": "stopped",
                "tailscaleIp": None,
                "tailscaleIps": [],
                "hostname": None,
                "dnsName": None,
                "tailnetName": None,
                "magicDnsEnabled": False,
                "httpsCertsAvailable": False,
                "loginUrl": None,
                "serveEnabled": False,
                "serveTarget": None,
                "serveUrl": None,
                "mcpUrl": None,
                "serveConflict": None,
                "serveConflictDetails": None,
                "cliVersion": None,
                "detail": combined_err
                or "Tailscale background service (tailscaled) is not running yet.",
            }

        raw_backend = str(parsed_status.get("BackendState") or "").strip()
        backend_map = {
            "running": "running",
            "needslogin": "needs_login",
            "needsmachineauth": "needs_machine_auth",
            "stopped": "stopped",
            "starting": "starting",
        }
        backend_state = backend_map.get(raw_backend.lower(), "unknown")
        service_active = True

        self_info = (
            parsed_status.get("Self")
            if isinstance(parsed_status.get("Self"), dict)
            else {}
        )
        raw_hostname = self_info.get("HostName")
        hostname = (
            raw_hostname.strip()
            if isinstance(raw_hostname, str) and raw_hostname.strip()
            else None
        )

        raw_dns = self_info.get("DNSName")
        dns_name: str | None = None
        if isinstance(raw_dns, str):
            candidate_dns = raw_dns.strip().rstrip(".").lower()
            if candidate_dns and DOMAIN_PATTERN.match(candidate_dns):
                dns_name = candidate_dns

        raw_ips = self_info.get("TailscaleIPs")
        if not isinstance(raw_ips, list):
            raw_ips = parsed_status.get("TailscaleIPs")
        tailscale_ips: list[str] = []
        if isinstance(raw_ips, list):
            for item in raw_ips:
                if isinstance(item, str) and item.strip():
                    candidate_ip = item.strip()
                    try:
                        ipaddress.ip_address(candidate_ip)
                        tailscale_ips.append(candidate_ip)
                    except ValueError:
                        continue

        tailscale_ip: str | None = None
        for ip in tailscale_ips:
            if ipaddress.ip_address(ip).version == 4:
                tailscale_ip = ip
                break
        if tailscale_ip is None and tailscale_ips:
            tailscale_ip = tailscale_ips[0]

        current_tailnet = (
            parsed_status.get("CurrentTailnet")
            if isinstance(parsed_status.get("CurrentTailnet"), dict)
            else {}
        )
        raw_tailnet_name = current_tailnet.get("Name")
        tailnet_name = (
            raw_tailnet_name.strip()
            if isinstance(raw_tailnet_name, str) and raw_tailnet_name.strip()
            else None
        )
        magic_dns_suffix = (
            current_tailnet.get("MagicDNSSuffix")
            or parsed_status.get("MagicDNSSuffix")
        )
        if "MagicDNSEnabled" in current_tailnet:
            magic_dns_enabled = bool(current_tailnet.get("MagicDNSEnabled"))
        else:
            magic_dns_enabled = bool(
                dns_name
                or (isinstance(magic_dns_suffix, str) and magic_dns_suffix.strip())
            )

        cert_domains = parsed_status.get("CertDomains")
        https_certs_available = isinstance(cert_domains, list) and any(
            isinstance(d, str) and d.strip() for d in cert_domains
        )
        login_url = _normalize_tailscale_url(parsed_status.get("AuthURL"))

        raw_version = parsed_status.get("Version")
        cli_version = (
            raw_version.strip()
            if isinstance(raw_version, str) and raw_version.strip()
            else None
        )

        connected = backend_state == "running" and tailscale_ip is not None
        if connected:
            serve_details = self._inspect_tailscale_serve_details(dns_name)
            serve_enabled = bool(serve_details["serve_enabled"])
            serve_target = serve_details["serve_target"]
            serve_conflict = serve_details["serve_conflict"]
            serve_conflict_details = serve_details["serve_conflict_details"]
            funnel_active = bool(serve_details["funnel_active"] and serve_details["root_matched"])
        else:
            serve_enabled, serve_target, serve_conflict = False, None, None
            serve_conflict_details = None
            funnel_active = False

        serve_url = f"https://{dns_name}" if (serve_enabled and dns_name) else None
        mcp_url = f"https://{dns_name}/mcp" if (serve_enabled and dns_name) else None

        detail: str | None = None
        if backend_state == "needs_machine_auth":
            detail = "This server is waiting for device approval in your Tailscale admin console."
        elif connected and not magic_dns_enabled:
            detail = (
                "MagicDNS is currently turned off in your tailnet. Enable MagicDNS and HTTPS "
                "Certificates in Tailscale DNS settings for automatic private HTTPS."
            )
        elif connected and not https_certs_available:
            detail = (
                "Tailscale HTTPS Certificates are not enabled for this tailnet yet. "
                "Enable MagicDNS and HTTPS Certificates in Tailscale DNS settings."
            )
        elif serve_conflict:
            detail = self._format_tailscale_conflict_summary(
                str(serve_conflict),
                serve_conflict_details,
                for_error=False,
            )
        elif connected and funnel_active:
            detail = (
                "Public Tailscale Funnel is currently active on port 443. Enable private "
                "Tailscale HTTPS to disable public Funnel and restrict access to your tailnet."
            )

        return {
            "installed": True,
            "serviceActive": service_active,
            "connected": connected,
            "backendState": backend_state,
            "tailscaleIp": tailscale_ip,
            "tailscaleIps": tailscale_ips,
            "hostname": hostname,
            "dnsName": dns_name,
            "tailnetName": tailnet_name,
            "magicDnsEnabled": magic_dns_enabled,
            "httpsCertsAvailable": https_certs_available,
            "loginUrl": login_url,
            "serveEnabled": serve_enabled,
            "serveTarget": serve_target,
            "serveUrl": serve_url,
            "mcpUrl": mcp_url,
            "serveConflict": serve_conflict,
            "serveConflictDetails": serve_conflict_details,
            "cliVersion": cli_version,
            "detail": detail,
        }

    def set_tailscale_serve(self, payload: dict[str, Any]) -> dict[str, Any]:
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise BridgeRequestError(400, "Field 'enabled' must be a boolean.")
        force = bool(payload.get("force", False))

        with self._tailscale_lock:
            status = self.tailscale_status()
            if enabled:
                if not status["installed"]:
                    raise BridgeRequestError(
                        400, "Tailscale is not installed on this server yet."
                    )
                if not status["connected"]:
                    raise BridgeRequestError(
                        400,
                        "Tailscale is not connected yet. Sign in to Tailscale first.",
                    )
                if not status["dnsName"]:
                    raise BridgeRequestError(
                        400,
                        "MagicDNS hostname is not available yet. Enable MagicDNS and HTTPS Certificates at https://login.tailscale.com/admin/dns and refresh.",
                    )
                if status["serveConflict"] and not force:
                    raise BridgeRequestError(
                        409,
                        self._format_tailscale_conflict_summary(
                            str(status["serveConflict"]),
                            status.get("serveConflictDetails"),
                            for_error=True,
                        ),
                    )
                if not self._tailscale_target_checker(
                    self._tailscale_target_host, self._tailscale_target_port
                ):
                    raise BridgeRequestError(
                        422,
                        f"VPSAgent's private local proxy port ({self._tailscale_target_host}:{self._tailscale_target_port}) is not open yet. Run the VPSAgent updater or re-run bootstrap/install.sh once so Docker publishes the private loopback port.",
                    )

                # Configure the root proxy FIRST before deleting any existing /mcp mount
                # so an HTTPS approval failure or CLI error never leaves an existing route deleted.
                proc = self._run_cmd(
                    [
                        self.tailscale_bin,
                        "serve",
                        "--bg",
                        "--https=443",
                        self.tailscale_target_url,
                    ],
                    label="Tailscale",
                    timeout=25,
                    check=False,
                )
                raw_out = (proc.stderr or "") + "\n" + (proc.stdout or "")
                action_match = TAILSCALE_LOGIN_URL_RE.search(raw_out)
                action_url = (
                    _normalize_tailscale_url(action_match.group(0))
                    if action_match
                    else None
                )
                if proc.returncode != 0:
                    if action_url:
                        raise BridgeRequestError(
                            422,
                            f"Tailscale Serve needs HTTPS enabled in your Tailscale DNS settings first. Open {action_url} to enable it, then try again.",
                        )
                    combined = redact_secrets(raw_out.strip())
                    raise BridgeRequestError(
                        422,
                        combined or "Could not enable Tailscale Serve on port 443.",
                    )
                if action_url is not None:
                    raise BridgeRequestError(
                        422,
                        f"Tailscale Serve needs HTTPS enabled in your Tailscale DNS settings first. Open {action_url} to enable it, then try again.",
                    )

                after_root = self._inspect_tailscale_serve_details(status["dnsName"])
                if not after_root["root_matched"]:
                    raise BridgeRequestError(
                        422,
                        redact_secrets(raw_out.strip())
                        or "Tailscale Serve did not activate on port 443. Check MagicDNS and HTTPS Certificates in your Tailscale DNS settings.",
                    )

                if force and after_root["mcp_conflict"]:
                    rm_proc = self._run_cmd(
                        [
                            self.tailscale_bin,
                            "serve",
                            "--https=443",
                            "--set-path=/mcp",
                            "off",
                        ],
                        label="Tailscale",
                        timeout=15,
                        check=False,
                    )
                    rm_out = (
                        (rm_proc.stderr or "") + "\n" + (rm_proc.stdout or "")
                    ).strip()
                    if rm_proc.returncode != 0 and not any(
                        msg in rm_out.lower()
                        for msg in (
                            "not serving",
                            "no serve config",
                            "nothing to turn off",
                        )
                    ):
                        raise BridgeRequestError(
                            422,
                            redact_secrets(rm_out)
                            or "Could not clear the conflicting /mcp Tailscale Serve route.",
                        )

                updated = self.tailscale_status()
                final_details = self._inspect_tailscale_serve_details(status["dnsName"])
                if not updated["serveEnabled"]:
                    if final_details["funnel_active"]:
                        raise BridgeRequestError(
                            422,
                            "Public Tailscale Funnel is still active on port 443. Run 'tailscale funnel --https=443 off' on the host and try again.",
                        )
                    raise BridgeRequestError(
                        422,
                        redact_secrets(raw_out.strip())
                        or "Tailscale Serve did not activate on port 443. Check MagicDNS and HTTPS Certificates in your Tailscale DNS settings.",
                    )
                return {
                    "ok": True,
                    "status": updated,
                    "actionUrl": None,
                }

            if not status["installed"]:
                return {"ok": True, "status": status, "actionUrl": None}
            if status["serveConflict"] and not force:
                raise BridgeRequestError(
                    409,
                    f'Refusing to turn off Tailscale Serve port 443 because it is forwarding to another service ({status["serveConflict"]}).',
                )
            disable_details = (
                self._inspect_tailscale_serve_details(status["dnsName"])
                if status["connected"]
                else {"mcp_explicit_match": False}
            )
            proc = self._run_cmd(
                [self.tailscale_bin, "serve", "--https=443", "--set-path=/", "off"],
                label="Tailscale",
                timeout=20,
                check=False,
            )
            raw_out = ((proc.stderr or "") + "\n" + (proc.stdout or "")).strip()
            if proc.returncode != 0 and not any(
                msg in raw_out.lower()
                for msg in ("not serving", "no serve config", "nothing to turn off")
            ):
                raise BridgeRequestError(
                    422,
                    redact_secrets(raw_out)
                    or "Could not turn off Tailscale Serve on port 443.",
                )
            if disable_details.get("mcp_explicit_match"):
                rm_mcp_proc = self._run_cmd(
                    [
                        self.tailscale_bin,
                        "serve",
                        "--https=443",
                        "--set-path=/mcp",
                        "off",
                    ],
                    label="Tailscale",
                    timeout=15,
                    check=False,
                )
                rm_mcp_out = (
                    (rm_mcp_proc.stderr or "") + "\n" + (rm_mcp_proc.stdout or "")
                ).strip()
                if rm_mcp_proc.returncode != 0 and not any(
                    msg in rm_mcp_out.lower()
                    for msg in (
                        "not serving",
                        "no serve config",
                        "nothing to turn off",
                    )
                ):
                    raise BridgeRequestError(
                        422,
                        redact_secrets(rm_mcp_out)
                        or "Could not turn off the Tailscale Serve /mcp route on port 443.",
                    )
            updated = self.tailscale_status()
            return {"ok": True, "status": updated, "actionUrl": None}

    def connect_tailscale(self, payload: dict[str, Any]) -> dict[str, Any]:
        mode = payload.get("mode", "login")
        if not isinstance(mode, str) or mode not in ("login", "authkey"):
            raise BridgeRequestError(
                400, "Field 'mode' must be either 'login' or 'authkey'."
            )

        auth_key = ""
        if mode == "authkey":
            raw_key = payload.get("authKey")
            if not isinstance(raw_key, str) or not TAILSCALE_AUTHKEY_PATTERN.match(
                raw_key.strip()
            ):
                raise BridgeRequestError(
                    400,
                    "Invalid Tailscale auth key format: expected a tskey-auth-... key.",
                )
            auth_key = raw_key.strip()

        with self._tailscale_lock:
            status = self.tailscale_status()
            if not status["installed"]:
                raise BridgeRequestError(
                    400, "Tailscale is not installed on this server yet."
                )

            if not status["serviceActive"]:
                try:
                    self._run_cmd(
                        [self.systemctl_bin, "start", "tailscaled"],
                        label="systemd",
                        timeout=15,
                        check=False,
                    )
                except BridgeRequestError:
                    pass
                status = self.tailscale_status()

            if mode == "login":
                if status["connected"]:
                    return {"ok": True, "status": status, "loginUrl": None}
                if status["loginUrl"] and status["backendState"] == "needs_login":
                    return {
                        "ok": True,
                        "status": status,
                        "loginUrl": status["loginUrl"],
                    }

                proc = self._run_cmd(
                    [self.tailscale_bin, "up", "--timeout=4s"],
                    label="Tailscale",
                    timeout=12,
                    check=False,
                )
                raw_out = (proc.stdout or "") + "\n" + (proc.stderr or "")
                extracted_match = TAILSCALE_LOGIN_URL_RE.search(raw_out)
                updated = self.tailscale_status()
                login_url = updated["loginUrl"] or _normalize_tailscale_url(
                    extracted_match.group(0) if extracted_match else None
                )
                if not updated["connected"] and not login_url and proc.returncode != 0:
                    raise BridgeRequestError(
                        422,
                        redact_secrets(
                            (
                                proc.stderr
                                or proc.stdout
                                or "Could not start Tailscale sign-in."
                            ).strip()
                        ),
                    )
                return {
                    "ok": True,
                    "status": updated,
                    "loginUrl": login_url,
                }

            tmp_dir = tempfile.mkdtemp(prefix="vpsagent-ts-")
            os.chmod(tmp_dir, 0o700)
            key_file = os.path.join(tmp_dir, "authkey")
            try:
                fd = os.open(
                    key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                )
                try:
                    os.write(fd, auth_key.encode("utf-8"))
                finally:
                    os.close(fd)
                os.chmod(key_file, 0o600)

                proc = self._run_cmd(
                    [
                        self.tailscale_bin,
                        "up",
                        f"--auth-key=file:{key_file}",
                        "--timeout=25s",
                    ],
                    label="Tailscale",
                    timeout=35,
                    check=False,
                )
            finally:
                try:
                    if os.path.exists(key_file):
                        os.unlink(key_file)
                except OSError:
                    pass
                shutil.rmtree(tmp_dir, ignore_errors=True)

            if proc.returncode != 0:
                detail = _scrub_secret_values(
                    (
                        proc.stderr
                        or proc.stdout
                        or "Tailscale sign-in with auth key failed."
                    ).strip(),
                    [auth_key],
                )
                raise BridgeRequestError(422, detail)

            updated = self.tailscale_status()
            return {
                "ok": True,
                "status": updated,
                "loginUrl": updated["loginUrl"],
            }

    # ------------------------------------------------------------------
    # VPSAgent Self-Update (GitHub Releases + Safe Git Branch Fallback)
    # ------------------------------------------------------------------

    def _default_update_state(self) -> dict[str, Any]:
        return {
            "state": "idle",
            "phase": None,
            "updateSource": "none",
            "releaseRepo": None,
            "releaseStatus": "unchecked",
            "releaseNote": None,
            "checkedAt": None,
            "startedAt": None,
            "finishedAt": None,
            "latestVersion": None,
            "latestReleaseTag": None,
            "latestReleaseName": None,
            "latestReleaseUrl": None,
            "latestReleaseNotes": None,
            "latestReleasePublishedAt": None,
            "latestReleasePrerelease": False,
            "latestReleaseAssetName": None,
            "checksumAvailable": False,
            "checksumStatus": "none",
            "checksumSha256": None,
            "latestCommit": None,
            "latestCommitSubject": None,
            "latestCommitDate": None,
            "commitsBehind": 0,
            "updateAvailable": False,
            "message": None,
            "error": None,
            "logs": [],
            "_releaseDownloadUrl": None,
            "_releaseChecksumUrl": None,
            "_releaseChecksumAssetName": None,
            "_releaseAssetDigest": None,
        }

    def _load_persisted_update_state(self) -> dict[str, Any]:
        base = self._default_update_state()
        try:
            if not os.path.isfile(self._update_status_file):
                return base
            with open(self._update_status_file, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                return base
            for key in base:
                if key in loaded:
                    base[key] = loaded[key]
            # If the bridge restarted while an update was marked in-progress, don't stay stuck forever.
            if base.get("state") == "updating":
                base["state"] = "idle"
                base["phase"] = None
                base["message"] = "Previous update session was interrupted by a service restart."
            if not isinstance(base.get("logs"), list):
                base["logs"] = []
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return base
        return base

    def _persist_update_state(self, state: dict[str, Any]) -> None:
        try:
            parent = os.path.dirname(self._update_status_file)
            os.makedirs(parent, exist_ok=True)
            tmp_path = f"{self._update_status_file}.tmp.{os.getpid()}"
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2)
            os.chmod(tmp_path, 0o640)
            os.replace(tmp_path, self._update_status_file)
        except OSError:
            pass

    def _read_repo_package_version(self, repo_dir: str) -> str | None:
        pkg_path = os.path.join(repo_dir, "package.json")
        if not os.path.isfile(pkg_path):
            return None
        try:
            with open(pkg_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            version = data.get("version")
            if isinstance(version, str) and version.strip():
                return version.strip()
        except (OSError, json.JSONDecodeError, TypeError):
            return None
        return None

    def _read_release_metadata(self, repo_dir: str) -> dict[str, Any] | None:
        meta_path = os.path.join(repo_dir, ".vpsagent-release.json")
        if not os.path.lexists(meta_path):
            return None
        try:
            raw = _read_regular_file_nofollow(meta_path, 32 * 1024, ".vpsagent-release.json")
            data = json.loads(raw)
            return data if isinstance(data, dict) else None
        except (BridgeRequestError, json.JSONDecodeError, TypeError, ValueError):
            return None

    def _run_repo_git(
        self,
        repo_dir: str,
        git_args: list[str],
        *,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        """
        Runs Git inside `repo_dir`. When the bridge runs as root on a user-owned
        checkout (e.g. `/home/ubuntu/vpsagent`), drops privileges to the checkout
        owner so Git trusts the repository, uses the owner's SSH/Git credentials,
        and never parses user-controlled `.git/config` as root.
        """
        extra_env: dict[str, str] = {"GIT_TERMINAL_PROMPT": "0"}
        run_kwargs: dict[str, Any] = {}
        try:
            st = os.stat(repo_dir)
            if (
                pwd is not None
                and hasattr(os, "geteuid")
                and os.geteuid() == 0
                and st.st_uid != 0
            ):
                pw = pwd.getpwuid(st.st_uid)
                extra_env["HOME"] = pw.pw_dir
                extra_env["USER"] = pw.pw_name
                extra_env["LOGNAME"] = pw.pw_name
                run_kwargs["user"] = st.st_uid
                run_kwargs["group"] = st.st_gid
        except (OSError, KeyError):
            pass

        cmd = [self.git_bin, "-C", repo_dir, *git_args]
        try:
            return subprocess.run(
                cmd,
                shell=False,
                env=_sanitized_subprocess_env(extra_env),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                **run_kwargs,
            )
        except FileNotFoundError as exc:
            raise BridgeRequestError(
                503, f"git CLI binary not found ({self.git_bin})."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise BridgeRequestError(
                504, f"git command timed out after {int(timeout)}s."
            ) from exc

    def _resolve_release_repo(self, repo_info: dict[str, Any]) -> str | None:
        if self.release_repo:
            return self.release_repo
        origin_url = repo_info.get("originUrl")
        if isinstance(origin_url, str) and origin_url.strip():
            match = GITHUB_REMOTE_URL_RE.match(origin_url.strip())
            if match:
                return match.group(1)
            # Local filesystem or non-GitHub git remotes stay offline in git mode unless overridden
            return None
        meta_repo = repo_info.get("releaseRepo")
        if isinstance(meta_repo, str) and RELEASE_REPO_PATTERN.match(meta_repo.strip()):
            return meta_repo.strip()
        return DEFAULT_RELEASE_REPO

    def _fetch_release_http(
        self,
        url: str,
        *,
        accept: str = "application/vnd.github+json",
        max_bytes: int = MAX_RELEASE_JSON_BYTES,
        timeout: float = 15.0,
        stream_to_file: str | None = None,
    ) -> tuple[int, dict[str, str], bytes | None, str | None]:
        """
        Performs a strict SSRF-safe, redirect-verified HTTP(S) GET request to GitHub
        Releases API or release asset CDNs. Strips Authorization headers whenever a
        redirect leaves the configured API origin and pins non-loopback connections
        to validated public IPs.
        """
        api_parsed = urlparse(self.release_api_base)
        api_host = (api_parsed.hostname or "").lower().strip("[]").rstrip(".")
        api_port = api_parsed.port or (443 if api_parsed.scheme.lower() == "https" else 80)

        current_url = url.strip()
        for _ in range(6):
            if not current_url or any(ch.isspace() or ord(ch) < 32 for ch in current_url):
                raise RuntimeError("Release URL contains invalid whitespace or control characters.")
            parsed = urlparse(current_url)
            if parsed.username or parsed.password:
                raise RuntimeError("Release URL must not embed credentials.")
            scheme = parsed.scheme.lower()
            host = (parsed.hostname or "").lower().strip("[]").rstrip(".")
            if not host:
                raise RuntimeError("Release URL is missing a hostname.")
            try:
                port = parsed.port or (443 if scheme == "https" else 80)
            except ValueError as exc:
                raise RuntimeError("Release URL has an invalid port.") from exc

            is_loopback_hop = host in ("127.0.0.1", "localhost", "::1")
            if self._allow_loopback_release_api and is_loopback_hop:
                if scheme not in ("http", "https"):
                    raise RuntimeError(f'Unsupported scheme "{scheme}" in release URL.')
            else:
                if scheme != "https":
                    raise RuntimeError("Release downloads must use https://.")
                if host not in ALLOWED_RELEASE_DOWNLOAD_HOSTS and host != api_host:
                    raise RuntimeError(f'Blocked disallowed release download host "{host}".')

            req_path = parsed.path or "/"
            if parsed.query:
                req_path = f"{req_path}?{parsed.query}"

            headers: dict[str, str] = {
                "Accept": accept,
                "User-Agent": "VPSAgent/2.1",
                "Connection": "close",
            }
            if (
                self.release_github_token
                and host == api_host
                and port == api_port
                and (scheme == "https" or self._allow_loopback_release_api)
            ):
                headers["Authorization"] = f"Bearer {self.release_github_token}"

            conn: http.client.HTTPConnection
            if self._allow_loopback_release_api and is_loopback_hop:
                if scheme == "https":
                    conn = http.client.HTTPSConnection(host, port=port, timeout=timeout)
                else:
                    conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
            else:
                resolver = self.dns_resolver or default_dns_resolver
                resolved_ips = resolver(host, port)
                if not resolved_ips:
                    raise RuntimeError(f'Could not resolve release host "{host}".')
                validated_ips: list[str] = []
                for ip_str in resolved_ips:
                    _assert_public_ip_address(ip_str, host)
                    clean_ip = ip_str.strip().strip("[]").split("%", 1)[0]
                    if clean_ip not in validated_ips:
                        validated_ips.append(clean_ip)
                conn = _PinnedHTTPSConnection(host, port, validated_ips, timeout=timeout)

            try:
                conn.request("GET", req_path, headers=headers)
                resp = conn.getresponse()
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                if resp.status in (301, 302, 303, 307, 308):
                    resp.read(8192)
                    location = resp.getheader("Location")
                    if not location:
                        raise RuntimeError(
                            f"Release download returned redirect ({resp.status}) without Location."
                        )
                    current_url = urljoin(current_url, location.strip())
                    continue

                if stream_to_file is not None and 200 <= resp.status < 300:
                    hasher = hashlib.sha256()
                    total = 0
                    with open(stream_to_file, "wb") as out_fh:
                        while True:
                            chunk = resp.read(65536)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > max_bytes:
                                raise RuntimeError(
                                    "Release download exceeded maximum allowed size."
                                )
                            hasher.update(chunk)
                            out_fh.write(chunk)
                    return resp.status, resp_headers, None, hasher.hexdigest()

                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(
                            "Release response exceeded maximum allowed size."
                        )
                    chunks.append(chunk)
                return resp.status, resp_headers, b"".join(chunks), None
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        raise RuntimeError("Release download exceeded maximum redirect limit.")

    def _select_asset_download_url(self, asset: dict[str, Any]) -> str | None:
        raw_api = asset.get("url")
        raw_browser = asset.get("browser_download_url")
        api_url = (
            raw_api.strip()
            if isinstance(raw_api, str) and raw_api.strip()
            else None
        )
        browser_url = (
            raw_browser.strip()
            if isinstance(raw_browser, str) and raw_browser.strip()
            else None
        )
        if self.release_github_token and api_url:
            try:
                api_base = urlparse(self.release_api_base)
                base_scheme = api_base.scheme.lower()
                base_host = (api_base.hostname or "").lower().strip("[]").rstrip(".")
                base_port = api_base.port or (443 if base_scheme == "https" else 80)

                cand = urlparse(api_url)
                cand_scheme = cand.scheme.lower()
                cand_host = (cand.hostname or "").lower().strip("[]").rstrip(".")
                cand_port = cand.port or (443 if cand_scheme == "https" else 80)
                if (cand_scheme, cand_host, cand_port) == (
                    base_scheme,
                    base_host,
                    base_port,
                ):
                    return api_url
            except ValueError:
                pass
        return browser_url or api_url

    def _parse_github_release_payload(
        self, release_repo: str, rel: dict[str, Any]
    ) -> dict[str, Any] | None:
        raw_tag = rel.get("tag_name")
        if not isinstance(raw_tag, str) or not RELEASE_TAG_PATTERN.match(raw_tag.strip()):
            return None
        tag = raw_tag.strip()
        raw_html = rel.get("html_url")
        html_url = (
            raw_html.strip()
            if isinstance(raw_html, str)
            and (
                raw_html.strip().startswith("https://")
                or (
                    self._allow_loopback_release_api
                    and raw_html.strip().startswith("http://")
                )
            )
            else None
        )
        raw_name = rel.get("name")
        release_name = (
            redact_secrets(raw_name.strip())[:200]
            if isinstance(raw_name, str) and raw_name.strip()
            else tag
        )
        raw_body = rel.get("body")
        release_notes: str | None = None
        if isinstance(raw_body, str) and raw_body.strip():
            cleaned_body = redact_secrets(raw_body.strip())
            if len(cleaned_body) > MAX_RELEASE_NOTES_CHARS:
                cleaned_body = cleaned_body[:MAX_RELEASE_NOTES_CHARS].rstrip() + "..."
            release_notes = cleaned_body
        published_at = (
            rel.get("published_at").strip()
            if isinstance(rel.get("published_at"), str)
            and rel.get("published_at").strip()
            else None
        )
        prerelease = bool(rel.get("prerelease"))

        assets_raw = rel.get("assets")
        assets = (
            [a for a in assets_raw if isinstance(a, dict)]
            if isinstance(assets_raw, list)
            else []
        )

        tar_candidates: list[dict[str, Any]] = []
        checksum_assets: list[dict[str, Any]] = []
        for asset in assets:
            name = asset.get("name")
            dl_s = self._select_asset_download_url(asset)
            if not isinstance(name, str) or not dl_s:
                continue
            name_s = name.strip()
            if not name_s:
                continue
            lower_name = name_s.lower()
            if lower_name.endswith((".sha256", ".sha256sum")) or lower_name in (
                "sha256sums",
                "sha256sums.txt",
                "checksums.txt",
            ):
                checksum_assets.append(asset)
                continue
            if lower_name.endswith((".tar.gz", ".tgz")):
                tar_candidates.append(asset)

        chosen_asset: dict[str, Any] | None = None
        if tar_candidates:
            tar_candidates.sort(
                key=lambda a: (
                    0 if str(a.get("name", "")).lower().startswith("vpsagent") else 1,
                    str(a.get("name", "")).lower(),
                )
            )
            chosen_asset = tar_candidates[0]

        asset_name: str | None = None
        download_url: str | None = None
        asset_digest_sha256: str | None = None
        checksum_url: str | None = None
        checksum_asset_name: str | None = None

        if chosen_asset is not None:
            asset_name = str(chosen_asset.get("name", "")).strip() or None
            download_url = self._select_asset_download_url(chosen_asset)
            raw_digest = chosen_asset.get("digest")
            if isinstance(raw_digest, str) and raw_digest.lower().startswith("sha256:"):
                hex_part = raw_digest.split(":", 1)[1].strip()
                if SHA256_HEX_PATTERN.match(hex_part):
                    asset_digest_sha256 = hex_part.lower()

            if asset_name and checksum_assets:
                exact_names = (f"{asset_name}.sha256", f"{asset_name}.sha256sum")
                for cs in checksum_assets:
                    cs_name = str(cs.get("name", "")).strip()
                    if cs_name in exact_names:
                        checksum_url = self._select_asset_download_url(cs)
                        checksum_asset_name = cs_name
                        break
                if checksum_url is None:
                    for cs in checksum_assets:
                        cs_name = str(cs.get("name", "")).strip()
                        if cs_name.lower() in (
                            "sha256sums",
                            "sha256sums.txt",
                            "checksums.txt",
                        ):
                            checksum_url = self._select_asset_download_url(cs)
                            checksum_asset_name = cs_name
                            break
        else:
            raw_tarball = rel.get("tarball_url")
            if isinstance(raw_tarball, str) and raw_tarball.strip():
                download_url = raw_tarball.strip()

        if not download_url:
            return None

        return {
            "status": "ok",
            "releaseRepo": release_repo,
            "tag": tag,
            "version": normalize_version_label(tag) or tag,
            "name": release_name,
            "htmlUrl": html_url,
            "notes": release_notes,
            "publishedAt": published_at,
            "prerelease": prerelease,
            "assetName": asset_name,
            "downloadUrl": download_url,
            "checksumUrl": checksum_url,
            "checksumAssetName": checksum_asset_name,
            "assetDigestSha256": asset_digest_sha256,
            "checksumAvailable": bool(checksum_url or asset_digest_sha256),
        }

    def _fetch_latest_github_release(self, release_repo: str) -> dict[str, Any]:
        latest_url = f"{self.release_api_base}/repos/{release_repo}/releases/latest"
        try:
            status, _headers, body, _ = self._fetch_release_http(
                latest_url,
                accept="application/vnd.github+json",
                max_bytes=MAX_RELEASE_JSON_BYTES,
                timeout=15.0,
            )
            if status == 200 and body is not None:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict) and not parsed.get("draft"):
                    info = self._parse_github_release_payload(release_repo, parsed)
                    if info is not None:
                        return info

            if status in (403, 429):
                return {
                    "status": "unavailable",
                    "releaseRepo": release_repo,
                    "note": "GitHub Releases API rate limit reached. Try again later.",
                }

            if status != 404 and status != 200:
                return {
                    "status": "unavailable",
                    "releaseRepo": release_repo,
                    "note": f"GitHub Releases check returned HTTP {status}.",
                }

            # Fallback to releases list (handles pre-releases or when /latest has no stable release)
            list_url = f"{self.release_api_base}/repos/{release_repo}/releases?per_page=10"
            list_status, _lh, list_body, _ = self._fetch_release_http(
                list_url,
                accept="application/vnd.github+json",
                max_bytes=MAX_RELEASE_JSON_BYTES,
                timeout=15.0,
            )
            if list_status == 404:
                return {
                    "status": "no_releases",
                    "releaseRepo": release_repo,
                    "note": f"No GitHub release published yet for {release_repo}.",
                }
            if list_status in (403, 429):
                return {
                    "status": "unavailable",
                    "releaseRepo": release_repo,
                    "note": "GitHub Releases API rate limit reached. Try again later.",
                }
            if list_status != 200 or list_body is None:
                return {
                    "status": "unavailable",
                    "releaseRepo": release_repo,
                    "note": f"GitHub Releases check returned HTTP {list_status}.",
                }

            raw_list = json.loads(list_body.decode("utf-8"))
            if not isinstance(raw_list, list):
                return {
                    "status": "unavailable",
                    "releaseRepo": release_repo,
                    "note": "GitHub Releases returned an unexpected response.",
                }

            candidates: list[dict[str, Any]] = []
            for item in raw_list:
                if not isinstance(item, dict) or item.get("draft"):
                    continue
                parsed_rel = self._parse_github_release_payload(release_repo, item)
                if parsed_rel is not None:
                    candidates.append(parsed_rel)

            if not candidates:
                return {
                    "status": "no_releases",
                    "releaseRepo": release_repo,
                    "note": f"No GitHub release published yet for {release_repo}.",
                }

            best = candidates[0]
            for cand in candidates[1:]:
                cmp_val = compare_versions(best["version"], cand["version"])
                if cmp_val is not None and cmp_val < 0:
                    best = cand
            return best
        except (
            OSError,
            http.client.HTTPException,
            RuntimeError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            scrubbed = _scrub_secret_values(
                str(exc),
                [self.release_github_token] if self.release_github_token else None,
            )
            return {
                "status": "unavailable",
                "releaseRepo": release_repo,
                "note": f"Could not reach GitHub Releases: {scrubbed}",
            }

    def _inspect_core_repo(self) -> dict[str, Any]:
        repo_dir = self.repo_dir
        has_core_env = os.path.isfile(os.path.join(self.vpsagent_root, ".env"))
        if not repo_dir or not os.path.isdir(repo_dir):
            return {
                "hasGit": False,
                "hasLocalSource": False,
                "canGitUpdate": False,
                "canReleaseUpdate": bool(has_core_env),
                "canUpdate": False,
                "unavailableReason": (
                    "Click \"Check for updates\" to look for a published GitHub release."
                    if has_core_env
                    else "VPSAgent source folder is not configured on this server."
                ),
                "repoDir": repo_dir,
                "branch": None,
                "originUrl": None,
                "installedFrom": "unknown",
                "releaseRepo": None,
                "currentReleaseTag": None,
                "currentVersion": None,
                "currentCommit": None,
                "dirtyWorkingTree": False,
                "divergedBranch": False,
                "hasCoreEnv": has_core_env,
            }

        has_local_source = os.path.isfile(
            os.path.join(repo_dir, "bootstrap", "docker-compose.core.yml")
        )
        pkg_version = self._read_repo_package_version(repo_dir)
        release_meta = self._read_release_metadata(repo_dir)
        current_release_tag = (
            str(release_meta.get("tag")).strip()
            if release_meta and isinstance(release_meta.get("tag"), str) and release_meta.get("tag").strip()
            else None
        )
        meta_release_repo = (
            str(release_meta.get("releaseRepo")).strip()
            if release_meta
            and isinstance(release_meta.get("releaseRepo"), str)
            and release_meta.get("releaseRepo").strip()
            else None
        )
        meta_commit = (
            str(release_meta.get("commit")).strip()
            if release_meta and isinstance(release_meta.get("commit"), str) and release_meta.get("commit").strip()
            else None
        )
        tag_version = (
            normalize_version_label(current_release_tag)
            if current_release_tag and parse_semver(current_release_tag) is not None
            else None
        )
        meta_version = (
            release_meta["version"].strip() or None
            if release_meta and isinstance(release_meta.get("version"), str)
            else None
        )

        git_dir = os.path.join(repo_dir, ".git")
        if not os.path.exists(git_dir):
            installed_from = "release" if release_meta else "unknown"
            version = (
                tag_version or meta_version or pkg_version
                if release_meta
                else pkg_version or tag_version or meta_version
            )
            can_release = bool(has_core_env)
            reason = (
                None
                if can_release
                else f"Core .env file not found in {self.vpsagent_root}."
            )
            return {
                "hasGit": False,
                "hasLocalSource": has_local_source,
                "canGitUpdate": False,
                "canReleaseUpdate": can_release,
                "canUpdate": can_release,
                "unavailableReason": reason,
                "repoDir": repo_dir,
                "branch": None,
                "originUrl": None,
                "installedFrom": installed_from,
                "releaseRepo": meta_release_repo,
                "currentReleaseTag": current_release_tag,
                "currentVersion": version,
                "currentCommit": meta_commit,
                "dirtyWorkingTree": False,
                "divergedBranch": False,
                "hasCoreEnv": has_core_env,
            }

        version = pkg_version or tag_version or meta_version
        head_proc = self._run_repo_git(repo_dir, ["rev-parse", "HEAD"], timeout=10)
        head_err = (head_proc.stderr or "").strip()
        if head_proc.returncode != 0 and "dubious ownership" in head_err.lower():
            return {
                "hasGit": True,
                "hasLocalSource": has_local_source,
                "canGitUpdate": False,
                "canReleaseUpdate": bool(has_core_env),
                "canUpdate": False,
                "unavailableReason": "Git refused access to the VPSAgent folder due to directory ownership mismatch.",
                "repoDir": repo_dir,
                "branch": None,
                "originUrl": None,
                "installedFrom": "git",
                "releaseRepo": meta_release_repo,
                "currentReleaseTag": current_release_tag,
                "currentVersion": version,
                "currentCommit": None,
                "dirtyWorkingTree": False,
                "divergedBranch": False,
                "hasCoreEnv": has_core_env,
            }
        current_commit = (
            (head_proc.stdout or "").strip() if head_proc.returncode == 0 else None
        ) or None

        branch_proc = self._run_repo_git(
            repo_dir, ["rev-parse", "--abbrev-ref", "HEAD"], timeout=10
        )
        raw_branch = (
            (branch_proc.stdout or "").strip() if branch_proc.returncode == 0 else ""
        )
        if not raw_branch or raw_branch == "HEAD":
            branch = os.environ.get("VPSAGENT_REPO_REF", "main").strip() or "main"
        else:
            branch = raw_branch

        status_proc = self._run_repo_git(
            repo_dir, ["status", "--porcelain"], timeout=10
        )
        dirty = (
            bool((status_proc.stdout or "").strip())
            if status_proc.returncode == 0
            else False
        )

        remote_proc = self._run_repo_git(
            repo_dir, ["remote", "get-url", "origin"], timeout=10
        )
        if remote_proc.returncode != 0 or not (remote_proc.stdout or "").strip():
            remote_err = (remote_proc.stderr or "").strip()
            if "dubious ownership" in remote_err.lower():
                reason = "Git refused access to the VPSAgent folder due to directory ownership mismatch."
            elif "permission denied" in remote_err.lower():
                reason = "Permission denied while inspecting the VPSAgent Git repository."
            else:
                reason = "No 'origin' Git remote is configured for VPSAgent."
            return {
                "hasGit": True,
                "hasLocalSource": has_local_source,
                "canGitUpdate": False,
                "canReleaseUpdate": bool(has_core_env and not dirty),
                "canUpdate": False,
                "unavailableReason": reason,
                "repoDir": repo_dir,
                "branch": branch,
                "originUrl": None,
                "installedFrom": "git",
                "releaseRepo": meta_release_repo,
                "currentReleaseTag": current_release_tag,
                "currentVersion": version,
                "currentCommit": current_commit,
                "dirtyWorkingTree": dirty,
                "divergedBranch": False,
                "hasCoreEnv": has_core_env,
            }

        origin_url = (remote_proc.stdout or "").strip()
        diverged = False
        if current_commit:
            remote_ref = f"origin/{branch}"
            ref_exists = self._run_repo_git(
                repo_dir, ["rev-parse", "--verify", remote_ref], timeout=10
            )
            if ref_exists.returncode == 0:
                anc_proc = self._run_repo_git(
                    repo_dir,
                    ["merge-base", "--is-ancestor", "HEAD", remote_ref],
                    timeout=10,
                )
                if anc_proc.returncode == 1:
                    diverged = True

        if dirty:
            unavailable_reason: str | None = (
                "Local edits exist in the VPSAgent source folder. Clean or commit them before updating."
            )
        elif diverged:
            unavailable_reason = (
                f"Local commits on '{branch}' have diverged from origin/{branch}. "
                "Reconcile the branch before using one-click updates."
            )
        else:
            unavailable_reason = None

        return {
            "hasGit": True,
            "hasLocalSource": has_local_source,
            "canGitUpdate": not dirty and not diverged,
            "canReleaseUpdate": bool(has_core_env and not dirty),
            "canUpdate": not dirty and not diverged,
            "unavailableReason": unavailable_reason,
            "repoDir": repo_dir,
            "branch": branch,
            "originUrl": origin_url,
            "installedFrom": "git",
            "releaseRepo": meta_release_repo,
            "currentReleaseTag": current_release_tag,
            "currentVersion": version,
            "currentCommit": current_commit,
            "dirtyWorkingTree": dirty,
            "divergedBranch": diverged,
            "hasCoreEnv": has_core_env,
        }

    def _build_update_status_response(
        self, repo_info: dict[str, Any], state: dict[str, Any]
    ) -> dict[str, Any]:
        resolved_release_repo = state.get("releaseRepo") or self._resolve_release_repo(repo_info)
        update_source = state.get("updateSource") or "none"
        if update_source not in ("release", "git", "none"):
            update_source = "none"
        release_status = state.get("releaseStatus") or "unchecked"
        if release_status not in (
            "unchecked",
            "available",
            "up_to_date",
            "no_releases",
            "unavailable",
        ):
            release_status = "unchecked"

        if update_source == "none":
            if repo_info.get("installedFrom") == "release" or not repo_info.get("hasGit"):
                update_source = "release" if resolved_release_repo else "none"
            else:
                update_source = "git"

        can_update = bool(repo_info.get("canUpdate"))
        unavailable_reason = repo_info.get("unavailableReason")
        if repo_info.get("dirtyWorkingTree"):
            can_update = False
        elif update_source == "release":
            if not repo_info.get("hasCoreEnv"):
                can_update = False
                unavailable_reason = f"Core .env file not found in {self.vpsagent_root}."
            elif state.get("_releaseDownloadUrl"):
                can_update = True
                unavailable_reason = None
            elif not repo_info.get("hasGit") and repo_info.get("hasLocalSource"):
                can_update = True
                unavailable_reason = None
            elif release_status in ("no_releases", "unavailable"):
                can_update = False
                unavailable_reason = (
                    state.get("releaseNote")
                    or "No GitHub release is published yet to update from."
                )
            elif release_status == "up_to_date":
                can_update = False
                unavailable_reason = (
                    state.get("releaseNote")
                    or "Installed version is newer than the latest published release."
                )
            elif resolved_release_repo and release_status == "unchecked":
                can_update = True
                unavailable_reason = None
            else:
                can_update = False
        else:
            can_update = bool(repo_info.get("canGitUpdate"))

        return {
            "state": state.get("state", "idle"),
            "phase": state.get("phase"),
            "canUpdate": can_update,
            "unavailableReason": unavailable_reason,
            "repoDir": repo_info["repoDir"],
            "branch": repo_info["branch"],
            "updateSource": update_source,
            "releaseRepo": resolved_release_repo,
            "releaseStatus": release_status,
            "releaseNote": redact_secrets(state["releaseNote"])
            if isinstance(state.get("releaseNote"), str)
            else None,
            "installedFrom": repo_info.get("installedFrom", "unknown"),
            "currentVersion": repo_info["currentVersion"],
            "currentReleaseTag": repo_info.get("currentReleaseTag"),
            "currentCommit": repo_info["currentCommit"],
            "latestVersion": state.get("latestVersion"),
            "latestReleaseTag": state.get("latestReleaseTag"),
            "latestReleaseName": redact_secrets(state["latestReleaseName"])
            if isinstance(state.get("latestReleaseName"), str)
            else None,
            "latestReleaseUrl": state.get("latestReleaseUrl"),
            "latestReleaseNotes": redact_secrets(state["latestReleaseNotes"])
            if isinstance(state.get("latestReleaseNotes"), str)
            else None,
            "latestReleasePublishedAt": state.get("latestReleasePublishedAt"),
            "latestReleasePrerelease": bool(state.get("latestReleasePrerelease")),
            "latestReleaseAssetName": state.get("latestReleaseAssetName"),
            "checksumAvailable": bool(state.get("checksumAvailable")),
            "checksumStatus": state.get("checksumStatus") or "none",
            "checksumSha256": state.get("checksumSha256"),
            "latestCommit": state.get("latestCommit"),
            "latestCommitSubject": state.get("latestCommitSubject"),
            "latestCommitDate": state.get("latestCommitDate"),
            "commitsBehind": int(state.get("commitsBehind") or 0),
            "updateAvailable": bool(state.get("updateAvailable")),
            "dirtyWorkingTree": bool(repo_info["dirtyWorkingTree"]),
            "checkedAt": state.get("checkedAt"),
            "startedAt": state.get("startedAt"),
            "finishedAt": state.get("finishedAt"),
            "message": redact_secrets(state["message"])
            if isinstance(state.get("message"), str)
            else None,
            "error": redact_secrets(state["error"])
            if isinstance(state.get("error"), str)
            else None,
            "logs": [
                redact_secrets(str(line))[:MAX_LOG_LINE_CHARS]
                for line in (state.get("logs") or [])
            ][-MAX_BUILD_LOG_LINES:],
        }

    def core_update_status(self, *, check_remote: bool = False) -> dict[str, Any]:
        with self._update_lock:
            is_updating = self._update_state.get("state") == "updating"
            snapshot = dict(self._update_state)
        repo_info = self._inspect_core_repo()

        if check_remote and not is_updating:
            release_repo = self._resolve_release_repo(repo_info)
            release_result: dict[str, Any] | None = None
            if release_repo:
                release_result = self._fetch_latest_github_release(release_repo)

            has_installable_release = bool(
                release_result and release_result.get("status") == "ok"
            )
            release_newer = False
            if has_installable_release and release_result is not None:
                release_newer = is_release_newer(
                    repo_info["currentVersion"],
                    release_result["tag"],
                    current_release_tag=repo_info.get("currentReleaseTag"),
                )

            latest_commit: str | None = None
            latest_subject: str | None = None
            latest_date: str | None = None
            commits_behind = 0

            # Skip git fetch completely once GitHub Releases already offers a newer release
            if (
                not (has_installable_release and release_newer)
                and repo_info.get("hasGit")
                and repo_info["repoDir"]
                and repo_info["branch"]
            ):
                repo_dir = repo_info["repoDir"]
                branch = repo_info["branch"]
                git_fetch_timeout = 15 if has_installable_release else 30
                fetch_proc: subprocess.CompletedProcess[str] | None = None
                try:
                    fetch_proc = self._run_repo_git(
                        repo_dir,
                        ["fetch", "--prune", "origin", branch],
                        timeout=git_fetch_timeout,
                    )
                except BridgeRequestError:
                    if not has_installable_release:
                        raise
                    fetch_proc = None

                if fetch_proc is not None and fetch_proc.returncode != 0:
                    if not has_installable_release:
                        detail = (
                            fetch_proc.stderr
                            or fetch_proc.stdout
                            or "git fetch failed"
                        ).strip()
                        raise BridgeRequestError(
                            502,
                            f"Could not check for updates: {redact_secrets(detail)}",
                        )
                elif fetch_proc is not None:
                    # Re-inspect after fetch so diverged-branch status reflects the latest origin/<branch>
                    repo_info = self._inspect_core_repo()
                    remote_ref = f"origin/{branch}"
                    latest_proc = self._run_repo_git(
                        repo_dir, ["rev-parse", remote_ref], timeout=10
                    )
                    latest_commit = (
                        (latest_proc.stdout or "").strip()
                        if latest_proc.returncode == 0
                        else None
                    ) or None

                    meta_proc = self._run_repo_git(
                        repo_dir, ["show", "-s", "--format=%s%n%cI", remote_ref], timeout=10
                    )
                    if meta_proc.returncode == 0:
                        meta_lines = (meta_proc.stdout or "").splitlines()
                        if len(meta_lines) >= 1 and meta_lines[0].strip():
                            latest_subject = redact_secrets(meta_lines[0].strip())[:200]
                        if len(meta_lines) >= 2 and meta_lines[1].strip():
                            latest_date = meta_lines[1].strip()

                    if repo_info["currentCommit"] and latest_commit:
                        count_proc = self._run_repo_git(
                            repo_dir,
                            ["rev-list", "--count", f"HEAD..{remote_ref}"],
                            timeout=10,
                        )
                        if count_proc.returncode == 0:
                            try:
                                commits_behind = max(
                                    0, int((count_proc.stdout or "0").strip())
                                )
                            except ValueError:
                                commits_behind = 0

            can_fast_forward = bool(
                repo_info.get("hasGit") and not repo_info.get("divergedBranch", False)
            )
            git_update_available = bool(
                can_fast_forward
                and latest_commit
                and repo_info["currentCommit"]
                and latest_commit != repo_info["currentCommit"]
                and commits_behind > 0
            )

            now_iso = datetime.now(timezone.utc).isoformat()
            update_source = "none"
            release_status = "unchecked"
            release_note: str | None = None
            update_available = False
            message: str | None = None
            latest_version: str | None = None
            latest_tag: str | None = None
            latest_name: str | None = None
            latest_url: str | None = None
            latest_notes: str | None = None
            latest_published_at: str | None = None
            latest_prerelease = False
            latest_asset_name: str | None = None
            checksum_available = False
            checksum_status = "none"
            dl_url: str | None = None
            cs_url: str | None = None
            cs_asset_name: str | None = None
            asset_digest: str | None = None

            if has_installable_release and release_result is not None:
                latest_tag = release_result["tag"]
                latest_version = release_result["version"]
                latest_name = release_result["name"]
                latest_url = release_result["htmlUrl"]
                latest_notes = release_result["notes"]
                latest_published_at = release_result["publishedAt"]
                latest_prerelease = bool(release_result["prerelease"])
                latest_asset_name = release_result["assetName"]
                checksum_available = bool(release_result["checksumAvailable"])
                checksum_status = "available" if checksum_available else "not_provided"
                dl_url = release_result["downloadUrl"]
                cs_url = release_result["checksumUrl"]
                cs_asset_name = release_result["checksumAssetName"]
                asset_digest = release_result["assetDigestSha256"]

                if release_newer:
                    release_status = "available"
                    update_source = "release"
                    update_available = True
                    message = f"New VPSAgent release {latest_tag} is ready to install."
                else:
                    release_status = "up_to_date"
                    release_older = is_release_older(
                        repo_info["currentVersion"],
                        latest_tag,
                        current_release_tag=repo_info.get("currentReleaseTag"),
                    )
                    if release_older or repo_info.get("hasLocalSource"):
                        # Never cache an older release (or redundant download when local source exists)
                        dl_url = None
                        cs_url = None
                        cs_asset_name = None
                        asset_digest = None
                    if release_older:
                        checksum_available = False
                        checksum_status = "none"

                    if git_update_available:
                        update_source = "git"
                        update_available = True
                        branch_name = repo_info.get("branch") or "main"
                        release_note = (
                            f"Latest published release is {latest_tag}; "
                            f"{commits_behind} newer commit{'s' if commits_behind != 1 else ''} available on {branch_name}."
                        )
                        message = (
                            f"{commits_behind} new update{'s' if commits_behind != 1 else ''} ready to install."
                        )
                    else:
                        update_source = (
                            "release"
                            if not repo_info.get("hasGit")
                            or repo_info.get("installedFrom") == "release"
                            else "git"
                        )
                        update_available = False
                        if release_older:
                            release_note = (
                                f"Installed version is newer than the latest published release ({latest_tag})."
                            )
                        ver = repo_info["currentVersion"]
                        message = (
                            f"VPSAgent v{ver} is up to date."
                            if ver
                            else "VPSAgent is up to date."
                        )
            else:
                if release_result is not None:
                    raw_status = release_result.get("status")
                    release_status = (
                        "no_releases"
                        if raw_status == "no_releases"
                        else "unavailable"
                    )
                    base_note = release_result.get("note")
                else:
                    release_status = "unchecked"
                    base_note = None

                if repo_info.get("hasGit"):
                    update_source = "git"
                    update_available = git_update_available
                    branch_name = repo_info.get("branch") or "main"
                    if release_status == "no_releases":
                        release_note = (
                            f"No GitHub release published yet for {release_repo} — "
                            f"tracking {branch_name} branch instead."
                        )
                    elif release_status == "unavailable" and base_note:
                        release_note = f"{base_note} Tracking {branch_name} branch instead."
                    if not can_fast_forward:
                        message = repo_info["unavailableReason"]
                    elif update_available:
                        message = (
                            f"{commits_behind} new update{'s' if commits_behind != 1 else ''} ready to install."
                        )
                    else:
                        message = "VPSAgent is up to date."
                else:
                    update_source = "release" if release_repo else "none"
                    release_note = base_note
                    message = base_note or repo_info["unavailableReason"]

            with self._update_lock:
                if self._update_state.get("state") != "updating":
                    self._update_state["checkedAt"] = now_iso
                    self._update_state["updateSource"] = update_source
                    self._update_state["releaseRepo"] = release_repo
                    self._update_state["releaseStatus"] = release_status
                    self._update_state["releaseNote"] = release_note
                    self._update_state["latestVersion"] = latest_version
                    self._update_state["latestReleaseTag"] = latest_tag
                    self._update_state["latestReleaseName"] = latest_name
                    self._update_state["latestReleaseUrl"] = latest_url
                    self._update_state["latestReleaseNotes"] = latest_notes
                    self._update_state["latestReleasePublishedAt"] = latest_published_at
                    self._update_state["latestReleasePrerelease"] = latest_prerelease
                    self._update_state["latestReleaseAssetName"] = latest_asset_name
                    self._update_state["checksumAvailable"] = checksum_available
                    self._update_state["checksumStatus"] = checksum_status
                    if self._update_state.get("state") != "succeeded":
                        self._update_state["checksumSha256"] = None
                    self._update_state["latestCommit"] = latest_commit
                    self._update_state["latestCommitSubject"] = latest_subject
                    self._update_state["latestCommitDate"] = latest_date
                    self._update_state["commitsBehind"] = commits_behind
                    self._update_state["updateAvailable"] = update_available
                    self._update_state["_releaseDownloadUrl"] = dl_url
                    self._update_state["_releaseChecksumUrl"] = cs_url
                    self._update_state["_releaseChecksumAssetName"] = cs_asset_name
                    self._update_state["_releaseAssetDigest"] = asset_digest
                    if self._update_state.get("state") in ("idle", "succeeded", "failed"):
                        self._update_state["message"] = message
                    self._persist_update_state(self._update_state)
                snapshot = dict(self._update_state)

        return self._build_update_status_response(repo_info, snapshot)

    def _append_update_log(self, line: str, *, phase: str | None = None, message: str | None = None) -> None:
        cleaned = redact_secrets(line).strip()
        with self._update_lock:
            if phase is not None:
                self._update_state["phase"] = phase
            if message is not None:
                self._update_state["message"] = redact_secrets(message)
            if cleaned:
                logs = list(self._update_state.get("logs") or [])
                logs.append(cleaned[:MAX_LOG_LINE_CHARS])
                self._update_state["logs"] = logs[-MAX_BUILD_LOG_LINES:]
            self._persist_update_state(self._update_state)

    @staticmethod
    def _caddyfile_changed_in_snapshots(
        config_snapshots: list[tuple[str, bytes | None, bytes]],
    ) -> bool:
        for dst_path, old_content, written_content in config_snapshots:
            if (
                os.path.basename(dst_path) == "Caddyfile"
                and old_content != written_content
            ):
                return True
        return False

    def _sync_core_configs(self, repo_dir: str) -> list[tuple[str, bytes | None, bytes]]:
        """
        Copies updated Caddyfile and docker-compose.core.yml into `self.vpsagent_root`
        while snapshotting originals for safe rollback (never touching `00-default.caddy`).
        If any file write fails, restores all previously written files before raising.
        """
        config_snapshots: list[tuple[str, bytes | None, bytes]] = []
        bootstrap_dir = os.path.join(repo_dir, "bootstrap")
        compose_src = os.path.join(bootstrap_dir, "docker-compose.core.yml")
        compose_dst = os.path.join(self.vpsagent_root, "docker-compose.yml")
        caddyfile_src = os.path.join(bootstrap_dir, "Caddyfile")
        caddyfile_dst = os.path.join(self.vpsagent_root, "Caddyfile")

        for src_path, dst_path in (
            (caddyfile_src, caddyfile_dst),
            (compose_src, compose_dst),
        ):
            if os.path.isfile(src_path) and os.path.isdir(self.vpsagent_root):
                old_content: bytes | None = None
                write_started = False
                try:
                    if os.path.isfile(dst_path):
                        with open(dst_path, "rb") as fh:
                            old_content = fh.read()
                    with open(src_path, "rb") as fh:
                        written_content = fh.read()
                    write_started = True
                    with open(dst_path, "wb") as fh:
                        fh.write(written_content)
                except OSError:
                    if write_started:
                        try:
                            if old_content is None:
                                if os.path.isfile(dst_path):
                                    os.unlink(dst_path)
                            else:
                                with open(dst_path, "wb") as rfh:
                                    rfh.write(old_content)
                        except OSError:
                            pass
                    if config_snapshots:
                        self._restore_core_configs(config_snapshots)
                    raise
                config_snapshots.append((dst_path, old_content, written_content))
        return config_snapshots

    def _restore_core_configs(
        self, config_snapshots: list[tuple[str, bytes | None, bytes]]
    ) -> list[str]:
        """
        Restores snapshotted Compose & Caddy config files ONLY if they still match what we wrote
        (never overwrite edits the owner made to active server config during the build).
        """
        rollback_notes: list[str] = []
        restored_files: list[str] = []
        for dst_path, old_content, written_content in reversed(config_snapshots):
            fname = os.path.basename(dst_path)
            try:
                if not os.path.isfile(dst_path):
                    rollback_notes.append(
                        f"Preserved {fname} because it was modified during the build."
                    )
                    continue
                with open(dst_path, "r+b") as fh:
                    current_content = fh.read()
                    if current_content != written_content:
                        rollback_notes.append(
                            f"Preserved {fname} because it was modified during the build."
                        )
                        continue
                    if old_content is not None:
                        fh.seek(0)
                        fh.write(old_content)
                        fh.truncate()
                if old_content is None:
                    os.unlink(dst_path)
                restored_files.append(fname)
            except OSError as restore_exc:
                rollback_notes.append(
                    f"Failed to restore {fname}: {redact_secrets(str(restore_exc))}"
                )
        if restored_files:
            rollback_notes.append(
                f"Restored previous configuration files: {', '.join(restored_files)}."
            )
        return rollback_notes

    def _prune_old_releases(self, releases_dir: str, *, keep_dir: str) -> None:
        try:
            real_releases = os.path.realpath(releases_dir)
            real_keep = os.path.realpath(keep_dir)
            previous_dirs: list[tuple[float, str]] = []
            for entry in os.listdir(real_releases):
                full_path = os.path.join(real_releases, entry)
                if os.path.islink(full_path):
                    continue
                real_entry = os.path.realpath(full_path)
                if not real_entry.startswith(real_releases + os.sep):
                    continue
                if entry.startswith((".tmp-", ".staging-", ".prev-")):
                    shutil.rmtree(real_entry, ignore_errors=True)
                    continue
                if os.path.isdir(real_entry) and real_entry != real_keep:
                    try:
                        mtime = os.stat(real_entry).st_mtime
                    except OSError:
                        mtime = 0.0
                    previous_dirs.append((mtime, real_entry))
            previous_dirs.sort(key=lambda item: item[0], reverse=True)
            for _, old_path in previous_dirs[1:]:
                shutil.rmtree(old_path, ignore_errors=True)
        except OSError:
            pass

    def _run_core_compose_up(
        self,
        source_dir: str,
        *,
        log_output: bool = True,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[str]:
        compose_dst = os.path.join(self.vpsagent_root, "docker-compose.yml")
        env_file = os.path.join(self.vpsagent_root, ".env")
        if not os.path.isfile(compose_dst) or not os.path.isfile(env_file):
            raise RuntimeError(
                f"Core stack files not found in {self.vpsagent_root} (expected docker-compose.yml and .env)."
            )
        proc = subprocess.run(
            [
                self.docker_bin,
                "compose",
                "--project-directory",
                self.vpsagent_root,
                "-f",
                compose_dst,
                "--env-file",
                env_file,
                "up",
                "-d",
                "--build",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "VPSAGENT_REPO_DIR": source_dir},
        )
        if log_output:
            combined_out = (
                (proc.stdout or "") + "\n" + (proc.stderr or "")
            ).splitlines()
            for line in combined_out[-40:]:
                if line.strip():
                    self._append_update_log(line)
        return proc

    def _install_bridge_script_if_changed(
        self, source_dir: str
    ) -> tuple[bool, bytes | None]:
        bridge_src = os.path.join(source_dir, "bootstrap", "runtime-bridge.py")
        bridge_dst = os.path.join(self.vpsagent_root, "runtime-bridge.py")
        if not (os.path.isfile(bridge_src) and os.path.isdir(self.vpsagent_root)):
            return False, None
        with open(bridge_src, "rb") as fh:
            new_bytes = fh.read()
        old_bytes: bytes | None = None
        if os.path.isfile(bridge_dst):
            with open(bridge_dst, "rb") as fh:
                old_bytes = fh.read()
        if old_bytes == new_bytes:
            return False, old_bytes
        tmp_bridge = f"{bridge_dst}.tmp.{os.getpid()}"
        try:
            with open(tmp_bridge, "wb") as fh:
                fh.write(new_bytes)
            os.chmod(tmp_bridge, 0o750)
            os.replace(tmp_bridge, bridge_dst)
            tmp_bridge = None
        finally:
            if tmp_bridge and os.path.lexists(tmp_bridge):
                try:
                    os.unlink(tmp_bridge)
                except OSError:
                    pass
        self._append_update_log(
            "Updated host Runtime Bridge script; scheduling seamless restart...",
            phase="restarting",
            message="Finishing update and restarting background bridge...",
        )
        return True, old_bytes

    def _restore_bridge_script(self, old_bytes: bytes | None) -> str | None:
        bridge_dst = os.path.join(self.vpsagent_root, "runtime-bridge.py")
        rb_tmp = f"{bridge_dst}.rollback.{os.getpid()}"
        try:
            if old_bytes is not None:
                with open(rb_tmp, "wb") as fh:
                    fh.write(old_bytes)
                os.chmod(rb_tmp, 0o750)
                os.replace(rb_tmp, bridge_dst)
                return "Restored previous runtime-bridge.py script."
            if os.path.lexists(bridge_dst):
                os.unlink(bridge_dst)
                return "Removed newly installed runtime-bridge.py script."
        except OSError as exc:
            try:
                if os.path.lexists(rb_tmp):
                    os.unlink(rb_tmp)
            except OSError:
                pass
            return f"Failed to restore runtime-bridge.py: {redact_secrets(str(exc))}"
        return None

    def _rollback_restored_caddy_if_needed(
        self, rollback_notes: list[str], *, was_active: bool
    ) -> None:
        if not was_active:
            return
        if not any(
            "Caddyfile" in note and "Restored previous configuration files" in note
            for note in rollback_notes
        ):
            return
        try:
            with self._caddy_lock:
                self._validate_and_reload_caddy()
            rollback_notes.append("Reloaded Caddy with restored configuration.")
        except Exception as exc:
            rollback_notes.append(
                f"Warning: Caddy reload during rollback failed: {redact_secrets(str(exc))}"
            )

    def _schedule_bridge_restart(self) -> None:
        time.sleep(0.25)
        try:
            is_active = self._run_cmd(
                [self.systemctl_bin, "is-active", "vpsagent-runtime.service"],
                label="systemd",
                timeout=5,
                check=False,
            )
            if is_active.returncode == 0:
                self._run_cmd(
                    [
                        self.systemctl_bin,
                        "restart",
                        "--no-block",
                        "vpsagent-runtime.service",
                    ],
                    label="systemd",
                    timeout=10,
                    check=False,
                )
        except Exception:
            pass

    def start_core_update(self, payload: dict[str, Any]) -> dict[str, Any]:
        requested_source: str | None = None
        if isinstance(payload, dict) and payload.get("source") is not None:
            raw_src = payload.get("source")
            if raw_src not in ("auto", "release", "git"):
                raise BridgeRequestError(
                    400, "Field 'source' must be one of: auto, release, git."
                )
            requested_source = raw_src

        repo_info = self._inspect_core_repo()
        if repo_info.get("dirtyWorkingTree"):
            raise BridgeRequestError(
                400,
                repo_info["unavailableReason"]
                or "Local edits exist in the VPSAgent source folder. Clean or commit them before updating.",
            )

        with self._update_lock:
            if self._update_state.get("state") == "updating":
                raise BridgeRequestError(
                    409, "A VPSAgent update is already in progress."
                )
            prev_source = self._update_state.get("updateSource")
            cached_dl_url = self._update_state.get("_releaseDownloadUrl")
            state_snapshot = dict(self._update_state)

        if requested_source == "release":
            use_release = True
        elif requested_source == "git":
            use_release = False
        else:
            use_release = bool(
                (prev_source == "release" and cached_dl_url)
                or not repo_info.get("hasGit")
            )

        if use_release:
            if not repo_info.get("hasCoreEnv"):
                raise BridgeRequestError(
                    400, f"Core .env file not found in {self.vpsagent_root}."
                )

            if (
                requested_source in (None, "auto")
                and not repo_info.get("hasGit")
                and state_snapshot.get("checkedAt")
                and not state_snapshot.get("updateAvailable")
                and repo_info.get("hasLocalSource")
                and repo_info.get("repoDir")
            ):
                return self._start_local_release_rebuild(repo_info)

            release_target: dict[str, Any]
            if cached_dl_url and state_snapshot.get("latestReleaseTag"):
                release_target = {
                    "releaseRepo": state_snapshot.get("releaseRepo")
                    or self._resolve_release_repo(repo_info)
                    or DEFAULT_RELEASE_REPO,
                    "tag": state_snapshot["latestReleaseTag"],
                    "version": state_snapshot.get("latestVersion")
                    or normalize_version_label(state_snapshot["latestReleaseTag"]),
                    "name": state_snapshot.get("latestReleaseName")
                    or state_snapshot["latestReleaseTag"],
                    "htmlUrl": state_snapshot.get("latestReleaseUrl"),
                    "notes": state_snapshot.get("latestReleaseNotes"),
                    "publishedAt": state_snapshot.get("latestReleasePublishedAt"),
                    "prerelease": bool(state_snapshot.get("latestReleasePrerelease")),
                    "assetName": state_snapshot.get("latestReleaseAssetName"),
                    "downloadUrl": cached_dl_url,
                    "checksumUrl": state_snapshot.get("_releaseChecksumUrl"),
                    "checksumAssetName": state_snapshot.get("_releaseChecksumAssetName"),
                    "assetDigestSha256": state_snapshot.get("_releaseAssetDigest"),
                    "checksumAvailable": bool(state_snapshot.get("checksumAvailable")),
                }
            else:
                release_repo = self._resolve_release_repo(repo_info) or DEFAULT_RELEASE_REPO
                fetched = self._fetch_latest_github_release(release_repo)
                if fetched.get("status") != "ok":
                    raise BridgeRequestError(
                        400,
                        fetched.get("note")
                        or "No GitHub release is available to install yet.",
                    )
                release_target = fetched

            if is_release_older(
                repo_info.get("currentVersion"),
                release_target.get("tag"),
                current_release_tag=repo_info.get("currentReleaseTag"),
            ):
                if (
                    requested_source in (None, "auto")
                    and not repo_info.get("hasGit")
                    and repo_info.get("hasLocalSource")
                    and repo_info.get("repoDir")
                ):
                    return self._start_local_release_rebuild(repo_info)
                cur_label = (
                    repo_info.get("currentReleaseTag")
                    or (
                        f"v{repo_info['currentVersion']}"
                        if repo_info.get("currentVersion")
                        else "current install"
                    )
                )
                raise BridgeRequestError(
                    400,
                    f"Refusing to downgrade VPSAgent from {cur_label} to older release {release_target['tag']}.",
                )

            if (
                not is_release_newer(
                    repo_info.get("currentVersion"),
                    release_target.get("tag"),
                    current_release_tag=repo_info.get("currentReleaseTag"),
                )
                and not repo_info.get("hasGit")
                and repo_info.get("hasLocalSource")
                and repo_info.get("repoDir")
            ):
                return self._start_local_release_rebuild(repo_info)

            now_iso = datetime.now(timezone.utc).isoformat()
            with self._update_lock:
                if self._update_state.get("state") == "updating":
                    raise BridgeRequestError(
                        409, "A VPSAgent update is already in progress."
                    )
                self._update_state = {
                    **self._update_state,
                    "state": "updating",
                    "phase": "downloading",
                    "updateSource": "release",
                    "releaseRepo": release_target["releaseRepo"],
                    "latestVersion": release_target["version"],
                    "latestReleaseTag": release_target["tag"],
                    "latestReleaseName": release_target["name"],
                    "latestReleaseUrl": release_target["htmlUrl"],
                    "latestReleaseNotes": release_target["notes"],
                    "latestReleasePublishedAt": release_target["publishedAt"],
                    "latestReleasePrerelease": bool(release_target["prerelease"]),
                    "latestReleaseAssetName": release_target["assetName"],
                    "checksumAvailable": bool(release_target["checksumAvailable"]),
                    "checksumStatus": (
                        "available"
                        if release_target["checksumAvailable"]
                        else "not_provided"
                    ),
                    "checksumSha256": None,
                    "_releaseDownloadUrl": release_target["downloadUrl"],
                    "_releaseChecksumUrl": release_target["checksumUrl"],
                    "_releaseChecksumAssetName": release_target["checksumAssetName"],
                    "_releaseAssetDigest": release_target["assetDigestSha256"],
                    "startedAt": now_iso,
                    "finishedAt": None,
                    "error": None,
                    "message": f"Downloading VPSAgent {release_target['tag']}...",
                    "logs": [
                        f"Starting VPSAgent update to release {release_target['tag']}..."
                    ],
                }
                self._persist_update_state(self._update_state)
                snapshot = dict(self._update_state)

            worker = threading.Thread(
                target=self._run_core_update_release_worker,
                args=(release_target,),
                name="vpsagent-release-update",
                daemon=False,
            )
            worker.start()

            return {
                "ok": True,
                "started": True,
                "status": self._build_update_status_response(repo_info, snapshot),
            }

        if (
            not repo_info.get("canGitUpdate")
            or not repo_info["repoDir"]
            or not repo_info["branch"]
        ):
            raise BridgeRequestError(
                400,
                repo_info["unavailableReason"]
                or "Automatic updates are not available on this server.",
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._update_lock:
            if self._update_state.get("state") == "updating":
                raise BridgeRequestError(
                    409, "A VPSAgent update is already in progress."
                )
            self._update_state = {
                **self._update_state,
                "state": "updating",
                "phase": "fetching",
                "updateSource": "git",
                "checksumStatus": "none",
                "checksumSha256": None,
                "startedAt": now_iso,
                "finishedAt": None,
                "error": None,
                "message": "Downloading the latest VPSAgent version...",
                "logs": [f"Starting VPSAgent update on branch {repo_info['branch']}..."],
            }
            self._persist_update_state(self._update_state)
            snapshot = dict(self._update_state)

        worker = threading.Thread(
            target=self._run_core_update_worker,
            args=(repo_info["repoDir"], repo_info["branch"]),
            name="vpsagent-self-update",
            daemon=False,
        )
        worker.start()

        return {
            "ok": True,
            "started": True,
            "status": self._build_update_status_response(repo_info, snapshot),
        }

    def _start_local_release_rebuild(self, repo_info: dict[str, Any]) -> dict[str, Any]:
        repo_dir = str(repo_info["repoDir"])
        label = (
            repo_info.get("currentReleaseTag")
            or (
                f"v{repo_info['currentVersion']}"
                if repo_info.get("currentVersion")
                else "installed build"
            )
        )
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._update_lock:
            if self._update_state.get("state") == "updating":
                raise BridgeRequestError(
                    409, "A VPSAgent update is already in progress."
                )
            self._update_state = {
                **self._update_state,
                "state": "updating",
                "phase": "syncing",
                "updateSource": "release",
                "startedAt": now_iso,
                "finishedAt": None,
                "error": None,
                "message": f"Rebuilding VPSAgent {label}...",
                "logs": [f"Starting local rebuild of installed VPSAgent {label}..."],
            }
            self._persist_update_state(self._update_state)
            snapshot = dict(self._update_state)

        worker = threading.Thread(
            target=self._run_core_rebuild_local_worker,
            args=(repo_dir,),
            name="vpsagent-release-rebuild",
            daemon=False,
        )
        worker.start()
        return {
            "ok": True,
            "started": True,
            "status": self._build_update_status_response(repo_info, snapshot),
        }

    def _run_core_rebuild_local_worker(self, repo_dir: str) -> None:
        bridge_changed = False
        bridge_written = False
        old_bridge_bytes: bytes | None = None
        core_activated = False
        caddy_reloaded = False
        config_snapshots: list[tuple[str, bytes | None, bytes]] = []
        try:
            env_file = os.path.join(self.vpsagent_root, ".env")
            if not os.path.isdir(repo_dir):
                raise RuntimeError(f"VPSAgent source directory not found: {repo_dir}.")
            if not os.path.isfile(env_file):
                raise RuntimeError(f"Core .env file not found in {self.vpsagent_root}.")

            self._append_update_log(
                "Syncing VPSAgent configuration files...",
                phase="syncing",
                message="Preparing updated server configuration...",
            )
            config_snapshots = self._sync_core_configs(repo_dir)

            self._append_update_log(
                "Rebuilding and restarting VPSAgent core container...",
                phase="building",
                message="Rebuilding VPSAgent (this usually takes 1-2 minutes)...",
            )
            compose_proc = self._run_core_compose_up(repo_dir)
            if compose_proc.returncode != 0:
                raise RuntimeError(
                    f"Docker rebuild failed (exit {compose_proc.returncode})."
                )
            core_activated = True

            if self._caddyfile_changed_in_snapshots(config_snapshots):
                self._append_update_log("Validating and reloading Caddy configuration...")
                with self._caddy_lock:
                    self._validate_and_reload_caddy()
                caddy_reloaded = True

            bridge_changed, old_bridge_bytes = self._install_bridge_script_if_changed(
                repo_dir
            )
            bridge_written = bridge_changed

            new_info = self._inspect_core_repo()
            label = (
                new_info.get("currentReleaseTag")
                or (
                    f"v{new_info['currentVersion']}"
                    if new_info.get("currentVersion")
                    else "installed build"
                )
            )
            done_msg = f"Rebuilt VPSAgent {label}."
            finished_iso = datetime.now(timezone.utc).isoformat()
            with self._update_lock:
                self._update_state = {
                    **self._update_state,
                    "state": "succeeded",
                    "phase": "completed",
                    "checkedAt": finished_iso,
                    "finishedAt": finished_iso,
                    "updateAvailable": False,
                    "error": None,
                    "message": done_msg,
                    "logs": (list(self._update_state.get("logs") or []) + [done_msg])[
                        -MAX_BUILD_LOG_LINES:
                    ],
                }
                self._persist_update_state(self._update_state)

            if bridge_changed:
                self._schedule_bridge_restart()
        except Exception as exc:
            err_text = redact_secrets(str(exc))
            rollback_notes: list[str] = []
            if bridge_written:
                note = self._restore_bridge_script(old_bridge_bytes)
                if note:
                    rollback_notes.append(note)
            rollback_notes.extend(self._restore_core_configs(config_snapshots))
            self._rollback_restored_caddy_if_needed(
                rollback_notes, was_active=(caddy_reloaded or core_activated)
            )
            if core_activated and os.path.isdir(repo_dir):
                try:
                    self._run_core_compose_up(repo_dir, log_output=False, timeout=300)
                except Exception:
                    pass
            finished_iso = datetime.now(timezone.utc).isoformat()
            with self._update_lock:
                extra_logs = [f"ERROR: {err_text}", *rollback_notes]
                self._update_state = {
                    **self._update_state,
                    "state": "failed",
                    "phase": "failed",
                    "finishedAt": finished_iso,
                    "error": err_text,
                    "message": "VPSAgent rebuild failed.",
                    "logs": (
                        list(self._update_state.get("logs") or []) + extra_logs
                    )[-MAX_BUILD_LOG_LINES:],
                }
                self._persist_update_state(self._update_state)

    def _run_core_update_release_worker(self, release_target: dict[str, Any]) -> None:
        bridge_changed = False
        bridge_written = False
        old_bridge_bytes: bytes | None = None
        core_activated = False
        caddy_reloaded = False
        source_persisted = False
        config_snapshots: list[tuple[str, bytes | None, bytes]] = []
        tmp_dir: str | None = None
        staging_dir: str | None = None
        backup_release_dir: str | None = None
        final_release_dir: str | None = None
        swapped_new_release = False
        checksum_status = "not_provided"
        actual_sha256: str | None = None
        tag = str(release_target["tag"]).strip()
        release_repo = str(release_target.get("releaseRepo") or DEFAULT_RELEASE_REPO)
        prev_repo_dir = self.repo_dir
        active_src_path = _active_source_path(self.vpsagent_root)
        had_active_source = os.path.isfile(active_src_path) and not os.path.islink(
            active_src_path
        )
        prev_active_source_bytes: bytes | None = None
        if had_active_source:
            try:
                with open(active_src_path, "rb") as afh:
                    prev_active_source_bytes = afh.read()
            except OSError:
                prev_active_source_bytes = None

        try:
            repo_info_now = self._inspect_core_repo()
            if is_release_older(
                repo_info_now.get("currentVersion"),
                tag,
                current_release_tag=repo_info_now.get("currentReleaseTag"),
            ):
                cur_label = (
                    repo_info_now.get("currentReleaseTag")
                    or (
                        f"v{repo_info_now['currentVersion']}"
                        if repo_info_now.get("currentVersion")
                        else "current install"
                    )
                )
                raise RuntimeError(
                    f"Refusing to downgrade VPSAgent from {cur_label} to older release {tag}."
                )

            env_file = os.path.join(self.vpsagent_root, ".env")
            if not os.path.isfile(env_file):
                raise RuntimeError(
                    f"Core .env file not found in {self.vpsagent_root}."
                )

            releases_dir = os.path.join(self.vpsagent_root, "releases")
            if os.path.islink(releases_dir):
                raise RuntimeError(
                    f"Security boundary violation: {releases_dir} cannot be a symlink."
                )
            os.makedirs(releases_dir, mode=0o750, exist_ok=True)
            safe_tag = re.sub(r"[^A-Za-z0-9._+-]", "-", tag).strip(".-") or "release"
            if safe_tag in (".", "..") or ".." in safe_tag:
                safe_tag = "release"

            tmp_dir = tempfile.mkdtemp(prefix=".tmp-", dir=releases_dir)
            os.chmod(tmp_dir, 0o700)
            archive_name = release_target.get("assetName") or f"vpsagent-{safe_tag}.tar.gz"
            safe_archive_name = (
                re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(archive_name)).strip(".")
                or f"vpsagent-{safe_tag}.tar.gz"
            )
            archive_path = os.path.join(tmp_dir, safe_archive_name)

            # Step 1: Download release tarball while computing SHA-256
            self._append_update_log(
                f"Downloading release archive for {tag} from {release_repo}...",
                phase="downloading",
                message=f"Downloading VPSAgent {tag}...",
            )
            dl_status, _headers, _body, actual_sha256 = self._fetch_release_http(
                release_target["downloadUrl"],
                accept="application/octet-stream",
                max_bytes=MAX_RELEASE_ARCHIVE_BYTES,
                timeout=120.0,
                stream_to_file=archive_path,
            )
            if dl_status < 200 or dl_status >= 300 or not actual_sha256:
                raise RuntimeError(
                    f"Release download failed with HTTP {dl_status}."
                )
            self._append_update_log(f"Downloaded archive (SHA-256: {actual_sha256[:16]}...).")

            # Step 2: Verify SHA-256 checksum
            self._append_update_log(
                "Verifying release archive integrity...",
                phase="verifying",
                message="Verifying SHA-256 checksum...",
            )
            checksum_url = release_target.get("checksumUrl")
            checksum_asset_name = release_target.get("checksumAssetName") or ""
            asset_digest = release_target.get("assetDigestSha256")
            parsed_checksum: str | None = None

            if checksum_url:
                try:
                    cs_status, _cs_headers, cs_body, _ = self._fetch_release_http(
                        checksum_url,
                        accept="application/octet-stream",
                        max_bytes=MAX_CHECKSUM_FILE_BYTES,
                        timeout=20.0,
                    )
                except Exception as cs_exc:
                    checksum_status = "failed"
                    raise RuntimeError(
                        f"Could not download release checksum file: {cs_exc}"
                    ) from cs_exc
                if cs_status < 200 or cs_status >= 300 or cs_body is None:
                    checksum_status = "failed"
                    raise RuntimeError(
                        f"Could not download release checksum file ({cs_status})."
                    )
                cs_text = cs_body.decode("utf-8", errors="replace")
                allow_bare = checksum_asset_name.lower().endswith(
                    (".sha256", ".sha256sum")
                )
                parsed_checksum = parse_sha256_checksum(
                    cs_text, archive_name, allow_bare_hash=allow_bare
                )
                if not parsed_checksum:
                    checksum_status = "failed"
                    raise RuntimeError(
                        f'Release checksum file "{checksum_asset_name or "SHA256SUMS"}" did not contain a valid SHA-256 entry for {archive_name}.'
                    )

            if parsed_checksum and asset_digest and not hmac.compare_digest(
                parsed_checksum.lower(), str(asset_digest).lower()
            ):
                checksum_status = "failed"
                raise RuntimeError(
                    "Release checksum file disagrees with GitHub asset digest. Update aborted safely."
                )

            expected_sha256 = parsed_checksum or asset_digest
            if expected_sha256:
                if not hmac.compare_digest(
                    actual_sha256.lower(), str(expected_sha256).lower()
                ):
                    checksum_status = "failed"
                    raise RuntimeError(
                        "Release checksum verification failed (SHA-256 mismatch). Update aborted safely."
                    )
                checksum_status = "verified"
                self._append_update_log(
                    f"Verified SHA-256 checksum ({actual_sha256[:16]}...)."
                )
            else:
                checksum_status = "not_provided"
                self._append_update_log(
                    f"Archive SHA-256: {actual_sha256[:16]}... (no checksum asset published for this release)."
                )

            # Step 3: Safely extract into staging dir and validate structure
            self._append_update_log(
                f"Extracting VPSAgent {tag}...",
                phase="extracting",
                message=f"Extracting VPSAgent {tag}...",
            )
            staging_dir = tempfile.mkdtemp(prefix=f".staging-{safe_tag}-", dir=releases_dir)
            os.chmod(staging_dir, 0o755)
            extracted = safe_extract_release_tarball(archive_path, staging_dir)
            tag_version = (
                normalize_version_label(tag) if parse_semver(tag) is not None else None
            )
            resolved_ver = (
                tag_version
                or release_target.get("version")
                or extracted.get("version")
                or normalize_version_label(tag)
                or tag
            )
            meta_payload = {
                "tag": tag,
                "version": resolved_ver,
                "releaseRepo": release_repo,
                "releaseUrl": release_target.get("htmlUrl"),
                "sha256": actual_sha256,
                "checksumStatus": checksum_status,
                "installedAt": datetime.now(timezone.utc).isoformat(),
            }
            meta_path = os.path.join(staging_dir, ".vpsagent-release.json")
            with open(meta_path, "w", encoding="utf-8") as mfh:
                json.dump(meta_payload, mfh, indent=2)
            os.chmod(meta_path, 0o644)

            final_release_dir = os.path.join(releases_dir, safe_tag)
            real_releases = os.path.realpath(releases_dir)
            if not os.path.abspath(final_release_dir).startswith(real_releases + os.sep):
                raise RuntimeError("Invalid release directory path.")
            if os.path.lexists(final_release_dir):
                backup_release_dir = os.path.join(
                    releases_dir, f".prev-{safe_tag}-{os.getpid()}"
                )
                os.replace(final_release_dir, backup_release_dir)
            os.replace(staging_dir, final_release_dir)
            staging_dir = None
            swapped_new_release = True
            os.chmod(final_release_dir, 0o755)

            # Step 4: Snapshot & sync Caddyfile + docker-compose.yml (never touches 00-default.caddy)
            self._append_update_log(
                "Syncing VPSAgent configuration files...",
                phase="syncing",
                message="Preparing updated server configuration...",
            )
            config_snapshots = self._sync_core_configs(final_release_dir)

            # Step 5: Rebuild & restart vpsagent-core container
            self._append_update_log(
                "Rebuilding and restarting VPSAgent core container...",
                phase="building",
                message="Rebuilding VPSAgent (this usually takes 1-2 minutes)...",
            )
            compose_proc = self._run_core_compose_up(final_release_dir)
            if compose_proc.returncode != 0:
                raise RuntimeError(
                    f"Docker rebuild failed (exit {compose_proc.returncode})."
                )
            core_activated = True

            # Step 5b: Validate and reload Caddy if Caddyfile changed
            if self._caddyfile_changed_in_snapshots(config_snapshots):
                self._append_update_log("Validating and reloading Caddy configuration...")
                with self._caddy_lock:
                    self._validate_and_reload_caddy()
                caddy_reloaded = True

            # Step 6: Install updated runtime-bridge.py if changed (before persisting active-source.json)
            bridge_changed, old_bridge_bytes = self._install_bridge_script_if_changed(
                final_release_dir
            )
            bridge_written = bridge_changed

            # Step 7: Persist non-secret active-source pointer cleanly (never reads or rewrites .env)
            _write_active_source_file(
                self.vpsagent_root,
                final_release_dir,
                release_tag=tag,
                release_repo=release_repo,
            )
            self.repo_dir = final_release_dir
            source_persisted = True

            if backup_release_dir and os.path.isdir(backup_release_dir):
                shutil.rmtree(backup_release_dir, ignore_errors=True)
                backup_release_dir = None
            self._prune_old_releases(releases_dir, keep_dir=final_release_dir)

            finished_iso = datetime.now(timezone.utc).isoformat()
            done_msg = (
                f"Updated VPSAgent to {tag} (SHA-256 verified)."
                if checksum_status == "verified"
                else f"Updated VPSAgent to {tag}."
            )
            with self._update_lock:
                self._update_state = {
                    **self._update_state,
                    "state": "succeeded",
                    "phase": "completed",
                    "updateSource": "release",
                    "releaseStatus": "up_to_date",
                    "releaseNote": None,
                    "checkedAt": finished_iso,
                    "finishedAt": finished_iso,
                    "latestVersion": resolved_ver,
                    "latestReleaseTag": tag,
                    "checksumStatus": checksum_status,
                    "checksumSha256": actual_sha256,
                    "commitsBehind": 0,
                    "updateAvailable": False,
                    "error": None,
                    "message": done_msg,
                    "logs": (list(self._update_state.get("logs") or []) + [done_msg])[
                        -MAX_BUILD_LOG_LINES:
                    ],
                }
                self._persist_update_state(self._update_state)

            if bridge_changed:
                self._schedule_bridge_restart()
        except Exception as exc:
            err_text = _scrub_secret_values(
                str(exc),
                [self.release_github_token] if self.release_github_token else None,
            )
            rollback_notes: list[str] = []
            if source_persisted:
                self.repo_dir = prev_repo_dir
                try:
                    if had_active_source and prev_active_source_bytes is not None:
                        tmp_act = f"{active_src_path}.rollback.{os.getpid()}"
                        with open(tmp_act, "wb") as afh:
                            afh.write(prev_active_source_bytes)
                        os.chmod(tmp_act, 0o644)
                        os.replace(tmp_act, active_src_path)
                    elif os.path.lexists(active_src_path):
                        os.unlink(active_src_path)
                    rollback_notes.append("Restored previous active source pointer.")
                except OSError as src_exc:
                    rollback_notes.append(
                        f"Failed to restore active source pointer: {redact_secrets(str(src_exc))}"
                    )

            if bridge_written:
                note = self._restore_bridge_script(old_bridge_bytes)
                if note:
                    rollback_notes.append(note)

            rollback_notes.extend(self._restore_core_configs(config_snapshots))
            self._rollback_restored_caddy_if_needed(
                rollback_notes, was_active=(caddy_reloaded or core_activated)
            )

            stack_rolled_back = False
            if core_activated and prev_repo_dir and os.path.isdir(prev_repo_dir):
                try:
                    rb_proc = self._run_core_compose_up(
                        prev_repo_dir, log_output=False, timeout=300
                    )
                    if rb_proc.returncode == 0:
                        stack_rolled_back = True
                        rollback_notes.append(
                            "Rebuilt core container back to previous source."
                        )
                except Exception:
                    pass

            has_same_tag_backup = bool(
                backup_release_dir and os.path.isdir(backup_release_dir)
            )
            can_remove_new_release = bool(
                not core_activated
                or has_same_tag_backup
                or (stack_rolled_back and self.repo_dir != final_release_dir)
            )
            if final_release_dir and can_remove_new_release and (
                swapped_new_release or has_same_tag_backup
            ):
                try:
                    if os.path.isdir(final_release_dir):
                        shutil.rmtree(final_release_dir, ignore_errors=True)
                    if backup_release_dir and os.path.isdir(backup_release_dir):
                        os.replace(backup_release_dir, final_release_dir)
                        backup_release_dir = None
                        rollback_notes.append(
                            f"Restored previous release directory {tag}."
                        )
                except OSError:
                    pass
            elif (
                core_activated
                and final_release_dir
                and os.path.isdir(final_release_dir)
                and not can_remove_new_release
            ):
                rollback_notes.append(
                    f"Preserved {final_release_dir} because the new core container was already started and rollback did not revert it."
                )

            finished_iso = datetime.now(timezone.utc).isoformat()
            with self._update_lock:
                extra_logs = [f"ERROR: {err_text}", *rollback_notes]
                self._update_state = {
                    **self._update_state,
                    "state": "failed",
                    "phase": "failed",
                    "checksumStatus": (
                        "failed"
                        if checksum_status == "failed"
                        else self._update_state.get("checksumStatus", "none")
                    ),
                    "finishedAt": finished_iso,
                    "error": err_text,
                    "message": "VPSAgent update failed.",
                    "logs": (
                        list(self._update_state.get("logs") or []) + extra_logs
                    )[-MAX_BUILD_LOG_LINES:],
                }
                self._persist_update_state(self._update_state)
        finally:
            if tmp_dir and os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)
            if staging_dir and os.path.exists(staging_dir):
                shutil.rmtree(staging_dir, ignore_errors=True)
            if backup_release_dir and os.path.exists(backup_release_dir):
                shutil.rmtree(backup_release_dir, ignore_errors=True)

    def _run_core_update_worker(self, repo_dir: str, branch: str) -> None:
        bridge_changed = False
        bridge_written = False
        old_bridge_bytes: bytes | None = None
        core_activated = False
        caddy_reloaded = False
        prev_commit: str | None = None
        after_commit: str | None = None
        merged_new_commit = False
        config_snapshots: list[tuple[str, bytes | None, bytes]] = []
        try:
            # Record current HEAD so we can roll back cleanly if Docker build fails
            prev_proc = self._run_repo_git(repo_dir, ["rev-parse", "HEAD"], timeout=10)
            if prev_proc.returncode == 0 and (prev_proc.stdout or "").strip():
                prev_commit = (prev_proc.stdout or "").strip()

            # Step 1: Fetch and fast-forward checkout
            self._append_update_log(
                f"Fetching origin/{branch}...",
                phase="fetching",
                message="Downloading the latest VPSAgent code...",
            )
            fetch_proc = self._run_repo_git(
                repo_dir, ["fetch", "--prune", "origin", branch], timeout=60
            )
            if fetch_proc.returncode != 0:
                detail = (fetch_proc.stderr or fetch_proc.stdout or "git fetch failed").strip()
                raise RuntimeError(f"Could not download updates from Git: {detail}")

            status_proc = self._run_repo_git(
                repo_dir, ["status", "--porcelain"], timeout=10
            )
            if status_proc.returncode == 0 and (status_proc.stdout or "").strip():
                raise RuntimeError(
                    "Local edits exist in the VPSAgent source folder. Clean or commit them before updating."
                )

            merge_proc = self._run_repo_git(
                repo_dir, ["merge", "--ff-only", f"origin/{branch}"], timeout=30
            )
            if merge_proc.returncode != 0:
                detail = (merge_proc.stderr or merge_proc.stdout or "git merge failed").strip()
                raise RuntimeError(
                    f"Could not fast-forward VPSAgent cleanly: {detail}"
                )
            after_merge_proc = self._run_repo_git(
                repo_dir, ["rev-parse", "HEAD"], timeout=10
            )
            after_commit = (
                (after_merge_proc.stdout or "").strip()
                if after_merge_proc.returncode == 0
                else None
            )
            merged_new_commit = bool(
                prev_commit and after_commit and after_commit != prev_commit
            )
            for line in ((merge_proc.stdout or "") + "\n" + (merge_proc.stderr or "")).splitlines():
                if line.strip():
                    self._append_update_log(line)

            # Step 2: Snapshot existing core configs before syncing updated files into VPSAGENT_ROOT
            # Note: Never overwrite caddy/apps.d/00-default.caddy during updates so an app
            # with slug "00-default" never loses its live HTTPS route.
            self._append_update_log(
                "Syncing VPSAgent configuration files...",
                phase="syncing",
                message="Preparing updated server configuration...",
            )
            config_snapshots = self._sync_core_configs(repo_dir)

            # Step 3: Rebuild and restart vpsagent-core stack
            self._append_update_log(
                "Rebuilding and restarting VPSAgent core container...",
                phase="building",
                message="Rebuilding VPSAgent (this usually takes 1-2 minutes)...",
            )
            compose_proc = self._run_core_compose_up(repo_dir)
            if compose_proc.returncode != 0:
                raise RuntimeError(
                    f"Docker rebuild failed (exit {compose_proc.returncode})."
                )
            core_activated = True

            # Step 3b: Validate and reload Caddy if Caddyfile changed
            if self._caddyfile_changed_in_snapshots(config_snapshots):
                self._append_update_log("Validating and reloading Caddy configuration...")
                with self._caddy_lock:
                    self._validate_and_reload_caddy()
                caddy_reloaded = True

            # Step 4: Install updated runtime-bridge.py if changed
            bridge_changed, old_bridge_bytes = self._install_bridge_script_if_changed(
                repo_dir
            )
            bridge_written = bridge_changed

            # Record success BEFORE restarting runtime-bridge.service so status survives restart
            new_info = self._inspect_core_repo()
            finished_iso = datetime.now(timezone.utc).isoformat()
            short_sha = (new_info["currentCommit"] or "")[:7]
            ver_label = (
                f"v{new_info['currentVersion']}"
                if new_info["currentVersion"]
                else "latest version"
            )
            done_msg = (
                f"Updated VPSAgent to {ver_label} ({short_sha})."
                if short_sha
                else f"Updated VPSAgent to {ver_label}."
            )
            with self._update_lock:
                self._update_state = {
                    **self._update_state,
                    "state": "succeeded",
                    "phase": "completed",
                    "checkedAt": finished_iso,
                    "finishedAt": finished_iso,
                    "latestCommit": new_info["currentCommit"],
                    "commitsBehind": 0,
                    "updateAvailable": False,
                    "error": None,
                    "message": done_msg,
                    "logs": (list(self._update_state.get("logs") or []) + [done_msg])[
                        -MAX_BUILD_LOG_LINES:
                    ],
                }
                self._persist_update_state(self._update_state)

            if bridge_changed:
                self._schedule_bridge_restart()
        except Exception as exc:
            err_text = redact_secrets(str(exc))
            rollback_notes: list[str] = []
            if bridge_written:
                note = self._restore_bridge_script(old_bridge_bytes)
                if note:
                    rollback_notes.append(note)
            rollback_notes.extend(self._restore_core_configs(config_snapshots))
            self._rollback_restored_caddy_if_needed(
                rollback_notes, was_active=(caddy_reloaded or core_activated)
            )

            # Only roll back Git checkout if it is still clean and at the exact merged commit
            # (never discard local edits the owner made while Docker was building).
            rolled_back_git = False
            if merged_new_commit and prev_commit:
                try:
                    cur_head_proc = self._run_repo_git(
                        repo_dir, ["rev-parse", "HEAD"], timeout=10
                    )
                    cur_head = (
                        (cur_head_proc.stdout or "").strip()
                        if cur_head_proc.returncode == 0
                        else None
                    )
                    cur_status_proc = self._run_repo_git(
                        repo_dir, ["status", "--porcelain"], timeout=10
                    )
                    is_still_clean = (
                        cur_status_proc.returncode == 0
                        and not (cur_status_proc.stdout or "").strip()
                    )
                    if is_still_clean and cur_head == after_commit:
                        rb_proc = self._run_repo_git(
                            repo_dir, ["reset", "--hard", prev_commit], timeout=20
                        )
                        if rb_proc.returncode == 0:
                            rolled_back_git = True
                            rollback_notes.append(
                                f"Rolled source checkout back to running commit {prev_commit[:7]}."
                            )
                    else:
                        rollback_notes.append(
                            "Skipped automatic Git rollback because local changes were detected in the checkout during the build."
                        )
                except Exception:
                    pass
            if core_activated and rolled_back_git and os.path.isdir(repo_dir):
                try:
                    self._run_core_compose_up(repo_dir, log_output=False, timeout=300)
                except Exception:
                    pass
            finished_iso = datetime.now(timezone.utc).isoformat()
            with self._update_lock:
                extra_logs = [f"ERROR: {err_text}", *rollback_notes]
                self._update_state = {
                    **self._update_state,
                    "state": "failed",
                    "phase": "failed",
                    "finishedAt": finished_iso,
                    "error": err_text,
                    "message": "VPSAgent update failed.",
                    "logs": (
                        list(self._update_state.get("logs") or []) + extra_logs
                    )[-MAX_BUILD_LOG_LINES:],
                }
                self._persist_update_state(self._update_state)


def make_handler(service: RuntimeService) -> type[BaseHTTPRequestHandler]:
    class RuntimeBridgeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 30

        def version_string(self) -> str:
            return "vpsagent-runtime"

        def address_string(self) -> str:
            if isinstance(self.client_address, tuple) and self.client_address:
                return str(self.client_address[0])
            return "unix-socket"

        def log_message(self, format: str, *args: Any) -> None:
            message = redact_secrets(format % args)
            sys.stderr.write(f"[vpsagent-runtime] {self.address_string()} {message}\n")

        def _send_json(self, status_code: int, body: dict[str, Any]) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def _send_file_stream(
            self,
            file_path: str,
            filename: str,
            content_type: str = "application/gzip",
        ) -> None:
            size = os.path.getsize(file_path)
            safe_filename = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(filename)) or "backup.tar.gz"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(size))
            self.send_header(
                "Content-Disposition", f'attachment; filename="{safe_filename}"'
            )
            self.send_header("X-VPSAgent-Backup-Filename", safe_filename)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

        def _require_auth(self) -> bool:
            expected = service.runtime_token
            if not expected:
                if service.allow_unauthenticated:
                    return True
                self._send_json(401, {"error": "Unauthorized."})
                return False
            provided = self.headers.get("X-VPSAgent-Runtime-Token", "").strip()
            if not provided:
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    provided = auth[7:].strip()
            if not provided:
                self._send_json(401, {"error": "Unauthorized."})
                return False
            try:
                provided_bytes = provided.encode("utf-8")
                expected_bytes = expected.encode("utf-8")
            except UnicodeEncodeError:
                self._send_json(401, {"error": "Unauthorized."})
                return False
            if not hmac.compare_digest(provided_bytes, expected_bytes):
                self._send_json(401, {"error": "Unauthorized."})
                return False
            return True

        def _read_json_body(self) -> dict[str, Any]:
            raw_len = self.headers.get("Content-Length")
            if raw_len is None:
                raise BridgeRequestError(411, "Content-Length header is required.")
            try:
                length = int(raw_len)
            except ValueError as exc:
                raise BridgeRequestError(
                    400, "Invalid Content-Length header."
                ) from exc
            if length < 0 or length > MAX_BODY_BYTES:
                raise BridgeRequestError(413, "Payload too large.")
            raw_bytes = self.rfile.read(length) if length > 0 else b"{}"
            try:
                parsed = json.loads(raw_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BridgeRequestError(400, "Invalid JSON payload.") from exc
            if not isinstance(parsed, dict):
                raise BridgeRequestError(400, "JSON body must be an object.")
            return parsed

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(200, {"ok": True, "service": "vpsagent-runtime"})
                return
            if self.path == "/v1/host/stats":
                if not self._require_auth():
                    return
                try:
                    self._send_json(200, service.host_stats())
                except BridgeRequestError as exc:
                    self._send_json(exc.status_code, {"error": str(exc)})
                except Exception as exc:  # pragma: no cover
                    self._send_json(500, {"error": redact_secrets(str(exc))})
                return
            if self.path == "/v1/host/tailscale/status":
                if not self._require_auth():
                    return
                try:
                    self._send_json(200, service.tailscale_status())
                except BridgeRequestError as exc:
                    self._send_json(exc.status_code, {"error": str(exc)})
                except Exception as exc:  # pragma: no cover
                    self._send_json(500, {"error": redact_secrets(str(exc))})
                return
            if self.path == "/v1/core/update/status":
                if not self._require_auth():
                    return
                try:
                    self._send_json(200, service.core_update_status(check_remote=False))
                except BridgeRequestError as exc:
                    self._send_json(exc.status_code, {"error": str(exc)})
                except Exception as exc:  # pragma: no cover
                    self._send_json(500, {"error": redact_secrets(str(exc))})
                return
            self._send_json(404, {"error": "Not found."})

        def do_POST(self) -> None:
            if not self._require_auth():
                return
            try:
                payload = self._read_json_body()
                if self.path == "/v1/apps/lifecycle":
                    self._send_json(200, service.lifecycle(payload))
                elif self.path == "/v1/apps/build-git":
                    self._send_json(200, service.build_git(payload))
                elif self.path == "/v1/apps/inspect-git":
                    self._send_json(200, service.inspect_git(payload))
                elif self.path == "/v1/apps/logs":
                    self._send_json(200, service.logs(payload))
                elif self.path == "/v1/apps/route-caddy":
                    self._send_json(200, service.route_caddy(payload))
                elif self.path == "/v1/core/route-domain":
                    self._send_json(200, service.route_core_domain(payload))
                elif self.path == "/v1/core/tls-check":
                    self._send_json(200, service.check_core_tls(payload))
                elif self.path == "/v1/core/update/check":
                    self._send_json(200, service.core_update_status(check_remote=True))
                elif self.path == "/v1/core/update/apply":
                    self._send_json(200, service.start_core_update(payload))
                elif self.path == "/v1/apps/remove":
                    self._send_json(200, service.remove_workload(payload))
                elif self.path == "/v1/apps/rollback":
                    self._send_json(200, service.rollback_app(payload))
                elif self.path == "/v1/apps/backup":
                    tar_path, filename = service.create_app_backup(payload)
                    try:
                        self._send_file_stream(tar_path, filename)
                    finally:
                        if os.path.exists(tar_path):
                            os.unlink(tar_path)
                elif self.path == "/v1/core/backup":
                    tar_path, filename = service.create_core_backup(payload)
                    try:
                        self._send_file_stream(tar_path, filename)
                    finally:
                        if os.path.exists(tar_path):
                            os.unlink(tar_path)
                elif self.path == "/v1/apps/statuses":
                    self._send_json(200, service.statuses(payload))
                elif self.path == "/v1/apps/inspect":
                    self._send_json(200, service.inspect_workload(payload))
                elif self.path == "/v1/apps/readiness":
                    self._send_json(200, service.check_readiness(payload))
                elif self.path == "/v1/apps/exec":
                    self._send_json(200, service.exec_in_app(payload))
                elif self.path == "/v1/host/exec":
                    self._send_json(200, service.host_exec(payload))
                elif self.path == "/v1/host/files/list":
                    self._send_json(200, service.list_files(payload))
                elif self.path == "/v1/host/files/read":
                    self._send_json(200, service.read_file(payload))
                elif self.path == "/v1/host/files/write":
                    self._send_json(200, service.write_file(payload))
                elif self.path == "/v1/host/files/delete":
                    self._send_json(200, service.delete_file(payload))
                elif self.path == "/v1/host/services/list":
                    self._send_json(200, service.list_services(payload))
                elif self.path == "/v1/host/services/manage":
                    self._send_json(200, service.manage_service(payload))
                elif self.path == "/v1/host/docker/cleanup":
                    self._send_json(200, service.docker_cleanup(payload))
                elif self.path == "/v1/host/tailscale/serve":
                    self._send_json(200, service.set_tailscale_serve(payload))
                elif self.path == "/v1/host/tailscale/connect":
                    self._send_json(200, service.connect_tailscale(payload))
                else:
                    self._send_json(404, {"error": "Not found."})
            except BridgeRequestError as exc:
                err_body: dict[str, Any] = {"error": str(exc)}
                if exc.build_log_tail:
                    err_body["buildLogTail"] = exc.build_log_tail
                self._send_json(exc.status_code, err_body)
            except Exception as exc:  # pragma: no cover - defensive fallback
                self._send_json(500, {"error": redact_secrets(str(exc))})

    return RuntimeBridgeHandler


if hasattr(socketserver, "UnixStreamServer"):

    class ThreadingUnixHttpServer(
        socketserver.ThreadingMixIn, socketserver.UnixStreamServer
    ):
        daemon_threads = True
        request_queue_size = 32


class ThreadingTcpHttpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32


def prepare_unix_socket(socket_path: str) -> None:
    parent = os.path.dirname(os.path.abspath(socket_path))
    os.makedirs(parent, mode=0o750, exist_ok=True)
    os.chmod(parent, 0o750)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.chown(parent, 0, 1000)
    if os.path.lexists(socket_path):
        st = os.lstat(socket_path)
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError(
                f"Refusing to overwrite non-socket file at {socket_path}"
            )
        os.unlink(socket_path)


def reset_admin_password_in_db(db_path: str, new_password: str) -> dict[str, Any]:
    if not isinstance(new_password, str) or len(new_password) < 8 or len(new_password) > 256:
        raise ValueError("Password must be between 8 and 256 characters long.")
    if "\x00" in new_password:
        raise ValueError("Password cannot contain null bytes.")
    resolved = os.path.abspath(db_path)
    if not os.path.lexists(resolved) or os.path.islink(resolved) or not os.path.isfile(resolved):
        raise ValueError(f"Registry database not found at {resolved}.")

    conn = sqlite3.connect(resolved, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout = 5000;")
        setup_row = conn.execute(
            "SELECT value_json FROM system_settings WHERE key = 'setup_state'"
        ).fetchone()
        claimed = False
        if setup_row and setup_row[0]:
            try:
                claimed = bool(json.loads(setup_row[0]).get("claimed"))
            except (json.JSONDecodeError, AttributeError):
                claimed = False
        if not claimed:
            raise ValueError(
                "This VPSAgent server has not been claimed yet. Complete first-time setup in your browser."
            )

        salt = os.urandom(16).hex()
        derived = hashlib.scrypt(
            new_password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=16384,
            r=8,
            p=1,
            dklen=64,
        ).hex()
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        conn.execute(
            """
            INSERT INTO system_settings (key, value_json, updated_at)
            VALUES ('admin_passphrase', ?, ?)
            ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
            """,
            (json.dumps({"salt": salt, "hash": derived}), now),
        )

        ver_row = conn.execute(
            "SELECT value_json FROM system_settings WHERE key = 'session_version'"
        ).fetchone()
        cur_ver = 1
        if ver_row and ver_row[0]:
            try:
                parsed_ver = json.loads(ver_row[0]).get("version")
                if isinstance(parsed_ver, int) and parsed_ver >= 1:
                    cur_ver = parsed_ver
            except (json.JSONDecodeError, AttributeError):
                cur_ver = 1
        next_ver = max(1, cur_ver) + 1
        conn.execute(
            """
            INSERT INTO system_settings (key, value_json, updated_at)
            VALUES ('session_version', ?, ?)
            ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
            """,
            (json.dumps({"version": next_ver}), now),
        )
        conn.execute(
            """
            INSERT INTO audit_events (id, actor, actor_token_id, action, target_slug, summary, risk_level, created_at)
            VALUES (?, 'system', NULL, 'auth.password_reset_cli', NULL, ?, 'high', ?)
            """,
            (
                f"aud_{os.urandom(8).hex()}",
                "Reset owner login password via server CLI and signed out all existing sessions",
                now,
            ),
        )
        conn.commit()
        return {"ok": True, "sessionVersion": next_ver}
    finally:
        conn.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VPSAgent v2 Host Runtime Bridge")
    parser.add_argument(
        "--socket",
        default=os.environ.get(
            "VPSAGENT_RUNTIME_SOCKET", "/var/lib/vpsagent/run/runtime.sock"
        ),
        help="Unix domain socket path to bind.",
    )
    parser.add_argument(
        "--tcp",
        default="",
        help="Optional loopback host:port (e.g. 127.0.0.1:0) for local testing.",
    )
    parser.add_argument(
        "--apps-root",
        default=os.environ.get("VPSAGENT_APPS_ROOT", "/var/lib/vpsagent/apps"),
    )
    parser.add_argument(
        "--caddy-apps-dir",
        default=os.environ.get(
            "VPSAGENT_CADDY_APPS_DIR", "/var/lib/vpsagent/caddy/apps.d"
        ),
    )
    parser.add_argument(
        "--caddy-core-dir",
        default=os.environ.get("VPSAGENT_CADDY_CORE_DIR", ""),
    )
    parser.add_argument(
        "--caddy-container",
        default=os.environ.get("VPSAGENT_CADDY_CONTAINER", "vpsagent-caddy"),
    )
    parser.add_argument(
        "--docker-bin",
        default=os.environ.get("VPSAGENT_DOCKER_BIN", "docker"),
    )
    parser.add_argument(
        "--git-bin",
        default=os.environ.get("VPSAGENT_GIT_BIN", "git"),
    )
    parser.add_argument(
        "--systemctl-bin",
        default=os.environ.get("VPSAGENT_SYSTEMCTL_BIN", "systemctl"),
    )
    parser.add_argument(
        "--tailscale-bin",
        default=os.environ.get("VPSAGENT_TAILSCALE_BIN", "tailscale"),
    )
    parser.add_argument(
        "--tailscale-target-url",
        default=os.environ.get(
            "VPSAGENT_TAILSCALE_TARGET_URL", DEFAULT_TAILSCALE_TARGET_URL
        ),
    )
    parser.add_argument(
        "--vpsagent-root",
        default=os.environ.get("VPSAGENT_ROOT", ""),
    )
    parser.add_argument(
        "--repo-dir",
        default=None,
    )
    parser.add_argument(
        "--release-repo",
        default=None,
    )
    parser.add_argument(
        "--release-api-base",
        default=None,
    )
    parser.add_argument(
        "--check-update",
        action="store_true",
        help="Check GitHub Releases / Git repository for a newer VPSAgent version and exit.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output when used with --check-update.",
    )
    parser.add_argument(
        "--reset-password",
        action="store_true",
        help="Reset the owner dashboard password in SQLite and sign out all existing sessions.",
    )
    parser.add_argument(
        "--db-path",
        default="",
        help="Path to registry.db for --reset-password (defaults to <vpsagent-root>/data/registry.db).",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the new password from stdin when running --reset-password.",
    )
    parser.add_argument(
        "--runtime-token",
        default=os.environ.get("VPSAGENT_RUNTIME_TOKEN", ""),
    )
    parser.add_argument(
        "--allow-unauthenticated",
        action="store_true",
        help="Allow starting without VPSAGENT_RUNTIME_TOKEN (tests only).",
    )
    parser.add_argument(
        "--status-deadline",
        type=float,
        default=float(
            os.environ.get("VPSAGENT_STATUS_DEADLINE_S", DEFAULT_STATUS_DEADLINE_S)
        ),
        help="Overall deadline in seconds for batch /v1/apps/statuses queries.",
    )
    parser.add_argument(
        "--health-interval",
        type=float,
        default=float(
            os.environ.get("VPSAGENT_HEALTH_INTERVAL_S", DEFAULT_HEALTH_INTERVAL_S)
        ),
        help="Interval in seconds for host-side recurring HTTP health probes.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.reset_password:
        root_dir = (
            args.vpsagent_root
            or os.environ.get("VPSAGENT_ROOT", "").strip()
            or (
                os.path.dirname(os.path.abspath(args.apps_root))
                if os.path.basename(os.path.abspath(args.apps_root)) == "apps"
                else "/var/lib/vpsagent"
            )
        )
        db_path = (
            args.db_path.strip()
            or os.environ.get("VPSAGENT_DB_PATH", "").strip()
            or os.path.join(root_dir, "data", "registry.db")
        )
        if args.password_stdin:
            raw_line = sys.stdin.readline()
            new_pw = raw_line.rstrip("\r\n")
        else:
            pw1 = getpass.getpass("New VPSAgent dashboard password (min 8 chars): ")
            pw2 = getpass.getpass("Confirm new password: ")
            if pw1 != pw2:
                sys.stderr.write("Error: passwords did not match.\n")
                return 1
            new_pw = pw1
        try:
            res = reset_admin_password_in_db(db_path, new_pw)
        except (ValueError, sqlite3.Error) as exc:
            sys.stderr.write(f"Password reset failed: {exc}\n")
            return 1
        sys.stdout.write(
            f"Dashboard password updated and all existing sessions signed out (session v{res['sessionVersion']}).\n"
        )
        return 0

    if args.check_update:
        service = RuntimeService(
            apps_root=args.apps_root,
            caddy_apps_dir=args.caddy_apps_dir,
            caddy_core_dir=args.caddy_core_dir or None,
            caddy_container=args.caddy_container,
            docker_bin=args.docker_bin,
            git_bin=args.git_bin,
            systemctl_bin=args.systemctl_bin,
            vpsagent_root=args.vpsagent_root or None,
            repo_dir=args.repo_dir or None,
            release_repo=args.release_repo or None,
            release_api_base=args.release_api_base or None,
            allow_unauthenticated=True,
            status_deadline_s=args.status_deadline,
            health_interval_s=args.health_interval,
        )
        try:
            status = service.core_update_status(check_remote=True)
        except BridgeRequestError as exc:
            if args.json:
                sys.stdout.write(json.dumps({"ok": False, "error": str(exc)}) + "\n")
            else:
                sys.stderr.write(f"Update check failed: {exc}\n")
            return 1
        if args.json:
            sys.stdout.write(json.dumps(status, indent=2) + "\n")
        else:
            installed = status.get("currentVersion") or "unknown"
            latest = status.get("latestReleaseTag") or status.get("latestVersion") or "none"
            sys.stdout.write(f"Installed version: {installed}\n")
            sys.stdout.write(f"Latest release:    {latest} ({status.get('releaseStatus')})\n")
            sys.stdout.write(f"Update source:     {status.get('updateSource')}\n")
            sys.stdout.write(f"Checksum status:   {status.get('checksumStatus')}\n")
            sys.stdout.write(f"Status:            {status.get('message') or 'Ready'}\n")
            if status.get("releaseNote"):
                sys.stdout.write(f"Note:              {status['releaseNote']}\n")
        return 0

    token = (args.runtime_token or "").strip()
    if not args.allow_unauthenticated and (
        not token or token.startswith("replace-with-") or len(token) < 16
    ):
        sys.stderr.write(
            "Fatal: VPSAGENT_RUNTIME_TOKEN must be a non-placeholder secret of at least 16 chars.\n"
        )
        return 1

    service = RuntimeService(
        apps_root=args.apps_root,
        caddy_apps_dir=args.caddy_apps_dir,
        caddy_core_dir=args.caddy_core_dir or None,
        caddy_container=args.caddy_container,
        docker_bin=args.docker_bin,
        git_bin=args.git_bin,
        systemctl_bin=args.systemctl_bin,
        tailscale_bin=args.tailscale_bin,
        tailscale_target_url=args.tailscale_target_url,
        vpsagent_root=args.vpsagent_root or None,
        repo_dir=args.repo_dir or None,
        release_repo=args.release_repo or None,
        release_api_base=args.release_api_base or None,
        runtime_token=token or None,
        allow_unauthenticated=bool(args.allow_unauthenticated),
        status_deadline_s=args.status_deadline,
        health_interval_s=args.health_interval,
    )
    if (
        service.repo_dir
        and os.path.isdir(service.repo_dir)
        and os.path.isdir(service.vpsagent_root)
        and not os.path.lexists(_active_source_path(service.vpsagent_root))
    ):
        try:
            _write_active_source_file(
                service.vpsagent_root,
                service.repo_dir,
                release_repo=service.release_repo,
            )
        except OSError:
            pass
    handler_cls = make_handler(service)

    server: socketserver.BaseServer
    if args.tcp:
        host, _, raw_port = args.tcp.rpartition(":")
        if host not in ("127.0.0.1", "localhost", "::1"):
            sys.stderr.write("Fatal: --tcp may only bind to loopback addresses.\n")
            return 1
        port = int(raw_port)
        server = ThreadingTcpHttpServer((host, port), handler_cls)
        actual_host, actual_port = server.server_address[:2]
        sys.stdout.write(f"LISTENING http://{actual_host}:{actual_port}\n")
        sys.stdout.flush()
    else:
        if not hasattr(socketserver, "UnixStreamServer"):
            sys.stderr.write(
                "Fatal: UnixStreamServer is not supported on this platform; pass --tcp 127.0.0.1:0 for tests.\n"
            )
            return 1
        prepare_unix_socket(args.socket)
        old_umask = os.umask(0o117)
        try:
            server = ThreadingUnixHttpServer(args.socket, handler_cls)
        finally:
            os.umask(old_umask)
        os.chmod(args.socket, 0o660)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.chown(args.socket, 0, 1000)
        sys.stdout.write(f"LISTENING unix://{args.socket}\n")
        sys.stdout.flush()

    def _shutdown(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    service.start_health_monitor()
    try:
        server.serve_forever()
    finally:
        service.stop_health_monitor()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
