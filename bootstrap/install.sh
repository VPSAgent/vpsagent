#!/usr/bin/env bash
set -euo pipefail

# VPSAgent v2 — Lean One-Command Ubuntu LTS Installer
# Usage (from an authenticated clone as a standard Ubuntu user — works for private repos):
#   git clone git@github.com:VPSAgent/vpsagent.git "$HOME/vpsagent"
#   sudo bash "$HOME/vpsagent/bootstrap/install.sh" [--domain vps.yourdomain.com --email you@yourdomain.com]
# Usage (when repository or release asset is public):
#   curl -fsSL https://raw.githubusercontent.com/VPSAgent/vpsagent/main/bootstrap/install.sh | sudo bash

VPSAGENT_ROOT="${VPSAGENT_ROOT:-/var/lib/vpsagent}"
VPSAGENT_REPO_URL="${VPSAGENT_REPO_URL:-https://github.com/VPSAgent/vpsagent.git}"
VPSAGENT_REPO_REF="${VPSAGENT_REPO_REF:-main}"
VPSAGENT_REPO_DIR="${VPSAGENT_REPO_DIR:-/opt/vpsagent}"
CORE_NETWORK="${CORE_NETWORK:-vpsagent-core}"

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
export NEEDRESTART_MODE="${NEEDRESTART_MODE:-a}"

FORCE_OVERWRITE="false"
ARG_DOMAIN=""
ARG_EMAIL=""
ARG_TAILSCALE="false"

TAILSCALE_BACKEND_STATE=""
TAILSCALE_IP=""
TAILSCALE_DNS_NAME=""
TAILSCALE_HTTPS_CERTS="false"
TAILSCALE_SERVE_URL=""
TAILSCALE_SERVE_CONFLICT=""

SOURCE_PATH="${BASH_SOURCE[0]:-}"
if [[ -n "${SOURCE_PATH}" && -f "${SOURCE_PATH}" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${SOURCE_PATH}")" && pwd)"
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
else
  SCRIPT_DIR=""
  REPO_ROOT=""
fi

log() {
  printf '[vpsagent-install] %s\n' "$1"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain)
        ARG_DOMAIN="${2:-}"
        shift 2
        ;;
      --email)
        ARG_EMAIL="${2:-}"
        shift 2
        ;;
      --tailscale)
        ARG_TAILSCALE="true"
        shift
        ;;
      --force)
        FORCE_OVERWRITE="true"
        shift
        ;;
      --help|-h)
        cat <<'EOF'
VPSAgent v2 — One-Command Ubuntu Installer

Options:
  --domain <host>   Optional dashboard domain for automatic HTTPS (e.g. vps.yourdomain.com)
  --email <email>   Optional Let's Encrypt notice email
  --tailscale       Install Tailscale and configure private HTTPS without needing a domain
                    (optional env var VPSAGENT_TAILSCALE_AUTHKEY for headless sign-in)
  --force           Overwrite existing config and systemd unit files
  --help, -h        Show this help text
EOF
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        exit 1
        ;;
    esac
  done
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: run this installer with sudo (as root)." >&2
    exit 1
  fi
}

require_ubuntu() {
  if [[ ! -f /etc/os-release ]]; then
    echo "Error: /etc/os-release not found." >&2
    exit 1
  fi
  # shellcheck source=/dev/null
  source /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    echo "Error: Ubuntu LTS is required (detected: ${ID:-unknown})." >&2
    exit 1
  fi
  log "Detected Ubuntu ${VERSION_ID:-unknown}"
}

ensure_packages() {
  if ! command -v git >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    log "Installing prerequisite packages (git, python3, curl, openssl, ufw)..."
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg git python3 openssl ufw
  fi
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log "Docker Engine and Compose v2 already installed."
    return
  fi
  log "Installing Docker Engine and Docker Compose v2..."
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  # shellcheck source=/dev/null
  source /etc/os-release
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$(dpkg --print-architecture)" "${VERSION_CODENAME}" > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

ensure_tailscale() {
  if [[ "${ARG_TAILSCALE}" != "true" ]]; then
    return
  fi
  if ! command -v tailscale >/dev/null 2>&1; then
    log "Installing Tailscale for private HTTPS access..."
    apt-get update -y
    apt-get install -y ca-certificates curl gnupg
    install -m 0755 -d /usr/share/keyrings
    # shellcheck source=/dev/null
    source /etc/os-release
    local codename="${VERSION_CODENAME:-noble}"
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.noarmor.gpg" -o /usr/share/keyrings/tailscale-archive-keyring.gpg
    curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${codename}.tailscale-keyring.list" -o /etc/apt/sources.list.d/tailscale.list
    apt-get update -y
    apt-get install -y tailscale
  else
    log "Tailscale is already installed."
  fi
  systemctl enable --now tailscaled || true
}

ensure_repo_checkout() {
  if [[ -n "${REPO_ROOT}" && -f "${REPO_ROOT}/bootstrap/docker-compose.core.yml" && -f "${REPO_ROOT}/bootstrap/runtime-bridge.py" ]]; then
    return
  fi
  if [[ -d "${VPSAGENT_REPO_DIR}/.git" ]]; then
    log "Updating VPSAgent repository in ${VPSAGENT_REPO_DIR}..."
    git -C "${VPSAGENT_REPO_DIR}" fetch --depth 1 origin "${VPSAGENT_REPO_REF}"
    git -C "${VPSAGENT_REPO_DIR}" checkout -B "${VPSAGENT_REPO_REF}" "origin/${VPSAGENT_REPO_REF}"
  else
    log "Cloning VPSAgent into ${VPSAGENT_REPO_DIR}..."
    git clone --depth 1 --branch "${VPSAGENT_REPO_REF}" "${VPSAGENT_REPO_URL}" "${VPSAGENT_REPO_DIR}"
  fi
  REPO_ROOT="${VPSAGENT_REPO_DIR}"
  SCRIPT_DIR="${REPO_ROOT}/bootstrap"
}

detect_public_ip() {
  local ip=""
  for probe in "https://api.ipify.org" "https://ipv4.icanhazip.com"; do
    ip="$(curl -fsS --max-time 3 "${probe}" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${ip}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s' "${ip}"
      return
    fi
  done
}

configure_firewall() {
  local ssh_port="22"
  if [[ -f /etc/ssh/sshd_config ]]; then
    ssh_port="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ {print $2; exit}' /etc/ssh/sshd_config || true)"
    ssh_port="${ssh_port:-22}"
  fi
  log "Configuring UFW firewall (allowing SSH ${ssh_port}/tcp, 80/tcp, 443/tcp)..."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${ssh_port}/tcp"
  ufw allow 80/tcp
  ufw allow 443/tcp
  if [[ "${ARG_TAILSCALE}" == "true" ]] || command -v tailscale >/dev/null 2>&1; then
    ufw allow in on tailscale0 || true
  fi
  ufw --force enable
}

write_core_caddy_route() {
  local core_route="${VPSAGENT_ROOT}/caddy/core.d/dashboard.caddy"
  if [[ -n "${ARG_DOMAIN}" ]]; then
    local tls_line=""
    if [[ -n "${ARG_EMAIL}" ]]; then
      tls_line="	tls ${ARG_EMAIL}"$'\n'
    fi
    cat > "${core_route}" <<EOF
# Managed by VPSAgent Installer / Host Runtime Bridge (Core Dashboard & MCP)
${ARG_DOMAIN} {
${tls_line}	encode zstd gzip
	handle /mcp {
		reverse_proxy vpsagent-core:3001
	}
	handle {
		reverse_proxy vpsagent-core:3001
	}
}
EOF
    chmod 644 "${core_route}"
  elif [[ ! -f "${core_route}" || "${FORCE_OVERWRITE}" == "true" ]]; then
    cp "${SCRIPT_DIR}/caddy/core.d/dashboard.caddy" "${core_route}"
    chmod 644 "${core_route}"
  fi
}

upsert_env_var() {
  local file="$1"
  local key="$2"
  local val="$3"
  local tmp_file
  tmp_file="$(mktemp "${VPSAGENT_ROOT}/.env.tmp.XXXXXX")"
  chmod 600 "${tmp_file}"
  ENV_KEY="${key}" ENV_VAL="${val}" awk '
    BEGIN {
      k = ENVIRON["ENV_KEY"]
      v = ENVIRON["ENV_VAL"]
      updated = 0
    }
    index($0, k "=") == 1 {
      print k "=" v
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print k "=" v
      }
    }
  ' "${file}" > "${tmp_file}"
  mv "${tmp_file}" "${file}"
  chmod 600 "${file}"
}

prepare_state_and_secrets() {
  log "Preparing ${VPSAGENT_ROOT} directories and secrets..."
  mkdir -p "${VPSAGENT_ROOT}/data" "${VPSAGENT_ROOT}/config" "${VPSAGENT_ROOT}/apps" \
    "${VPSAGENT_ROOT}/run" "${VPSAGENT_ROOT}/caddy/core.d" "${VPSAGENT_ROOT}/caddy/apps.d"
  chmod 750 "${VPSAGENT_ROOT}" "${VPSAGENT_ROOT}/config" "${VPSAGENT_ROOT}/run" "${VPSAGENT_ROOT}/apps"
  chown 0:1000 "${VPSAGENT_ROOT}/run"
  chown 1000:1000 "${VPSAGENT_ROOT}/data" "${VPSAGENT_ROOT}/config" "${VPSAGENT_ROOT}/apps"

  PUBLIC_IP="$(detect_public_ip || true)"
  ENV_FILE="${VPSAGENT_ROOT}/.env"

  if [[ ! -f "${ENV_FILE}" || "${FORCE_OVERWRITE}" == "true" ]]; then
    RUNTIME_TOKEN="$(openssl rand -hex 32)"
    SESSION_SECRET="$(openssl rand -hex 32)"
    ENCRYPTION_SECRET="$(openssl rand -hex 32)"
    CLAIM_TOKEN="$(openssl rand -hex 18)"
    DOMAIN_VAL="${ARG_DOMAIN:-localhost}"
    EMAIL_VAL="${ARG_EMAIL:-admin@example.com}"

    cat > "${ENV_FILE}" <<EOF
VPSAGENT_REPO_DIR=${REPO_ROOT}
VPSAGENT_DOMAIN=${DOMAIN_VAL}
VPSAGENT_ACME_EMAIL=${EMAIL_VAL}
VPSAGENT_PUBLIC_IP=${PUBLIC_IP}
VPSAGENT_RUNTIME_TOKEN=${RUNTIME_TOKEN}
VPSAGENT_SESSION_SECRET=${SESSION_SECRET}
VPSAGENT_ENCRYPTION_SECRET=${ENCRYPTION_SECRET}
VPSAGENT_CLAIM_TOKEN=${CLAIM_TOKEN}
VPSAGENT_RUNTIME_SOCKET=${VPSAGENT_ROOT}/run/runtime.sock
VPSAGENT_APPS_ROOT=${VPSAGENT_ROOT}/apps
VPSAGENT_CADDY_CORE_DIR=${VPSAGENT_ROOT}/caddy/core.d
VPSAGENT_CADDY_APPS_DIR=${VPSAGENT_ROOT}/caddy/apps.d
VPSAGENT_CADDY_CONTAINER=vpsagent-caddy
EOF
    chmod 600 "${ENV_FILE}"
  else
    # Preserve existing secrets on upgrade, update VPSAGENT_REPO_DIR to the checkout
    # launching this installer so vpsagent-core rebuilds from the current revision,
    # and backfill any newly added non-secret keys.
    CLAIM_TOKEN="$(awk -F= '/^VPSAGENT_CLAIM_TOKEN=/{print $2; exit}' "${ENV_FILE}" || true)"
    upsert_env_var "${ENV_FILE}" "VPSAGENT_REPO_DIR" "${REPO_ROOT}"
    if ! grep -q '^VPSAGENT_CADDY_CORE_DIR=' "${ENV_FILE}"; then
      upsert_env_var "${ENV_FILE}" "VPSAGENT_CADDY_CORE_DIR" "${VPSAGENT_ROOT}/caddy/core.d"
    fi
  fi

  cp "${SCRIPT_DIR}/Caddyfile" "${VPSAGENT_ROOT}/Caddyfile"
  cp "${SCRIPT_DIR}/docker-compose.core.yml" "${VPSAGENT_ROOT}/docker-compose.yml"
  cp "${SCRIPT_DIR}/caddy/apps.d/00-default.caddy" "${VPSAGENT_ROOT}/caddy/apps.d/00-default.caddy"
  write_core_caddy_route
  install -m 0750 "${SCRIPT_DIR}/runtime-bridge.py" "${VPSAGENT_ROOT}/runtime-bridge.py"
  ACTIVE_SOURCE_ROOT="${VPSAGENT_ROOT}" ACTIVE_SOURCE_REPO="${REPO_ROOT}" python3 - <<'PY'
import datetime
import json
import os

root = os.environ["ACTIVE_SOURCE_ROOT"]
repo = os.path.abspath(os.environ["ACTIVE_SOURCE_REPO"])
path = os.path.join(root, "active-source.json")
if os.path.islink(path):
    raise SystemExit(f"Refusing to overwrite symlink {path}")
tmp_path = os.path.join(root, f".active-source.json.tmp.{os.getpid()}")
with open(tmp_path, "w", encoding="utf-8") as fh:
    json.dump(
        {
            "repoDir": repo,
            "updatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        fh,
        indent=2,
    )
    fh.write("\n")
os.chmod(tmp_path, 0o644)
os.replace(tmp_path, path)
PY
}

configure_runtime_bridge_service() {
  local unit_file="/etc/systemd/system/vpsagent-runtime.service"
  log "Installing and starting host Runtime Bridge daemon (${unit_file})..."
  cat > "${unit_file}" <<EOF
[Unit]
Description=VPSAgent v2 Host Runtime Bridge
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=simple
EnvironmentFile=${VPSAGENT_ROOT}/.env
ExecStart=/usr/bin/python3 ${VPSAGENT_ROOT}/runtime-bridge.py
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "${unit_file}"
  systemctl daemon-reload
  systemctl enable vpsagent-runtime.service
  systemctl restart vpsagent-runtime.service
  wait_for_runtime_bridge
}

wait_for_runtime_bridge() {
  local sock="${VPSAGENT_ROOT}/run/runtime.sock"
  log "Verifying restarted host Runtime Bridge health on ${sock}..."
  local tries=0
  while (( tries < 30 )); do
    if [[ -S "${sock}" ]] && curl --unix-socket "${sock}" -fsS --max-time 2 http://localhost/health | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
      log "Host Runtime Bridge is healthy and accepting requests."
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.5
  done
  echo "Error: host Runtime Bridge did not become healthy on ${sock} after restart." >&2
  systemctl status vpsagent-runtime.service --no-pager >&2 || true
  exit 1
}

start_core_stack() {
  if ! docker network inspect "${CORE_NETWORK}" >/dev/null 2>&1; then
    docker network create "${CORE_NETWORK}"
  fi
  log "Building and starting VPSAgent core stack from ${REPO_ROOT} (vpsagent-core + Caddy Auto-TLS)..."
  VPSAGENT_REPO_DIR="${REPO_ROOT}" docker compose --project-directory "${VPSAGENT_ROOT}" \
    -f "${VPSAGENT_ROOT}/docker-compose.yml" \
    --env-file "${VPSAGENT_ROOT}/.env" up -d --build
}

detect_tailscale_info() {
  TAILSCALE_BACKEND_STATE=""
  TAILSCALE_IP=""
  TAILSCALE_DNS_NAME=""
  TAILSCALE_HTTPS_CERTS="false"
  TAILSCALE_SERVE_URL=""
  TAILSCALE_SERVE_CONFLICT=""
  TAILSCALE_FUNNEL_ACTIVE="false"

  if ! command -v tailscale >/dev/null 2>&1; then
    return
  fi

  local status_json=""
  local serve_json=""
  status_json="$(tailscale status --json 2>/dev/null || true)"
  serve_json="$(tailscale serve status --json 2>/dev/null || true)"
  if [[ -z "${status_json}" ]]; then
    return
  fi

  local parsed_lines=""
  parsed_lines="$(
    TS_STATUS_JSON="${status_json}" TS_SERVE_JSON="${serve_json}" python3 - <<'PY' 2>/dev/null || true
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

KNOWN_TOKEN_RE = re.compile(
    r"\b(sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{12,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|vpsmcp_[A-Za-z0-9_-]{16,}|tskey-[a-z]+-[A-Za-z0-9_-]{8,})\b"
)


def sanitize_proxy_display(raw):
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
        sanitized = f"{parts.scheme}://{prefix}{host_port}{parts.path}"
        return KNOWN_TOKEN_RE.sub("[REDACTED]", sanitized)
    fallback = re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@",
        r"\1[REDACTED]@",
        cleaned,
    )
    fallback = re.split(r"[?#]", fallback, maxsplit=1)[0]
    return KNOWN_TOKEN_RE.sub("[REDACTED]", fallback)


def is_matching_root_target(val):
    return val.strip().rstrip("/").lower() in (
        "http://127.0.0.1:3001",
        "http://localhost:3001",
    )


def is_matching_mcp_target(val):
    # Tailscale strips explicit mount prefixes before forwarding, so /mcp needs an upstream /mcp path.
    return val.strip().lower() in (
        "http://127.0.0.1:3001/mcp",
        "http://localhost:3001/mcp",
    )


try:
    st = json.loads(os.environ.get("TS_STATUS_JSON") or "{}")
except Exception:
    raise SystemExit(0)

if not isinstance(st, dict):
    raise SystemExit(0)

backend = str(st.get("BackendState") or "").strip()
self_info = st.get("Self") if isinstance(st.get("Self"), dict) else {}
raw_dns = str(self_info.get("DNSName") or "").strip().rstrip(".").lower()
raw_ips = self_info.get("TailscaleIPs")
if not isinstance(raw_ips, list):
    raw_ips = st.get("TailscaleIPs")
ts_ip = ""
if isinstance(raw_ips, list):
    for item in raw_ips:
        if isinstance(item, str) and item.strip():
            try:
                addr = ipaddress.ip_address(item.strip())
                if addr.version == 4:
                    ts_ip = str(addr)
                    break
                if not ts_ip:
                    ts_ip = str(addr)
            except ValueError:
                continue

cert_domains = st.get("CertDomains")
https_certs = (
    "true"
    if isinstance(cert_domains, list)
    and any(isinstance(d, str) and d.strip() for d in cert_domains)
    else "false"
)

serve_url = ""
serve_conflict = ""
funnel_active = False
raw_serve = os.environ.get("TS_SERVE_JSON") or ""
if raw_serve.strip():
    try:
        sv = json.loads(raw_serve)
    except Exception:
        sv = {}
    web = sv.get("Web") if isinstance(sv, dict) else None
    allow_funnel = sv.get("AllowFunnel") if isinstance(sv, dict) else None
    candidate_keys = []
    if isinstance(web, dict):
        if raw_dns and f"{raw_dns}:443" in web:
            candidate_keys.append(f"{raw_dns}:443")
        for k in web:
            if isinstance(k, str) and k.endswith(":443") and k not in candidate_keys:
                candidate_keys.append(k)
    if isinstance(allow_funnel, dict):
        for fk, fv in allow_funnel.items():
            if bool(fv) is True and isinstance(fk, str) and (
                fk in candidate_keys or fk.endswith(":443")
            ):
                funnel_active = True
                break
    if isinstance(web, dict):
        root_matched = False
        other_proxy = ""
        mcp_conflict = ""
        any_handler_key = ""
        funnel_siblings = []
        for k in candidate_keys:
            entry = web.get(k)
            if not isinstance(entry, dict):
                continue
            handlers = entry.get("Handlers")
            if not isinstance(handlers, dict):
                continue
            if handlers and not any_handler_key:
                any_handler_key = k
            root_h = handlers.get("/")
            if isinstance(root_h, dict):
                proxy = root_h.get("Proxy")
                if isinstance(proxy, str) and proxy.strip():
                    cleaned = proxy.strip()
                    if is_matching_root_target(cleaned):
                        root_matched = True
                    elif not other_proxy:
                        other_proxy = sanitize_proxy_display(cleaned)
                elif not other_proxy:
                    other_proxy = f"existing handler on {k}"
            mcp_h = handlers.get("/mcp")
            if isinstance(mcp_h, dict):
                mcp_proxy = mcp_h.get("Proxy")
                if isinstance(mcp_proxy, str) and mcp_proxy.strip():
                    cleaned_mcp = mcp_proxy.strip()
                    if not is_matching_mcp_target(cleaned_mcp):
                        mcp_conflict = f"/mcp -> {sanitize_proxy_display(cleaned_mcp)}"
                elif not mcp_conflict:
                    mcp_conflict = f"/mcp on {k}"
            for path_key, handler_val in sorted(handlers.items()):
                if not isinstance(path_key, str) or path_key in ("/", "/mcp"):
                    continue
                if isinstance(handler_val, dict):
                    sib_proxy = handler_val.get("Proxy")
                    if isinstance(sib_proxy, str) and sib_proxy.strip():
                        summary = f"{path_key} -> {sanitize_proxy_display(sib_proxy)}"
                    else:
                        summary = f"{path_key} on {k}"
                else:
                    summary = f"{path_key} on {k}"
                if summary not in funnel_siblings:
                    funnel_siblings.append(summary)

        if funnel_active and funnel_siblings:
            affected = []
            if other_proxy:
                affected.append(f"/ -> {other_proxy}")
            if mcp_conflict:
                affected.append(mcp_conflict)
            affected.extend(funnel_siblings)
            serve_conflict = f"public Funnel sibling routes ({', '.join(affected)})"
            serve_url = ""
        elif mcp_conflict:
            serve_conflict = mcp_conflict
            serve_url = ""
        elif root_matched:
            if funnel_active:
                serve_url = ""
            elif raw_dns:
                serve_url = f"https://{raw_dns}"
        elif other_proxy:
            serve_conflict = other_proxy
            serve_url = ""
        elif any_handler_key:
            serve_conflict = f"existing handler on {any_handler_key}"
            serve_url = ""

print(backend)
print(ts_ip)
print(raw_dns)
print(https_certs)
print(serve_url)
print(serve_conflict)
print("true" if funnel_active else "false")
PY
  )"

  if [[ -n "${parsed_lines}" ]]; then
    {
      IFS= read -r TAILSCALE_BACKEND_STATE || true
      IFS= read -r TAILSCALE_IP || true
      IFS= read -r TAILSCALE_DNS_NAME || true
      IFS= read -r TAILSCALE_HTTPS_CERTS || true
      IFS= read -r TAILSCALE_SERVE_URL || true
      IFS= read -r TAILSCALE_SERVE_CONFLICT || true
      IFS= read -r TAILSCALE_FUNNEL_ACTIVE || true
    } <<< "${parsed_lines}"
  fi
}

configure_tailscale() {
  detect_tailscale_info
  if [[ "${ARG_TAILSCALE}" != "true" ]]; then
    return
  fi

  if [[ "${TAILSCALE_BACKEND_STATE}" != "Running" && -n "${VPSAGENT_TAILSCALE_AUTHKEY:-}" ]]; then
    log "Signing server into Tailscale with provided auth key..."
    local tmp_key
    tmp_key="$(mktemp)"
    chmod 600 "${tmp_key}"
    printf '%s' "${VPSAGENT_TAILSCALE_AUTHKEY}" > "${tmp_key}"
    if ! tailscale up --auth-key="file:${tmp_key}" --timeout=30s >/dev/null 2>&1; then
      log "Note: Tailscale sign-in did not finish automatically. You can finish signing in from the VPSAgent dashboard."
    fi
    rm -f "${tmp_key}"
    detect_tailscale_info
  fi

  if [[ "${TAILSCALE_BACKEND_STATE}" == "Running" && -n "${TAILSCALE_DNS_NAME}" ]]; then
    if [[ -n "${TAILSCALE_SERVE_CONFLICT}" ]]; then
      if [[ "${TAILSCALE_SERVE_CONFLICT}" == "public Funnel sibling routes"* ]]; then
        log "Warning: Port 443 is currently open to the public internet via Tailscale Funnel with ${TAILSCALE_SERVE_CONFLICT}. Turning on private Tailscale HTTPS would disable public Funnel for the entire port 443 listener and cut off public access to those services. Leaving your existing Funnel setup untouched; move those services to another port or confirm the switch in AI Keys & Settings -> Tailscale private access."
        return
      fi
      log "Warning: Tailscale Serve port 443 is already forwarding to ${TAILSCALE_SERVE_CONFLICT}. Keeping your existing route; open AI Keys & Settings -> Tailscale private access if you want to replace it."
      return
    fi
    if [[ -n "${TAILSCALE_SERVE_URL}" && "${TAILSCALE_FUNNEL_ACTIVE}" != "true" ]]; then
      log "Tailscale private HTTPS is already active at ${TAILSCALE_SERVE_URL}."
      return
    fi
    if [[ "${TAILSCALE_FUNNEL_ACTIVE}" == "true" ]]; then
      log "Public Tailscale Funnel is active on port 443; switching to private tailnet-only HTTPS (tailscale serve) for ${TAILSCALE_DNS_NAME}..."
    else
      log "Enabling Tailscale private HTTPS (tailscale serve) for ${TAILSCALE_DNS_NAME}..."
    fi
    if ! tailscale serve --bg --https=443 http://127.0.0.1:3001 >/dev/null 2>&1; then
      log "Note: Could not enable Tailscale Serve automatically. Enable MagicDNS and HTTPS Certificates at https://login.tailscale.com/admin/dns, then click Enable private HTTPS in the dashboard."
    fi
    detect_tailscale_info
    if [[ "${TAILSCALE_FUNNEL_ACTIVE}" == "true" ]]; then
      log "Warning: Public Tailscale Funnel is still active on port 443. Run 'tailscale funnel --https=443 off' and then 'tailscale serve --bg --https=443 http://127.0.0.1:3001' to restrict access to your private tailnet."
    fi
  fi
}

print_ready_banner() {
  local token_display="${CLAIM_TOKEN:-<see /var/lib/vpsagent/.env>}"
  printf '\n=================================================================\n'
  printf '  VPSAgent v2 is installed and running!\n'
  printf '=================================================================\n'
  if [[ -n "${ARG_DOMAIN}" ]]; then
    printf '  Open your private HTTPS first-time setup link:\n'
    printf '    https://%s/#claim=%s\n\n' "${ARG_DOMAIN}" "${token_display}"
  elif [[ -n "${TAILSCALE_SERVE_URL}" ]]; then
    printf '  Open your private Tailscale HTTPS first-time setup link:\n'
    printf '    %s/#claim=%s\n\n' "${TAILSCALE_SERVE_URL}" "${token_display}"
  else
    printf '  No domain was provided yet, so remote plaintext HTTP login is disabled\n'
    printf '  for your safety. Open a private SSH tunnel from your computer:\n'
    printf '    ssh -L 3002:127.0.0.1:3002 root@%s\n\n' "${PUBLIC_IP:-<YOUR_SERVER_IP>}"
    printf '  Then open your private first-time setup link in your browser:\n'
    printf '    http://localhost:3002/#claim=%s\n\n' "${token_display}"
    if [[ -n "${TAILSCALE_DNS_NAME}" || -n "${TAILSCALE_IP}" ]]; then
      printf '  Tailscale detected (%s). You can enable private Tailscale HTTPS\n' "${TAILSCALE_DNS_NAME:-${TAILSCALE_IP}}"
      printf '  with no domain or DNS required during Step 2 of setup.\n\n'
    elif [[ "${ARG_TAILSCALE}" == "true" ]]; then
      printf '  Tailscale is installed on this server. You can finish signing in and\n'
      printf '  turn on private Tailscale HTTPS during Step 2 of setup.\n\n'
    fi
  fi
  printf '  Step 1: Choose your dashboard password\n'
  printf '  Step 2: Connect your domain or enable Tailscale private HTTPS\n'
  printf '=================================================================\n\n'
}

main() {
  parse_args "$@"
  require_root
  require_ubuntu
  ensure_packages
  ensure_docker
  ensure_tailscale
  ensure_repo_checkout
  configure_firewall
  prepare_state_and_secrets
  configure_runtime_bridge_service
  start_core_stack
  configure_tailscale
  print_ready_banner
}

if [[ "${VPSAGENT_INSTALL_LIBRARY_ONLY:-false}" != "true" ]]; then
  main "$@"
fi
