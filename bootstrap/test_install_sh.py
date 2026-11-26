#!/usr/bin/env python3
"""Tests for bootstrap/install.sh upgrade behavior across checkout paths."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "bootstrap" / "install.sh"


class TestInstallScriptUpgrade(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="vpsagent-install-test-")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_upgrade_from_opt_to_home_checkout_rebuilds_new_core_and_preserves_secrets(
        self,
    ) -> None:
        vpsagent_root = Path(self.tmp) / "var-lib-vpsagent"
        vpsagent_root.mkdir(parents=True)

        # Simulate a previous install that originally ran from /opt/vpsagent
        env_file = vpsagent_root / ".env"
        original_secrets = {
            "VPSAGENT_RUNTIME_TOKEN": "orig_runtime_token_1111222233334444",
            "VPSAGENT_SESSION_SECRET": "orig_session_secret_5555666677778888",
            "VPSAGENT_ENCRYPTION_SECRET": "orig_encrypt_secret_9999aaaabbbbcccc",
            "VPSAGENT_CLAIM_TOKEN": "orig_claim_token_ddddeeeeffff",
        }
        env_file.write_text(
            "\n".join(
                [
                    "VPSAGENT_REPO_DIR=/opt/vpsagent",
                    "VPSAGENT_DOMAIN=vps.example.com",
                    "VPSAGENT_ACME_EMAIL=owner@example.com",
                    "VPSAGENT_PUBLIC_IP=203.0.113.10",
                    f"VPSAGENT_RUNTIME_TOKEN={original_secrets['VPSAGENT_RUNTIME_TOKEN']}",
                    f"VPSAGENT_SESSION_SECRET={original_secrets['VPSAGENT_SESSION_SECRET']}",
                    f"VPSAGENT_ENCRYPTION_SECRET={original_secrets['VPSAGENT_ENCRYPTION_SECRET']}",
                    f"VPSAGENT_CLAIM_TOKEN={original_secrets['VPSAGENT_CLAIM_TOKEN']}",
                    f"VPSAGENT_RUNTIME_SOCKET={vpsagent_root}/run/runtime.sock",
                    f"VPSAGENT_APPS_ROOT={vpsagent_root}/apps",
                    f"VPSAGENT_CADDY_APPS_DIR={vpsagent_root}/caddy/apps.d",
                    "VPSAGENT_CADDY_CONTAINER=vpsagent-caddy",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(env_file, 0o600)

        # Simulate a new checkout in ~/vpsagent with updated runtime-bridge.py marker
        home_checkout = Path(self.tmp) / "home-ubuntu" / "vpsagent"
        shutil.copytree(REPO_ROOT / "bootstrap", home_checkout / "bootstrap")
        marker = "# NEW_REVISION_MARKER_TEST_10"
        bridge_src = home_checkout / "bootstrap" / "runtime-bridge.py"
        bridge_src.write_text(
            bridge_src.read_text(encoding="utf-8") + f"\n{marker}\n",
            encoding="utf-8",
        )

        # Fake shims for chown, curl (public ip), and docker so we can run the real
        # prepare_state_and_secrets + start_core_stack functions cleanly without root.
        bin_dir = Path(self.tmp) / "bin"
        bin_dir.mkdir()
        docker_log = Path(self.tmp) / "docker-compose-call.txt"

        (bin_dir / "chown").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        os.chmod(bin_dir / "chown", 0o755)

        (bin_dir / "curl").write_text(
            "#!/usr/bin/env bash\nprintf '203.0.113.10'\n", encoding="utf-8"
        )
        os.chmod(bin_dir / "curl", 0o755)

        (bin_dir / "docker").write_text(
            f"""#!/usr/bin/env bash
if [[ "$1" == "network" && "$2" == "inspect" ]]; then
  exit 0
fi
printf 'VPSAGENT_REPO_DIR=%s\\nARGS=%s\\n' "${{VPSAGENT_REPO_DIR:-}}" "$*" > "{docker_log}"
exit 0
""",
            encoding="utf-8",
        )
        os.chmod(bin_dir / "docker", 0o755)

        script = f"""
set -euo pipefail
export PATH="{bin_dir}:$PATH"
export VPSAGENT_ROOT="{vpsagent_root}"
export VPSAGENT_INSTALL_LIBRARY_ONLY=true
source "{home_checkout / 'bootstrap' / 'install.sh'}"
prepare_state_and_secrets
start_core_stack
"""
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"install.sh upgrade failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )

        # 1. .env must stay 0600, preserve all secrets, backfill VPSAGENT_CADDY_CORE_DIR,
        # and update VPSAGENT_REPO_DIR to the new ~/vpsagent checkout.
        env_mode = stat.S_IMODE(os.stat(env_file).st_mode)
        self.assertEqual(env_mode, 0o600)
        parsed: dict[str, str] = {}
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                parsed[k] = v

        self.assertEqual(parsed["VPSAGENT_REPO_DIR"], str(home_checkout))
        self.assertEqual(
            parsed["VPSAGENT_CADDY_CORE_DIR"], str(vpsagent_root / "caddy" / "core.d")
        )
        for key, expected_val in original_secrets.items():
            self.assertEqual(parsed[key], expected_val)

        # 2. Installed runtime-bridge.py must be updated to the new checkout revision
        installed_bridge = (vpsagent_root / "runtime-bridge.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(marker, installed_bridge)

        # 3. docker compose up -d --build must explicitly receive the new checkout path
        docker_call = docker_log.read_text(encoding="utf-8")
        self.assertIn(f"VPSAGENT_REPO_DIR={home_checkout}\n", docker_call)
        self.assertIn("up -d --build", docker_call)

    def test_tailscale_install_configures_serve_banner_and_never_leaks_authkey(
        self,
    ) -> None:
        bin_dir = Path(self.tmp) / "bin"
        bin_dir.mkdir()
        ts_state = Path(self.tmp) / "ts-state.json"
        ts_calls = Path(self.tmp) / "ts-calls.log"
        vpsagent_root = Path(self.tmp) / "var-lib-vpsagent"
        vpsagent_root.mkdir(parents=True)
        env_file = vpsagent_root / ".env"
        env_file.write_text("VPSAGENT_CLAIM_TOKEN=claim_ts_banner_123\n", encoding="utf-8")
        os.chmod(env_file, 0o600)

        (bin_dir / "tailscale").write_text(
            f"""#!/usr/bin/env python3
import json, os, sys
state_path = {str(ts_state)!r}
calls_path = {str(ts_calls)!r}
args = sys.argv[1:]
with open(calls_path, "a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

st = {{"connected": False, "serve": False}}
if os.path.exists(state_path):
    with open(state_path, "r", encoding="utf-8") as fh:
        st = json.load(fh)

if args[:1] == ["up"]:
    for arg in args[1:]:
        if arg.startswith("--auth-key=file:"):
            key_path = arg.split(":", 1)[1]
            with open(key_path, "r", encoding="utf-8") as kf:
                assert kf.read().startswith("tskey-auth-")
    st["connected"] = True
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    sys.exit(0)

if args == ["serve", "--bg", "--https=443", "http://127.0.0.1:3001"]:
    st["serve"] = True
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    sys.exit(0)

if args == ["status", "--json"]:
    if not st["connected"]:
        print(json.dumps({{"BackendState": "Stopped", "Self": {{"TailscaleIPs": []}}}}))
    else:
        print(json.dumps({{
            "BackendState": "Running",
            "Self": {{"DNSName": "vps-node.tail99.ts.net.", "TailscaleIPs": ["100.64.0.99"]}},
            "CertDomains": ["vps-node.tail99.ts.net"],
        }}))
    sys.exit(0)

if args == ["serve", "status", "--json"]:
    if st["serve"]:
        print(json.dumps({{
            "Web": {{
                "vps-node.tail99.ts.net:443": {{
                    "Handlers": {{"/": {{"Proxy": "http://127.0.0.1:3001"}}}}
                }}
            }}
        }}))
    else:
        print("{{}}")
    sys.exit(0)

sys.exit(0)
""",
            encoding="utf-8",
        )
        os.chmod(bin_dir / "tailscale", 0o755)

        secret_auth_key = "tskey-auth-kInstallSecret99998888"
        script = f"""
set -euo pipefail
export PATH="{bin_dir}:$PATH"
export VPSAGENT_ROOT="{vpsagent_root}"
export VPSAGENT_INSTALL_LIBRARY_ONLY=true
export VPSAGENT_TAILSCALE_AUTHKEY="{secret_auth_key}"
source "{INSTALL_SH}"
ARG_TAILSCALE="true"
CLAIM_TOKEN="claim_ts_banner_123"
configure_tailscale
print_ready_banner
"""
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=f"configure_tailscale failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        self.assertIn(
            "https://vps-node.tail99.ts.net/#claim=claim_ts_banner_123",
            proc.stdout,
        )
        self.assertNotIn(secret_auth_key, proc.stdout)
        self.assertNotIn(secret_auth_key, proc.stderr)
        self.assertNotIn(secret_auth_key, env_file.read_text(encoding="utf-8"))
        calls_text = ts_calls.read_text(encoding="utf-8")
        self.assertIn("serve --bg --https=443 http://127.0.0.1:3001", calls_text)
        self.assertNotIn(secret_auth_key, calls_text)

    def test_tailscale_install_preserves_existing_conflicting_serve_route(
        self,
    ) -> None:
        bin_dir = Path(self.tmp) / "bin-conflict"
        bin_dir.mkdir()
        ts_calls = Path(self.tmp) / "ts-conflict-calls.log"
        vpsagent_root = Path(self.tmp) / "var-lib-vpsagent-conflict"
        vpsagent_root.mkdir(parents=True)

        (bin_dir / "tailscale").write_text(
            f"""#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
with open({str(ts_calls)!r}, "a", encoding="utf-8") as fh:
    fh.write(" ".join(args) + "\\n")

if args == ["status", "--json"]:
    print(json.dumps({{
        "BackendState": "Running",
        "Self": {{"DNSName": "vps-node.tail99.ts.net.", "TailscaleIPs": ["100.64.0.99"]}},
        "CertDomains": ["vps-node.tail99.ts.net"],
    }}))
    sys.exit(0)

if args == ["serve", "status", "--json"]:
    print(json.dumps({{
        "Web": {{
            "vps-node.tail99.ts.net:443": {{
                "Handlers": {{"/": {{"Proxy": "http://127.0.0.1:9000"}}}}
            }}
        }}
    }}))
    sys.exit(0)

sys.exit(0)
""",
            encoding="utf-8",
        )
        os.chmod(bin_dir / "tailscale", 0o755)

        script = f"""
set -euo pipefail
export PATH="{bin_dir}:$PATH"
export VPSAGENT_ROOT="{vpsagent_root}"
export VPSAGENT_INSTALL_LIBRARY_ONLY=true
source "{INSTALL_SH}"
ARG_TAILSCALE="true"
configure_tailscale
"""
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("http://127.0.0.1:9000", proc.stdout)
        calls_text = ts_calls.read_text(encoding="utf-8")
        self.assertNotIn("serve --bg --https=443", calls_text)


if __name__ == "__main__":
    unittest.main()
