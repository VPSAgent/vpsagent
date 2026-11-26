#!/usr/bin/env python3
"""Tests for bootstrap/install.sh upgrade behavior across checkout paths."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
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

        # 2. Installed runtime-bridge.py & active-source.json must point to home_checkout cleanly
        installed_bridge = (vpsagent_root / "runtime-bridge.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(marker, installed_bridge)
        active_source_path = vpsagent_root / "active-source.json"
        self.assertTrue(active_source_path.is_file())
        self.assertEqual(stat.S_IMODE(os.stat(active_source_path).st_mode), 0o644)
        active_source = json.loads(active_source_path.read_text(encoding="utf-8"))
        self.assertEqual(active_source["repoDir"], str(home_checkout))

        # 3. CLI --check-update --json (with VPSAGENT_REPO_DIR unset & no --repo-dir) discovers home_checkout
        remote_dir = Path(self.tmp) / "bare-remote.git"
        git_env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
        subprocess.run(["git", "init", "--bare", str(remote_dir)], check=True, env=git_env)
        subprocess.run(["git", "-C", str(home_checkout), "init", "-b", "main"], check=True, env=git_env)
        (home_checkout / "package.json").write_text(
            '{"name":"vpsagent","version":"2.0.0-alpha.1"}', encoding="utf-8"
        )
        subprocess.run(["git", "-C", str(home_checkout), "add", "."], check=True, env=git_env)
        subprocess.run(["git", "-C", str(home_checkout), "commit", "-m", "init"], check=True, env=git_env)
        subprocess.run(
            ["git", "-C", str(home_checkout), "remote", "add", "origin", str(remote_dir)],
            check=True,
            env=git_env,
        )
        subprocess.run(
            ["git", "-C", str(home_checkout), "push", "-u", "origin", "main"],
            check=True,
            env=git_env,
        )
        cli_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("VPSAGENT_REPO_DIR", "VPSAGENT_RELEASE_REPO")
        }
        cli_proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "bootstrap" / "runtime-bridge.py"),
                "--apps-root",
                str(vpsagent_root / "apps"),
                "--caddy-apps-dir",
                str(vpsagent_root / "caddy" / "apps.d"),
                "--vpsagent-root",
                str(vpsagent_root),
                "--check-update",
                "--json",
            ],
            capture_output=True,
            text=True,
            env=cli_env,
            check=False,
        )
        self.assertEqual(
            cli_proc.returncode,
            0,
            msg=f"CLI --check-update failed: stdout={cli_proc.stdout} stderr={cli_proc.stderr}",
        )
        cli_payload = json.loads(cli_proc.stdout)
        self.assertEqual(cli_payload["repoDir"], str(home_checkout))
        self.assertEqual(cli_payload["currentVersion"], "2.0.0-alpha.1")

        # 4. docker compose up -d --build must explicitly receive the new checkout path
        docker_call = docker_log.read_text(encoding="utf-8")
        self.assertIn(f"VPSAGENT_REPO_DIR={home_checkout}\n", docker_call)
        self.assertIn("up -d --build", docker_call)


if __name__ == "__main__":
    unittest.main()
