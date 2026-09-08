#!/usr/bin/env python3
"""Offline signing of a prepared admission candidate (plan §7.1 "Offline signing must then" steps 1-4).

Run this on the steward's offline signing machine against the candidate branch produced by
prepare-admission.py. It is the only ledger script that uses a secret key, and it uses only the
operator's own GNUPGHOME (ambient or --gnupghome); it never copies, exports, or prints key material.

  1. Recompute every declaration and event hash listed in the manifest; refuse on any drift.
  2. Create a content-addressed admissions/<slug>.<sha256>.record.asc for each new declaration version.
  3. Sign each admission event JSON (detached, armored) with the pinned signing subkey.
  4. Create one signed Git commit (pinned subkey) containing the complete candidate tree.

Exit codes: 0 signed, 1 rejected (drift, wrong branch, dirty state), 2 fail-closed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledgerlib as L  # noqa: E402


class Rejected(Exception):
    pass


def gpg_env(gnupghome: str | None) -> dict[str, str]:
    env = dict(os.environ)
    if gnupghome:
        env["GNUPGHOME"] = gnupghome
    return env


def sign_detached(gpg: str, env: dict[str, str], subkey: str, target: Path, output: Path, extra: list[str]) -> None:
    if output.exists():
        raise Rejected(f"{output} already exists; admissions/ is append-only")
    cmd = [gpg, "--batch", "--yes", "--quiet", *extra, "--local-user", f"{subkey}!", "--detach-sign", "--armor"]
    cmd += ["-o", str(output), str(target)]
    result = subprocess.run(cmd, capture_output=True, env=env)
    if result.returncode != 0:
        raise L.FailClosed(f"gpg could not sign {target.name}: {result.stderr.decode('utf-8', 'replace').strip()}")
    check = subprocess.run(
        [gpg, "--batch", "--status-fd", "1", "--verify", str(output), str(target)], capture_output=True, env=env
    )
    res = L.parse_status(check.stdout.decode("utf-8", "replace"), check.returncode)
    if not res.good or res.key_fingerprint != subkey:
        raise L.FailClosed(f"freshly created signature {output.name} did not verify with subkey {subkey}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True, help="manifest JSON written by prepare-admission.py build --manifest")
    ap.add_argument("--root", default=".")
    ap.add_argument("--gpg", help="gpg binary (default: LEDGER_GPG or auto-detect)")
    ap.add_argument("--gnupghome", help="operator GNUPGHOME holding the steward secret key (default: ambient)")
    ap.add_argument("--message", help="commit message (default: '<action>: <action-id>' from the manifest)")
    ap.add_argument("--no-commit", action="store_true", help="sign artifacts but leave the commit to the operator")
    ap.add_argument("--gpg-extra", action="append", default=[], help="extra gpg option (e.g. --pinentry-mode=loopback)")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        manifest: dict[str, Any] = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        git = L.Git(root)
        if not git.available:
            raise L.FailClosed(f"{root} is not the ledger checkout")
        branch = git.run("rev-parse", "--abbrev-ref", "HEAD")
        if branch != manifest.get("branch"):
            raise Rejected(f"checked-out branch {branch!r} is not the manifest branch {manifest.get('branch')!r}")
        if git.head() != manifest.get("base_main"):
            raise Rejected("HEAD moved since prepare-admission.py ran; the candidate must be signed from its main base")
        gpg = L.find_gpg(args.gpg)
        env = gpg_env(args.gnupghome)
        subkey = L.read_pin(root, L.SUBKEY_REF_PATH)
        primary = L.read_pin(root, L.KEY_REF_PATH)

        # 1. recompute hashes
        drift: list[str] = []
        for rel, sha in manifest.get("declarations", {}).items():
            p = root / rel
            if not p.exists():
                drift.append(f"{rel}: missing")
            elif L.sha256_file(p) != sha:
                drift.append(f"{rel}: {L.sha256_file(p)} != {sha}")
        for rel, sha in manifest.get("events", {}).items():
            p = root / rel
            if not p.exists() or L.sha256_file(p) != sha:
                drift.append(f"{rel}: missing or changed")
        if drift:
            raise Rejected("hash drift since preparation:\n  " + "\n  ".join(drift))
        print(
            f"hashes match the manifest ({len(manifest.get('declarations', {}))} declaration(s), "
            f"{len(manifest.get('events', {}))} event(s))"
        )

        # 2. record signatures
        for sig, record in sorted(manifest.get("record_signatures", {}).items()):
            sign_detached(gpg, env, subkey, root / record, root / sig, args.gpg_extra)
            print(f"signed {sig}")
        # 3. event signatures
        for rel in sorted(manifest.get("events", {})):
            sign_detached(gpg, env, subkey, root / rel, root / (rel + ".asc"), args.gpg_extra)
            print(f"signed {rel}.asc")

        # 4. signed commit
        if args.no_commit:
            print("artifacts signed; commit left to the operator (--no-commit)")
            return L.EXIT_OK
        git.run("add", "-A", "--", "attestations", "revocations", "admissions")
        status = git.run("status", "--porcelain")
        for line in status.splitlines():
            path = line[3:]
            if not (path.startswith(("attestations/", "revocations/", "admissions/"))):
                raise Rejected(f"unexpected change outside ledger directories: {line}")
        message = (
            args.message or f"{manifest.get('action', 'admission')}: {manifest.get('branch', '').split('/', 1)[-1]}"
        )
        commit_env = dict(env)
        commit_env.update(
            {
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "gpg.program",
                "GIT_CONFIG_VALUE_0": gpg,
                "GIT_CONFIG_KEY_1": "user.signingkey",
                "GIT_CONFIG_VALUE_1": f"{subkey}!",
            }
        )
        git.run("commit", "-q", "-S", "-m", message, env=commit_env)
        head = git.head()
        code, raw = git.verify_commit_raw(head, commit_env, gpg)
        res = L.parse_status(raw, code)
        if not res.good or res.key_fingerprint != subkey or res.primary_fingerprint != primary:
            raise L.FailClosed("the new commit's signature does not verify with the pinned subkey; do not push it")
        print(f"signed commit {head} on {branch}")
        print(
            f"next: git push origin {branch} ; open the admission PR ; run promote-admission.py --expected-head {head}"
        )
    except Rejected as exc:
        print(f"REJECTED {exc}", file=sys.stderr)
        return L.EXIT_INVALID
    except L.FailClosed as exc:
        print(f"FAIL (closed) {exc}", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED
    except subprocess.CalledProcessError as exc:
        print(f"FAIL (closed) git failed: {exc.stderr.decode('utf-8', 'replace').strip()}", file=sys.stderr)
        return L.EXIT_FAIL_CLOSED
    return L.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
