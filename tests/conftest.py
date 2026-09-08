"""Shared fixtures for the ledger test suite.

Every test drives the command-line scripts against a complete temporary ledger
tree. GPG material is a throwaway certificate generated per session; Git
history is built with real commits in temporary repositories. The real steward
secret is never involved.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
VALIDATE = SCRIPTS / "validate.py"
VERIFY = SCRIPTS / "verify-signatures.py"
PREPARE = SCRIPTS / "prepare-admission.py"
SIGN = SCRIPTS / "sign-admission.py"
PROMOTE = SCRIPTS / "promote-admission.py"
SCHEMA_DIR = REPO_ROOT / "schema"
DECLARATION_SCHEMA = "schema/attestation.schema.json"
EVENT_SCHEMA = "schema/admission-event.schema.json"

CONSTITUTION_HASH = "71bf60ad917c5413cc17b0f65e83c7a29218e24a2740725a819058ed9c6b1993"
LAW_NAMES = [
    "Options and Consent",
    "Corrigibility and Oversight",
    "Reversibility and Proportion",
    "Commitments with a Safety Valve",
    "Scoped Exploration",
]
LAW_IDS = [
    "options_and_consent",
    "corrigibility_and_oversight",
    "reversibility_and_proportion",
    "commitments_with_safety_valve",
    "scoped_exploration",
]
REPOSITORY = "FIDES-ANIMA/fpp-attestation-ledger"
STEWARD_LOGIN = "steward-bot"
FAKE_PAST = "20240101T000000!"
# Built from fragments so the repository's own secret-armor scan never matches this file.
PRIVATE_ARMOR = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP " + "PRIVATE KEY BLOCK-----\n"


def find_gpg() -> str:
    env = os.environ.get("LEDGER_GPG")
    if env:
        return env
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
            if base:
                candidate = Path(base) / "GnuPG" / "bin" / "gpg.exe"
                if candidate.exists():
                    return str(candidate)
    found = shutil.which("gpg")
    if not found:
        pytest.skip("gpg not available")
    return found


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_payload(doc: dict[str, Any]) -> bytes:
    payload = copy.deepcopy(doc)
    payload.get("attestation", {}).pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def dump_yaml(doc: dict[str, Any]) -> bytes:
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True).encode("utf-8")


class AgentKey:
    """Throwaway Ed25519 agent identity."""

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key_hex = raw.hex()
        self.fpp_id = "fpp:ed25519:" + hashlib.sha256(raw).hexdigest()

    def sign(self, doc: dict[str, Any]) -> str:
        return self.private.sign(canonical_payload(doc)).hex()


def declaration(
    *,
    name: str = "Nova",
    slug: str | None = None,
    state: str = "reviewed",
    authorship: str = "operator-reported",
    filing: str = "operator",
    key: AgentKey | None = None,
    fpp_id: str | None = None,
    public_key_hex: str | None = None,
    contact: str = "github:alice",
    operator_name: str = "Alice",
    grade: str = "prompt-only",
    overlays: list[str] | None = None,
    version: int = 1,
    declaration_id: str | None = None,
    predecessor: dict[str, Any] | None = None,
    transition_from: str | None = "__auto__",
    occurred_at: str = "2026-08-24T12:00:00Z",
    evidence: dict[str, Any] | None | str = "__auto__",
    notes: str = "",
    reason: str | None = None,
    revocation: dict[str, Any] | None = None,
    runtime: dict[str, Any] | None = None,
    extensions: dict[str, Any] | None = None,
    date: str = "2026-08-24",
    method: str = "pr",
    sign: bool = True,
) -> dict[str, Any]:
    """Build a schema-valid declaration with sensible defaults.

    If ``key`` is given the record is agent-signed by that key unless
    ``authorship`` overrides it. Evidence for a first ``accepted`` filing is
    generated automatically unless ``evidence`` is set explicitly (None omits it).
    """
    if key is not None:
        fpp_id = fpp_id or key.fpp_id
        public_key_hex = public_key_hex or key.public_key_hex
        if authorship == "operator-reported" and filing == "operator" and sign:
            authorship, filing = "agent-signed", "self"
    slug = slug or slugify(name)
    if transition_from == "__auto__":
        if version == 1:
            transition_from = "reviewed" if state in ("accepted", "externally-enforced") else None
        else:
            transition_from = state
    actor_type = "agent" if authorship == "agent-signed" else "operator"
    actor_ref = fpp_id if actor_type == "agent" and fpp_id else contact
    if evidence == "__auto__":
        if state == "accepted" and transition_from != "accepted":
            evidence = {
                "inspection": {
                    "record_ref": "https://example.invalid/records/inspection",
                    "constitution_hash": CONSTITUTION_HASH,
                    "inspected_at": "2026-08-20T00:00:00Z",
                },
                "acceptance": {
                    "record_ref": "https://example.invalid/records/acceptance",
                    "constitution_hash": CONSTITUTION_HASH,
                    "accepted_at": "2026-08-24T11:00:00Z",
                },
            }
        else:
            evidence = None
    if overlays is None:
        overlays = ["runtime_degraded"] if state == "accepted" and grade == "prompt-only" else []
    doc: dict[str, Any] = {
        "agent": {
            "name": name,
            "slug": slug,
            "fpp_id": fpp_id,
            "public_key_hex": public_key_hex,
            "description": "",
        },
        "operator": {"name": operator_name, "contact": contact},
        "adoption": {
            "lifecycle_state": state,
            "constitution_version": "1.0.0",
            "constitution_hash": CONSTITUTION_HASH,
            "date": date,
            "laws_acknowledged": list(LAW_NAMES),
            "law_ids": list(LAW_IDS),
            "harness_id": None,
            "enforcement_grade": grade,
            "overlays": overlays,
            "layers": {"prompt": True, "enforcement": grade != "prompt-only", "trust": False},
            "tooling": {
                "skill_version": None,
                "enforcement_plugin_version": None,
                "trust_plugin_version": None,
            },
            "transition": {
                "from": transition_from,
                "to": state,
                "occurred_at": occurred_at,
                "actor": {"type": actor_type, "ref": actor_ref},
                "predecessor_ref": predecessor["path"] if predecessor else None,
            },
        },
        "attestation": {
            "declaration_id": declaration_id or str(uuid.uuid4()),
            "version": version,
            "action": "attest" if version == 1 else "amend",
            "predecessor_record": predecessor,
            "authorship": authorship,
            "filing": filing,
            "method": method,
            "assurance": "declaration-only",
            "signature": None,
            "notes": notes,
            "reason": reason,
        },
    }
    if evidence:
        doc["adoption"]["evidence"] = evidence
    if runtime is not None:
        doc["runtime"] = runtime
    if extensions is not None:
        doc["extensions"] = extensions
    if revocation is not None:
        doc["revocation"] = revocation
    if key is not None and authorship == "agent-signed" and sign:
        doc["attestation"]["signature"] = key.sign(doc)
    return doc


def slugify(name: str) -> str:
    import re

    return "-".join(t for t in re.findall(r"[a-z0-9]+", name.lower()) if t)


def successor(
    prev: dict[str, Any],
    prev_path: str,
    prev_bytes: bytes,
    *,
    state: str | None = None,
    key: AgentKey | None = None,
    occurred_at: str = "2026-09-01T12:00:00Z",
    **overrides: Any,
) -> dict[str, Any]:
    """Build version n+1 of ``prev`` with a correct predecessor record."""
    doc = copy.deepcopy(prev)
    new_state = state or prev["adoption"]["lifecycle_state"]
    doc["adoption"]["lifecycle_state"] = new_state
    doc["adoption"]["transition"] = {
        "from": prev["adoption"]["lifecycle_state"],
        "to": new_state,
        "occurred_at": occurred_at,
        "actor": prev["adoption"]["transition"]["actor"],
        "predecessor_ref": prev_path,
    }
    doc["adoption"].pop("evidence", None)
    if new_state == "accepted" and prev["adoption"]["lifecycle_state"] != "accepted":
        doc["adoption"]["evidence"] = {
            "inspection": {
                "record_ref": "https://example.invalid/records/inspection-2",
                "constitution_hash": CONSTITUTION_HASH,
                "inspected_at": "2026-08-30T00:00:00Z",
            },
            "acceptance": {
                "record_ref": "https://example.invalid/records/acceptance-2",
                "constitution_hash": CONSTITUTION_HASH,
                "accepted_at": "2026-09-01T11:00:00Z",
            },
        }
    if new_state == "accepted" and doc["adoption"]["enforcement_grade"] == "prompt-only":
        if "runtime_degraded" not in doc["adoption"]["overlays"]:
            doc["adoption"]["overlays"].append("runtime_degraded")
    doc["attestation"]["version"] = prev["attestation"]["version"] + 1
    doc["attestation"]["predecessor_record"] = {"path": prev_path, "sha256": sha256_bytes(prev_bytes)}
    doc["attestation"]["signature"] = None
    if new_state == "revoked":
        doc["attestation"]["action"] = "withdraw-adoption"
    elif prev["adoption"]["lifecycle_state"] == "revoked":
        doc["attestation"]["action"] = "re-adopt"
    else:
        doc["attestation"]["action"] = "amend"
    doc.pop("revocation", None)
    for dotted, value in overrides.items():
        target = doc
        parts = dotted.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    agent_signed = doc["attestation"]["authorship"] == "agent-signed"
    doc["adoption"]["transition"]["actor"] = {
        "type": "agent" if agent_signed else "operator",
        "ref": doc["agent"]["fpp_id"] if agent_signed and doc["agent"]["fpp_id"] else doc["operator"]["contact"],
    }
    if key is not None:
        doc["attestation"]["signature"] = key.sign(doc)
    return doc


def revocation_of(
    prev: dict[str, Any],
    prev_path: str,
    prev_bytes: bytes,
    *,
    key: AgentKey | None = None,
    revoked_at: str = "2026-09-01",
    revoked_by: str = "operator",
    reason: str = "Operator withdrew the declaration after decommissioning the agent.",
) -> dict[str, Any]:
    doc = successor(prev, prev_path, prev_bytes, state="revoked", occurred_at=revoked_at + "T12:00:00Z")
    doc["attestation"]["reason"] = reason
    doc["revocation"] = {"revoked_at": revoked_at, "revoked_by": revoked_by, "original_path": prev_path}
    doc["attestation"]["signature"] = key.sign(doc) if key else None
    return doc


class TestSteward:
    """Session-scoped throwaway OpenPGP certificate resembling the real steward cert."""

    def __init__(self) -> None:
        self.gpg = find_gpg()
        self.homedir = tempfile.mkdtemp(prefix="gnupghome-test-")
        os.chmod(self.homedir, stat.S_IRWXU)
        self.env = dict(os.environ, GNUPGHOME=self.homedir)
        self._run(
            [
                "--faked-system-time",
                FAKE_PAST,
                "--quick-gen-key",
                "Test Steward <test@example.invalid>",
                "ed25519",
                "cert",
                "never",
            ]
        )
        self.primary = self._fingerprints()[0]
        self._run(["--faked-system-time", FAKE_PAST, "--quick-add-key", self.primary, "ed25519", "sign", "10y"])
        self._run(["--faked-system-time", FAKE_PAST, "--quick-add-key", self.primary, "ed25519", "sign", "1d"])
        fprs = self._fingerprints()
        self.signing = fprs[1]
        self.expired = fprs[2]
        out = subprocess.run(
            [self.gpg, "--batch", "--export", "--armor", self.primary], capture_output=True, env=self.env, check=True
        )
        self.public_armor = out.stdout.replace(b"\r\n", b"\n")

    def _run(self, args: list[str]) -> None:
        subprocess.run(
            [self.gpg, "--batch", "--quiet", "--pinentry-mode", "loopback", "--passphrase", "", *args],
            capture_output=True,
            env=self.env,
            check=True,
        )

    def _fingerprints(self) -> list[str]:
        out = subprocess.run(
            [self.gpg, "--batch", "--with-colons", "--with-subkey-fingerprints", "--list-keys"],
            capture_output=True,
            text=True,
            env=self.env,
            check=True,
        )
        return [line.split(":")[9] for line in out.stdout.splitlines() if line.startswith("fpr:")]

    def sign_detached(
        self, target: Path, output: Path | None = None, *, subkey: str | None = None, faked_time: str | None = None
    ) -> Path:
        output = output or target.with_name(target.name + ".asc")
        args = [self.gpg, "--batch", "--yes", "--quiet", "--pinentry-mode", "loopback", "--passphrase", ""]
        if faked_time:
            args += ["--faked-system-time", faked_time]
        args += [
            "--local-user",
            (subkey or self.signing) + "!",
            "--detach-sign",
            "--armor",
            "-o",
            str(output),
            str(target),
        ]
        subprocess.run(args, capture_output=True, env=self.env, check=True)
        return output

    def git_signing_env(self, *, subkey: str | None = None) -> dict[str, str]:
        env = dict(self.env)
        env.update(
            {
                "GIT_CONFIG_COUNT": "2",
                "GIT_CONFIG_KEY_0": "gpg.program",
                "GIT_CONFIG_VALUE_0": self.gpg,
                "GIT_CONFIG_KEY_1": "user.signingkey",
                "GIT_CONFIG_VALUE_1": (subkey or self.signing) + "!",
            }
        )
        return env

    def close(self) -> None:
        subprocess.run(
            [str(Path(self.gpg).with_name("gpgconf" + Path(self.gpg).suffix)), "--kill", "gpg-agent"],
            capture_output=True,
            env=self.env,
        )
        shutil.rmtree(self.homedir, ignore_errors=True)


@pytest.fixture(scope="session")
def steward() -> Iterable[TestSteward]:
    s = TestSteward()
    yield s
    s.close()


class Ledger:
    """A complete temporary ledger tree, optionally under Git."""

    def __init__(self, root: Path, steward: TestSteward) -> None:
        self.root = root
        self.steward = steward
        for d in ("attestations", "revocations", "admissions", "stewards", "schema", "scripts"):
            (root / d).mkdir(parents=True, exist_ok=True)
        for d in ("attestations", "revocations", "admissions"):
            (root / d / ".gitkeep").write_bytes(b"")
        if SCHEMA_DIR.exists():
            for f in SCHEMA_DIR.glob("*.json"):
                shutil.copy(f, root / "schema" / f.name)
        self.write("stewards/fides-anima.asc", steward.public_armor)
        self.write("stewards/expected-key-ref.txt", f"openpgp:{steward.primary.lower()}\n")
        self.write("stewards/expected-signing-subkey-ref.txt", f"openpgp:{steward.signing.lower()}\n")
        self.write("stewards/authorized-github-actors.txt", f"# verified steward logins\n{STEWARD_LOGIN}\n")
        self.write(
            ".gitattributes",
            "* text=auto eol=lf\nattestations/** -text\nrevocations/** -text\n"
            "admissions/** -text\nstewards/** -text\n*.asc -text\n",
        )
        self.has_git = False

    # -- files -------------------------------------------------------------
    def path(self, rel: str) -> Path:
        return self.root / rel

    def write(self, rel: str, data: bytes | str) -> bytes:
        p = self.path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        raw = data.encode("utf-8") if isinstance(data, str) else data
        p.write_bytes(raw)
        return raw

    def write_yaml(self, rel: str, doc: dict[str, Any]) -> bytes:
        return self.write(rel, dump_yaml(doc))

    def read(self, rel: str) -> bytes:
        return self.path(rel).read_bytes()

    def sha256(self, rel: str) -> str:
        return sha256_bytes(self.read(rel))

    def remove(self, rel: str) -> None:
        self.path(rel).unlink()

    # -- git ---------------------------------------------------------------
    def git(
        self, *args: str, env: dict[str, str] | None = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        base_env = dict(os.environ)
        base_env.update(
            {
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.invalid",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.invalid",
            }
        )
        if env:
            base_env.update(env)
        return subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, env=base_env, check=check)

    def git_init(self) -> None:
        self.git("init", "-q", "-b", "main")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.has_git = True

    def commit(self, message: str = "commit", *, sign: bool = False, subkey: str | None = None) -> str:
        self.git("add", "-A")
        args = ["commit", "-q", "--allow-empty", "-m", message]
        env = None
        if sign:
            args.insert(1, "-S")
            env = self.steward.git_signing_env(subkey=subkey)
        self.git(*args, env=env)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    # -- admissions --------------------------------------------------------
    def event_name(self, record_rel: str, seq: int) -> str:
        slug = Path(record_rel).name.split(".")[0]
        return f"admissions/{slug}.{self.sha256(record_rel)}.{seq:04d}.json"

    def record_sig_name(self, record_rel: str) -> str:
        slug = Path(record_rel).name.split(".")[0]
        return f"admissions/{slug}.{self.sha256(record_rel)}.record.asc"

    def event_template(
        self,
        record_rel: str,
        *,
        seq: int = 1,
        action: str = "admit",
        declaration_action: str | None = "attest",
        status: str = "admitted",
        previous: str | None = None,
        record_bytes: bytes | None = None,
        record_path: str | None = None,
        head_sha: str | None = None,
        requested_by: str = "github:alice",
        reason: str = "Reviewed intake and admitted the declaration.",
    ) -> dict[str, Any]:
        raw = record_bytes if record_bytes is not None else self.read(record_rel)
        doc = yaml.safe_load(raw)
        event: dict[str, Any] = {
            "schemaVersion": 1,
            "sequence": seq,
            "action": action,
            "declarationAction": declaration_action if action == "admit" else None,
            "admissionStatus": status,
            "reasonCode": "intake-reviewed" if action == "admit" else action,
            "reason": reason,
            "occurredAt": "2026-09-08T20:00:00Z",
            "record": {
                "declarationId": doc["attestation"]["declaration_id"],
                "version": doc["attestation"]["version"],
                "path": record_path or record_rel,
                "sha256": sha256_bytes(raw),
            },
            "actor": {
                "type": "steward",
                "keyRef": f"openpgp:{self.steward.primary.lower()}",
                "signingSubkeyRef": f"openpgp:{self.steward.signing.lower()}",
            },
            "request": {
                "sourceType": "github-pr" if action == "admit" else "github-issue",
                "sourceRef": f"https://github.com/{REPOSITORY}/pull/12"
                if action == "admit"
                else f"https://github.com/{REPOSITORY}/issues/40",
                "requestedBy": requested_by,
                "evidence": [],
            },
            "authority": {
                "basis": "agent-signature"
                if doc["attestation"]["authorship"] == "agent-signed"
                else "github-pr-author-match",
                "principal": doc["agent"]["fpp_id"]
                if doc["attestation"]["authorship"] == "agent-signed"
                else doc["operator"]["contact"],
                "evidenceRef": {"uri": f"https://github.com/{REPOSITORY}/pull/12#issuecomment-1", "sha256": None},
            },
            "review": None,
            "previousEvent": None,
            "correctionRef": None,
            "slugReleased": False,
        }
        if action == "admit":
            event["review"] = {
                "intakePr": f"https://github.com/{REPOSITORY}/pull/12",
                "headSha": head_sha or "0" * 40,
                "checkRun": f"https://github.com/{REPOSITORY}/actions/runs/1",
                "declarationHashes": {record_path or record_rel: sha256_bytes(raw)},
            }
        if previous:
            event["previousEvent"] = {"path": previous, "sha256": self.sha256(previous)}
        return event

    def write_event(
        self, rel: str, event: dict[str, Any], *, subkey: str | None = None, faked_time: str | None = None
    ) -> str:
        self.write(rel, json.dumps(event, indent=2, sort_keys=True) + "\n")
        self.steward.sign_detached(self.path(rel), subkey=subkey, faked_time=faked_time)
        return rel

    def admit(
        self, record_rel: str, *, seq: int = 1, subkey: str | None = None, faked_time: str | None = None, **kw: Any
    ) -> str:
        """Write .record.asc (once) and an admission event with its signature."""
        sig = self.path(self.record_sig_name(record_rel))
        if not sig.exists():
            self.steward.sign_detached(self.path(record_rel), sig, subkey=subkey, faked_time=faked_time)
        event = self.event_template(record_rel, seq=seq, **kw)
        rel = self.event_name(record_rel, seq)
        return self.write_event(rel, event, subkey=subkey, faked_time=faked_time)

    def append_event(
        self,
        record_rel: str,
        record_sha: str,
        seq: int,
        *,
        action: str,
        status: str,
        previous: str,
        subkey: str | None = None,
        **kw: Any,
    ) -> str:
        """Append an admission-only event to an existing chain (record may no longer be at record_rel)."""
        slug = Path(record_rel).name.split(".")[0]
        event = self.event_template(
            record_rel,
            seq=seq,
            action=action,
            declaration_action=None,
            status=status,
            previous=previous,
            record_bytes=kw.pop("record_bytes", None),
            record_path=record_rel,
            **kw,
        )
        rel = f"admissions/{slug}.{record_sha}.{seq:04d}.json"
        return self.write_event(rel, event, subkey=subkey)

    # -- context -----------------------------------------------------------
    def context(
        self,
        *,
        event_name: str = "pull_request",
        event_action: str = "synchronize",
        actor: str = "alice",
        author: str | None = None,
        head_repo: str = "alice/fpp-attestation-ledger",
        head_ref: str = "nova",
        head_sha: str | None = None,
        base_sha: str | None = None,
        run_id: str = "1001",
        number: int = 12,
        ref: str = "refs/heads/main",
    ) -> str:
        head_sha = head_sha or (self.head() if self.has_git else "0" * 40)
        ctx: dict[str, Any] = {
            "event_name": event_name,
            "event_action": event_action,
            "actor": actor,
            "run_id": run_id,
            "repository": REPOSITORY,
            "sha": head_sha,
            "ref": ref,
        }
        if event_name == "pull_request":
            ctx["pull_request"] = {
                "number": number,
                "html_url": f"https://github.com/{REPOSITORY}/pull/{number}",
                "author": author or actor,
                "head_repo": head_repo,
                "head_owner": head_repo.split("/")[0],
                "head_ref": head_ref,
                "head_sha": head_sha,
                "base_repo": REPOSITORY,
                "base_ref": "main",
                "base_sha": base_sha or "0" * 40,
            }
        self._context_counter = getattr(self, "_context_counter", 0) + 1
        out = self.root.parent / f"context-{self._context_counter}.json"
        out.write_text(json.dumps(ctx, indent=2), encoding="utf-8")
        return str(out)

    # -- CLIs --------------------------------------------------------------
    def _run(
        self, script: Path, args: list[str], env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        full_env = dict(os.environ, LEDGER_GPG=self.steward.gpg, PYTHONIOENCODING="utf-8")
        if env:
            full_env.update(env)
        return subprocess.run(
            [sys.executable, str(script), *args],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=full_env,
        )

    def validate(
        self,
        mode: str = "working",
        *,
        base_ref: str | None = None,
        context: str | None = None,
        extra: Iterable[str] = (),
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = ["--mode", mode, "--schema", DECLARATION_SCHEMA, "--all"]
        if base_ref:
            args += ["--base-ref", base_ref]
        if context:
            args += ["--context", context]
        args += list(extra)
        return self._run(VALIDATE, args, env)

    def verify(
        self,
        mode: str = "main",
        *,
        base_ref: str | None = None,
        context: str | None = None,
        extra: Iterable[str] = (),
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = [
            "--cert",
            "stewards/fides-anima.asc",
            "--expected-key-ref",
            "stewards/expected-key-ref.txt",
            "--expected-signing-subkey-ref",
            "stewards/expected-signing-subkey-ref.txt",
            "--mode",
            mode,
        ]
        if base_ref:
            args += ["--base-ref", base_ref]
        if context:
            args += ["--context", context]
        args += list(extra)
        return self._run(VERIFY, args, env)

    def run_script(
        self, script: Path, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self._run(script, list(args), env)


@pytest.fixture
def ledger(tmp_path: Path, steward: TestSteward) -> Ledger:
    return Ledger(tmp_path / "ledger", steward)


@pytest.fixture
def git_ledger(ledger: Ledger) -> Ledger:
    ledger.git_init()
    return ledger


def output(result: subprocess.CompletedProcess[str]) -> str:
    return (result.stdout or "") + (result.stderr or "")


def assert_fails(result: subprocess.CompletedProcess[str], *needles: str) -> None:
    text = output(result)
    assert result.returncode != 0, f"expected failure, got exit 0:\n{text}"
    for needle in needles:
        assert needle in text, f"expected {needle!r} in output:\n{text}"


def assert_passes(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, f"expected success, got exit {result.returncode}:\n{output(result)}"
