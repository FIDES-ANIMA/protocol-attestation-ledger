"""Shared model, Git, GnuPG, and rule helpers for the FPP attestation ledger validators.

Nothing in this module reads, writes, or requires an OpenPGP secret key.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator

# --------------------------------------------------------------------------- frozen vocabulary

CONSTITUTION_VERSION = "1.0.0"
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
STATES = ("reviewed", "accepted", "externally-enforced", "inherited", "revoked", "forked", "superseded")
IDENTITY_BOUND_STATES = {"accepted", "inherited", "forked", "superseded"}
INITIAL_STATES = {"reviewed", "inherited"}
ALLOWED_TRANSITIONS: set[tuple[str, str]] = {
    ("reviewed", "accepted"),
    ("reviewed", "externally-enforced"),
    ("accepted", "revoked"),
    ("accepted", "forked"),
    ("accepted", "superseded"),
    ("accepted", "externally-enforced"),
    ("externally-enforced", "revoked"),
    ("externally-enforced", "accepted"),
    ("externally-enforced", "reviewed"),
    ("inherited", "accepted"),
    ("inherited", "revoked"),
    ("inherited", "forked"),
    ("inherited", "superseded"),
    ("revoked", "reviewed"),
    ("revoked", "accepted"),
    ("forked", "accepted"),
    ("forked", "superseded"),
    ("forked", "revoked"),
    ("superseded", "accepted"),
    ("superseded", "forked"),
    ("superseded", "revoked"),
}
DECLARATION_ACTIONS = ("attest", "amend", "correct-declaration", "withdraw-adoption", "re-adopt")
ADMISSION_ACTIONS = (
    "admit",
    "mark-disputed",
    "withdraw-admission",
    "reinstate-admission",
    "correct-admission",
    "resolve-dispute",
    "slug-release",
)
# action -> (allowed prior statuses, allowed resulting statuses)
ADMISSION_EDGES: dict[str, tuple[set[str | None], set[str]]] = {
    "admit": ({None}, {"admitted"}),
    "mark-disputed": ({"admitted"}, {"disputed"}),
    "withdraw-admission": ({"admitted"}, {"withdrawn"}),
    "resolve-dispute": ({"disputed"}, {"admitted", "withdrawn"}),
    "reinstate-admission": ({"withdrawn"}, {"admitted"}),
    "correct-admission": ({"admitted", "disputed"}, {"corrected"}),
    "slug-release": ({"withdrawn", "corrected"}, {"withdrawn", "corrected"}),
}

SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$")
FPP_ID_RE = re.compile(r"^fpp:ed25519:([0-9a-f]{64})$")
ACTIVE_PATH_RE = re.compile(r"^attestations/([A-Za-z0-9._-]+)\.yaml$")
REVOKED_PATH_RE = re.compile(r"^revocations/([a-z0-9-]+)\.(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.yaml$")
EVENT_PATH_RE = re.compile(r"^admissions/([a-z0-9-]+)\.([0-9a-f]{64})\.(\d{4})\.json$")
RECORD_SIG_RE = re.compile(r"^admissions/([a-z0-9-]+)\.([0-9a-f]{64})\.record\.asc$")
GITHUB_CONTACT_RE = re.compile(r"^github:([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)$")
# Assembled from fragments so this module never contains a literal armor header.
SECRET_ARMOR_RE = re.compile(rb"-----BEGIN PGP (?:PRIVATE|SECRET) KEY BLOCK-----")
PUBLIC_ARMOR_RE = re.compile(rb"-----BEGIN PGP PUBLIC KEY BLOCK-----")

# Change classes for a contributor pull request (see GOVERNANCE.md §5a). A declaration intake PR changes only
# declaration files; a maintenance PR changes only software/documentation paths; steward-only paths may never
# change in a contributor PR; a PR that mixes declaration and maintenance paths must be split.
CHANGE_CLASS_EMPTY = "empty"
CHANGE_CLASS_DECLARATION = "declaration"
CHANGE_CLASS_MAINTENANCE = "maintenance"
CHANGE_CLASS_STEWARD_ONLY = "steward-only"
CHANGE_CLASS_MIXED = "mixed"
STEWARD_ONLY_PREFIXES = ("admissions/", "stewards/", "schema/")
STEWARD_ONLY_FILES = {".gitattributes"}
# Maintenance paths whose change alters the validation rules or the CI contract itself. They are still a
# maintenance change, but the report names them so the steward reviews them explicitly and never lets the
# contributor's copy of the validators be the sole authority for its own approval.
RULES_SENSITIVE_PREFIXES = (".github/",)
RULES_SENSITIVE_FILES = {
    "scripts/ledgerlib.py",
    "scripts/validate.py",
    "scripts/verify-signatures.py",
    "scripts/ci-context.py",
    "scripts/prepare-admission.py",
    "scripts/sign-admission.py",
    "scripts/promote-admission.py",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
}
SCAN_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
}
ALLOWLIST_PATH = "stewards/authorized-github-actors.txt"
CERT_PATH = "stewards/fides-anima.asc"
KEY_REF_PATH = "stewards/expected-key-ref.txt"
SUBKEY_REF_PATH = "stewards/expected-signing-subkey-ref.txt"
AUTHORITY_EVENT_ACTIONS = {"opened", "synchronize", "reopened"}

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_FAIL_CLOSED = 2


class FailClosed(Exception):
    """Raised when a release mode cannot obtain the evidence it needs."""


# --------------------------------------------------------------------------- reporting


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.notes: list[str] = []

    def error(self, path: str | None, message: str) -> None:
        self.errors.append(f"{path}: {message}" if path else message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    @property
    def ok(self) -> bool:
        return not self.errors

    def emit(self, stream: Any = None) -> None:
        stream = stream or sys.stdout
        for n in self.notes:
            print(f"note: {n}", file=stream)
        for e in self.errors:
            print(f"FAIL {e}", file=stream)


# --------------------------------------------------------------------------- small helpers


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def slugify(text: str) -> str:
    return "-".join(t for t in re.findall(r"[a-z0-9]+", text.lower()) if t)


def contact_slug(contact: str) -> str:
    return slugify(contact.split(":", 1)[1] if ":" in contact else contact)


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(UTC)


def canonical_payload(doc: dict[str, Any]) -> bytes:
    payload = copy.deepcopy(doc)
    if isinstance(payload.get("attestation"), dict):
        payload["attestation"].pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint_public_key(public_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def verify_ed25519(public_key_hex: str, signature_hex: str, payload: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def is_public_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    host = parts.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "." in host
    non_public = (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    )
    if isinstance(ip, ipaddress.IPv6Address):
        non_public = non_public or ip.is_site_local
    return not non_public


def iter_tree_files(root: Path) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SCAN_EXCLUDED_DIRS)
        for name in sorted(filenames):
            rel = Path(dirpath, name).relative_to(root).as_posix()
            yield rel


def read_pin(root: Path, rel: str) -> str:
    p = root / rel
    if not p.exists():
        raise FailClosed(f"{rel} is missing")
    text = p.read_text(encoding="utf-8").strip().lower()
    m = re.fullmatch(r"openpgp:([0-9a-f]{40})", text)
    if not m:
        raise FailClosed(f"{rel} must contain exactly one 'openpgp:<40 hex>' fingerprint")
    return m.group(1)


def load_allowlist(root: Path) -> set[str] | None:
    p = root / ALLOWLIST_PATH
    if not p.exists():
        return None
    logins = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            logins.add(line)
    return logins


# --------------------------------------------------------------------------- git


class Git:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.available = False
        try:
            top = self._run("rev-parse", "--show-toplevel")
            self.available = Path(top).resolve() == root.resolve()
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.available = False
        self._blob_cache: dict[tuple[str, str], bytes | None] = {}

    def _run(self, *args: str, check: bool = True, env: dict[str, str] | None = None) -> str:
        result = subprocess.run(["git", *args], cwd=self.root, capture_output=True, env=env, check=False)
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        return result.stdout.decode("utf-8", "replace").strip()

    def _run_bytes(self, *args: str) -> bytes | None:
        result = subprocess.run(["git", *args], cwd=self.root, capture_output=True, check=False)
        return result.stdout if result.returncode == 0 else None

    def run(self, *args: str, env: dict[str, str] | None = None) -> str:
        """Run a git command that is allowed to mutate the repository (steward helpers only)."""
        return self._run(*args, env=env)

    def has_commits(self) -> bool:
        try:
            self._run("rev-parse", "--verify", "HEAD")
            return True
        except subprocess.CalledProcessError:
            return False

    def head(self) -> str:
        return self._run("rev-parse", "HEAD")

    def is_shallow(self) -> bool:
        """True unless Git positively reports a complete (non-shallow) history.

        A shallow clone presents its boundary commits as parentless, so a first-parent walk over it looks
        like a complete append-only history that simply started later. Anything other than an explicit
        "false" (old git, unexpected output) is treated as shallow so release modes fail closed.
        """
        try:
            answer = self._run("rev-parse", "--is-shallow-repository")
        except subprocess.CalledProcessError:
            return True
        return answer != "false"

    def rev_parse(self, ref: str) -> str | None:
        try:
            return self._run("rev-parse", "--verify", f"{ref}^{{commit}}")
        except subprocess.CalledProcessError:
            return None

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=self.root, capture_output=True
        )
        return result.returncode == 0

    def merge_base(self, a: str, b: str) -> str | None:
        try:
            return self._run("merge-base", a, b)
        except subprocess.CalledProcessError:
            return None

    def is_clean(self) -> bool:
        return self._run("status", "--porcelain") == ""

    def diff_name_status(self, base: str, head: str) -> list[tuple[str, str]]:
        out = self._run("diff", "--name-status", "--no-renames", "-z", base, head)
        items = out.split("\0")
        pairs: list[tuple[str, str]] = []
        i = 0
        while i + 1 < len(items):
            status, path = items[i], items[i + 1]
            if status and path:
                pairs.append((status[0], path))
            i += 2
        return pairs

    def show(self, ref: str, path: str) -> bytes | None:
        key = (ref, path)
        if key not in self._blob_cache:
            self._blob_cache[key] = self._run_bytes("show", f"{ref}:{path}")
        return self._blob_cache[key]

    def ls_tree(self, ref: str) -> set[str]:
        out = self._run("ls-tree", "-r", "--name-only", "-z", ref)
        return {p for p in out.split("\0") if p}

    def find_blob(self, path: str, sha256: str, head: str) -> bytes | None:
        """Return the historical bytes of ``path`` with the given SHA-256 reachable from ``head``."""
        try:
            commits = self._run("rev-list", head, "--", path).split()
        except subprocess.CalledProcessError:
            return None
        for commit in commits:
            blob = self.show(commit, path)
            if blob is not None and sha256_bytes(blob) == sha256:
                return blob
        return None

    def first_parent_chain(self, head: str) -> list[str]:
        out = self._run("rev-list", "--first-parent", "--reverse", head)
        return out.split()

    def parent(self, commit: str) -> str | None:
        parents = self._run("rev-list", "--parents", "-n", "1", commit).split()
        return parents[1] if len(parents) > 1 else None

    def verify_commit_raw(self, commit: str, env: dict[str, str], gpg_binary: str) -> tuple[int, str]:
        """Verify a commit signature with the given gpg binary inside the given (ephemeral) GNUPGHOME env."""
        result = subprocess.run(
            ["git", "-c", f"gpg.program={gpg_binary}", "verify-commit", "--raw", commit],
            cwd=self.root,
            capture_output=True,
            text=True,
            env=env,
        )
        return result.returncode, result.stderr + result.stdout


# --------------------------------------------------------------------------- gnupg


def find_gpg(explicit: str | None = None) -> str:
    if explicit:
        return explicit
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
        raise FailClosed("gpg executable not found; set LEDGER_GPG or install GnuPG")
    return found


@dataclass
class SubkeyInfo:
    fingerprint: str
    capabilities: str
    created: int
    expires: int | None
    validity: str  # gpg validity letter: e=expired, r=revoked, -/u/f... otherwise

    @property
    def usable_now(self) -> bool:
        return self.validity not in ("e", "r", "d", "i", "n")


@dataclass
class CertInfo:
    primary: str
    subkeys: dict[str, SubkeyInfo] = field(default_factory=dict)
    uids: list[str] = field(default_factory=list)


@dataclass
class SigResult:
    good: bool
    key_fingerprint: str | None = None
    primary_fingerprint: str | None = None
    sig_time: int | None = None
    key_expired: bool = False
    detail: str = ""


class Gpg:
    """Thin wrapper around a GnuPG binary that only ever operates inside an ephemeral home."""

    def __init__(self, binary: str) -> None:
        self.binary = binary

    @contextmanager
    def ephemeral_home(self) -> Iterator[dict[str, str]]:
        home = tempfile.mkdtemp(prefix="ledger-gnupghome-")
        os.chmod(home, stat.S_IRWXU)
        env = {k: v for k, v in os.environ.items() if k != "GNUPGHOME"}
        env["GNUPGHOME"] = home
        try:
            yield env
        finally:
            gpgconf = Path(self.binary).with_name("gpgconf" + Path(self.binary).suffix)
            if gpgconf.exists():
                subprocess.run([str(gpgconf), "--kill", "all"], capture_output=True, env=env)
            for _ in range(10):
                shutil.rmtree(home, ignore_errors=True)
                if not os.path.exists(home):
                    break
                time.sleep(0.2)
            shutil.rmtree(home, ignore_errors=True)

    def _run(
        self, env: dict[str, str], *args: str, input_bytes: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [self.binary, "--batch", "--no-tty", "--status-fd", "1", *args],
            capture_output=True,
            env=env,
            input=input_bytes,
        )

    def import_public_cert(self, env: dict[str, str], armor: bytes) -> None:
        if SECRET_ARMOR_RE.search(armor):
            raise FailClosed("certificate contains secret key armor; refusing to import")
        result = self._run(env, "--import", input_bytes=armor)
        if result.returncode != 0 or b"IMPORT_OK" not in result.stdout:
            raise FailClosed("certificate could not be imported: " + result.stderr.decode("utf-8", "replace").strip())

    def list_cert(self, env: dict[str, str]) -> CertInfo:
        result = self._run(env, "--with-colons", "--with-subkey-fingerprints", "--list-keys")
        primary: str | None = None
        pending: list[str] | None = None
        info: CertInfo | None = None
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            tag = fields[0]
            if tag in ("pub", "sub"):
                pending = fields
            elif tag == "fpr" and pending is not None:
                fpr = fields[9].lower()
                if pending[0] == "pub":
                    primary = fpr
                    info = CertInfo(primary=fpr)
                elif info is not None:
                    info.subkeys[fpr] = SubkeyInfo(
                        fingerprint=fpr,
                        capabilities=pending[11],
                        created=int(pending[5] or 0),
                        expires=int(pending[6]) if pending[6] else None,
                        validity=pending[1],
                    )
                pending = None
            elif tag == "uid" and info is not None:
                info.uids.append(fields[9])
        if info is None or primary is None:
            raise FailClosed("no public certificate found after import")
        return info

    def verify_detached(self, env: dict[str, str], signature: Path, data: Path) -> SigResult:
        result = self._run(env, "--verify", str(signature), str(data))
        return parse_status(result.stdout.decode("utf-8", "replace"), result.returncode)


def parse_status(status_text: str, returncode: int) -> SigResult:
    res = SigResult(good=False, detail="")
    lines = [ln for ln in status_text.splitlines() if ln.startswith("[GNUPG:] ")]
    for ln in lines:
        parts = ln.split()
        tag = parts[1] if len(parts) > 1 else ""
        if tag == "VALIDSIG" and len(parts) >= 12:
            res.key_fingerprint = parts[2].lower()
            res.sig_time = int(parts[4]) if parts[4].isdigit() else None
            res.primary_fingerprint = parts[11].lower()
        elif tag == "EXPKEYSIG":
            res.key_expired = True
        elif tag in ("BADSIG",):
            res.detail = "BADSIG: signature does not match the data"
        elif tag in ("ERRSIG", "NO_PUBKEY"):
            res.detail = f"{tag}: signature not verifiable with the committed certificate"
    res.good = res.key_fingerprint is not None and res.primary_fingerprint is not None and "BADSIG" not in res.detail
    if not res.good and not res.detail:
        res.detail = f"gpg exited {returncode} without a valid signature status"
    return res


# --------------------------------------------------------------------------- records


@dataclass
class Record:
    path: str
    raw: bytes
    doc: dict[str, Any]
    historical: bool = False

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.raw)

    @property
    def is_active_path(self) -> bool:
        return self.path.startswith("attestations/")

    @property
    def agent(self) -> dict[str, Any]:
        return self.doc.get("agent") or {}

    @property
    def operator(self) -> dict[str, Any]:
        return self.doc.get("operator") or {}

    @property
    def adoption(self) -> dict[str, Any]:
        return self.doc.get("adoption") or {}

    @property
    def attestation(self) -> dict[str, Any]:
        return self.doc.get("attestation") or {}

    @property
    def slug(self) -> str | None:
        return self.agent.get("slug")

    @property
    def name(self) -> str:
        return str(self.agent.get("name") or "")

    @property
    def fpp_id(self) -> str | None:
        return self.agent.get("fpp_id")

    @property
    def public_key_hex(self) -> str | None:
        return self.agent.get("public_key_hex")

    @property
    def contact(self) -> str:
        return str(self.operator.get("contact") or "")

    @property
    def state(self) -> str | None:
        return self.adoption.get("lifecycle_state")

    @property
    def declaration_id(self) -> str | None:
        return self.attestation.get("declaration_id")

    @property
    def version(self) -> int:
        v = self.attestation.get("version")
        return v if isinstance(v, int) and not isinstance(v, bool) else 0

    @property
    def action(self) -> str | None:
        return self.attestation.get("action")

    @property
    def authorship(self) -> str | None:
        return self.attestation.get("authorship")

    @property
    def predecessor(self) -> dict[str, Any] | None:
        pred = self.attestation.get("predecessor_record")
        return pred if isinstance(pred, dict) else None

    @property
    def transition(self) -> dict[str, Any]:
        t = self.adoption.get("transition")
        return t if isinstance(t, dict) else {}

    def identity_key(self) -> tuple[str, str]:
        if self.authorship == "agent-signed" and self.fpp_id:
            return ("fpp", self.fpp_id)
        return ("operator", self.contact.lower())

    def describe_identity(self) -> str:
        kind, value = self.identity_key()
        return f"authenticated fpp_id={value}" if kind == "fpp" else f"operator-reported contact={value}"


def parse_record(path: str, raw: bytes, report: Report | None = None) -> Record | None:
    try:
        docs = list(yaml.safe_load_all(raw))
    except yaml.YAMLError as exc:
        if report:
            report.error(path, f"YAML parse error: {str(exc).splitlines()[0]}")
        return None
    if len(docs) != 1 or not isinstance(docs[0], dict):
        if report:
            report.error(path, "declaration must be exactly one YAML mapping document")
        return None
    return Record(path=path, raw=raw, doc=docs[0])


def load_schema(path: Path) -> Draft202012Validator:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def schema_errors(validator: Draft202012Validator, doc: Any) -> list[str]:
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(map(str, e.absolute_path))):
        loc = "$" + "".join(f".{p}" if isinstance(p, str) else f"[{p}]" for p in err.absolute_path)
        out.append(f"{loc}: {err.message}")
    return out


# --------------------------------------------------------------------------- admission events


@dataclass
class Event:
    path: str
    raw: bytes
    doc: dict[str, Any]
    slug: str
    record_sha: str
    sequence: int

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.raw)

    @property
    def action(self) -> str:
        return str(self.doc.get("action"))

    @property
    def status(self) -> str:
        return str(self.doc.get("admissionStatus"))


@dataclass
class Chain:
    slug: str
    record_sha: str
    events: list[Event]
    errors: list[str] = field(default_factory=list)

    @property
    def latest(self) -> Event | None:
        return self.events[-1] if self.events else None

    @property
    def status(self) -> str | None:
        return self.latest.status if self.latest else None

    @property
    def slug_released(self) -> bool:
        return bool(self.latest and self.latest.doc.get("slugReleased") is True)


def load_chains(root: Path, report: Report | None = None) -> dict[tuple[str, str], Chain]:
    """Parse every admissions/<slug>.<sha>.<seq>.json into per-record chains (structural only)."""
    chains: dict[tuple[str, str], Chain] = {}
    admissions = root / "admissions"
    if not admissions.exists():
        return chains
    for p in sorted(admissions.iterdir()):
        rel = f"admissions/{p.name}"
        if p.name == ".gitkeep" or p.suffix == ".asc":
            continue
        m = EVENT_PATH_RE.match(rel)
        if not m:
            if report:
                report.error(rel, "unexpected file under admissions/; expected <slug>.<sha256>.<seq>.json or .asc")
            continue
        slug, sha, seq = m.group(1), m.group(2), int(m.group(3))
        raw = p.read_bytes()
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if report:
                report.error(rel, f"event is not valid JSON: {exc}")
            continue
        if not isinstance(doc, dict):
            if report:
                report.error(rel, "event must be a JSON object")
            continue
        chains.setdefault((slug, sha), Chain(slug=slug, record_sha=sha, events=[])).events.append(
            Event(path=rel, raw=raw, doc=doc, slug=slug, record_sha=sha, sequence=seq)
        )
    for chain in chains.values():
        chain.events.sort(key=lambda e: e.sequence)
    return chains


def check_chain_structure(chain: Chain, root: Path, report: Report) -> None:
    """Sequence, previousEvent, status edges. Signature checks live in verify-signatures.py."""
    prev_status: str | None = None
    prev_event: Event | None = None
    for expected, ev in enumerate(chain.events, start=1):
        if ev.sequence != expected:
            report.error(ev.path, f"admission sequence gap: expected {expected:04d}, found {ev.sequence:04d}")
            return
        if ev.doc.get("sequence") != ev.sequence:
            report.error(ev.path, "sequence field does not match the filename")
        if ev.doc.get("record", {}).get("sha256") != chain.record_sha:
            report.error(ev.path, "record.sha256 does not match the record hash in the filename")
        action = ev.action
        edge = ADMISSION_EDGES.get(action)
        if edge is None:
            report.error(ev.path, f"unknown admission action {action!r}")
            return
        allowed_from, allowed_to = edge
        if prev_status not in allowed_from:
            report.error(ev.path, f"invalid admission edge: {prev_status or '(none)'} --{action}--> {ev.status}")
        if ev.status not in allowed_to:
            report.error(ev.path, f"action {action} cannot produce admissionStatus {ev.status!r}")
        if action == "slug-release" and prev_status is not None and ev.status != prev_status:
            report.error(ev.path, "slug-release must keep the prior admission status")
        if not str(ev.doc.get("reason") or "").strip():
            report.error(ev.path, "reason must be a non-empty string")
        actor = ev.doc.get("actor") or {}
        if actor.get("type") != "steward":
            report.error(ev.path, "actor.type must be 'steward'")
        prev_ref = ev.doc.get("previousEvent")
        if expected == 1:
            if prev_ref is not None:
                report.error(ev.path, "first event must not have previousEvent")
        else:
            assert prev_event is not None
            if not isinstance(prev_ref, dict):
                report.error(ev.path, "previousEvent is required after sequence 0001")
            else:
                if prev_ref.get("path") != prev_event.path:
                    report.error(ev.path, f"previousEvent.path must be {prev_event.path}")
                if prev_ref.get("sha256") != prev_event.sha256:
                    report.error(ev.path, "previousEvent.sha256 does not hash the exact prior event bytes")
        prev_status = ev.status
        prev_event = ev


# --------------------------------------------------------------------------- github context


@dataclass
class Context:
    raw: dict[str, Any]

    @property
    def event_name(self) -> str:
        return str(self.raw.get("event_name") or "")

    @property
    def event_action(self) -> str:
        return str(self.raw.get("event_action") or "")

    @property
    def actor(self) -> str:
        return str(self.raw.get("actor") or "").lower()

    @property
    def repository(self) -> str:
        return str(self.raw.get("repository") or "")

    @property
    def sha(self) -> str:
        return str(self.raw.get("sha") or "")

    @property
    def pr(self) -> dict[str, Any]:
        pr = self.raw.get("pull_request")
        return pr if isinstance(pr, dict) else {}

    @property
    def pr_author(self) -> str:
        return str(self.pr.get("author") or "").lower()

    @property
    def head_repo(self) -> str:
        return str(self.pr.get("head_repo") or "")

    @property
    def head_owner(self) -> str:
        return str(self.pr.get("head_owner") or self.head_repo.split("/")[0]).lower()

    @property
    def head_ref(self) -> str:
        return str(self.pr.get("head_ref") or "")

    @property
    def head_sha(self) -> str:
        return str(self.pr.get("head_sha") or self.sha)

    @property
    def base_repo(self) -> str:
        return str(self.pr.get("base_repo") or "")

    @property
    def base_sha(self) -> str:
        return str(self.pr.get("base_sha") or "")

    @property
    def is_fork(self) -> bool:
        return bool(self.head_repo) and self.head_repo.lower() != self.repository.lower()


def load_context(path: str | None) -> Context | None:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        raise FailClosed(f"--context file {path} does not exist")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FailClosed(f"--context is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise FailClosed("--context must be a JSON object")
    return Context(raw=data)


def require_release_inputs(mode: str, git: Git, base_ref: str | None, context: Context | None) -> str | None:
    """Fail closed unless the inputs a release mode depends on are present. Returns resolved base SHA."""
    if mode == "working":
        return None
    if not git.available or not git.has_commits():
        raise FailClosed(f"{mode} mode requires a Git repository with full history; none is available")
    if git.is_shallow():
        raise FailClosed(
            f"{mode} mode requires complete Git history but this repository is shallow; a truncated history "
            "cannot prove append-only behaviour (use fetch-depth: 0 or `git fetch --unshallow`)"
        )
    if not git.is_clean():
        raise FailClosed(f"{mode} mode requires the working tree to equal HEAD (uncommitted changes present)")
    if mode == "main":
        if context is not None:
            if context.event_name != "push":
                raise FailClosed("main mode context must come from a push event")
            if context.sha and context.sha != git.head():
                raise FailClosed("main mode context sha does not equal HEAD")
        return None
    if not base_ref:
        raise FailClosed(f"{mode} mode requires --base-ref <sha> (immutable base commit)")
    if context is None:
        raise FailClosed(f"{mode} mode requires --context <trusted GitHub event context>")
    base = git.rev_parse(base_ref)
    if base is None:
        raise FailClosed(f"--base-ref {base_ref} is not a reachable commit")
    if context.event_name != "pull_request":
        raise FailClosed(f"{mode} mode requires pull_request event context, got {context.event_name!r}")
    if context.base_sha and context.base_sha != base:
        raise FailClosed(f"context base sha {context.base_sha} differs from --base-ref {base}")
    if context.head_sha != git.head():
        raise FailClosed(f"context head sha {context.head_sha} does not equal the checked-out HEAD {git.head()}")
    if context.base_repo and context.base_repo.lower() != context.repository.lower():
        raise FailClosed("pull request base repository is not this repository")
    return base


def check_mode_context(mode: str, context: Context | None, root: Path, report: Report) -> None:
    """Trusted-context rules that select and constrain intake vs admission."""
    if context is None or mode not in ("intake", "admission"):
        return
    if mode == "admission":
        if context.is_fork:
            report.error(None, "admission mode requires the admission branch to live in the base repository")
        if not context.head_ref.startswith("admission/"):
            report.error(None, f"admission mode requires an admission/* branch, got {context.head_ref!r}")
        allow = load_allowlist(root)
        if allow is None:
            report.error(None, f"{ALLOWLIST_PATH} is missing; admission mode fails closed")
            return
        for label, login in (("actor", context.actor), ("PR author", context.pr_author)):
            if login not in allow:
                report.error(None, f"admission {label} {login!r} is not in {ALLOWLIST_PATH}")
    else:
        if context.head_ref.startswith("admission/") and not context.is_fork:
            report.error(None, "intake mode cannot be used for an admission/* branch in the base repository")


def github_authority_ok(context: Context, login: str, report: Report, path: str, what: str) -> bool:
    """Bind operator authority to the final head-producing event, actor, author, and branch/fork owner."""
    ok = True
    if context.event_action not in AUTHORITY_EVENT_ACTIONS:
        report.error(
            path,
            f"{what}: authority requires an opened/synchronize/reopened event that produced this head, "
            f"got {context.event_action!r}; reruns and other events supply no authority",
        )
        ok = False
    if context.pr_author != login:
        report.error(path, f"{what}: PR author {context.pr_author!r} does not match operator authority github:{login}")
        ok = False
    if context.actor != login:
        report.error(path, f"{what}: event actor {context.actor!r} does not match operator authority github:{login}")
        ok = False
    if context.is_fork:
        if context.head_owner != login:
            report.error(
                path, f"{what}: fork owner {context.head_owner!r} does not match operator authority github:{login}"
            )
            ok = False
    else:
        prefix = f"intake/{login}/"
        if not context.head_ref.startswith(prefix):
            report.error(path, f"{what}: base-repository branch {context.head_ref!r} must be under {prefix}")
            ok = False
    return ok


def steward_transport_ok(context: Context, root: Path, report: Report, path: str) -> bool:
    allow = load_allowlist(root)
    if allow is None:
        report.error(path, f"out-of-band intake requires steward transport but {ALLOWLIST_PATH} is missing")
        return False
    ok = True
    for label, login in (("actor", context.actor), ("PR author", context.pr_author)):
        if login not in allow:
            report.error(
                path,
                f"operator contact is not a GitHub login; out-of-band intake must be transported by a "
                f"steward, but {label} {login!r} is not in {ALLOWLIST_PATH}",
            )
            ok = False
    if ok:
        if context.is_fork:
            if context.head_owner not in allow:
                report.error(path, "out-of-band intake fork must be owned by a steward actor")
                ok = False
        elif not context.head_ref.startswith(f"intake/{context.actor}/"):
            report.error(path, f"out-of-band intake branch must be under intake/{context.actor}/")
            ok = False
    return ok


def posix(path: str | Path) -> str:
    return PurePosixPath(str(path).replace("\\", "/")).as_posix()


# --------------------------------------------------------------------------- change classification


@dataclass
class ChangeClassification:
    """How a contributor pull request's diff is classified (GOVERNANCE.md §5a)."""

    change_class: str
    declaration_paths: list[str] = field(default_factory=list)
    maintenance_paths: list[str] = field(default_factory=list)
    steward_only_paths: list[str] = field(default_factory=list)
    rules_sensitive_paths: list[str] = field(default_factory=list)


def is_declaration_change_path(path: str) -> bool:
    return path.startswith("attestations/") or path.startswith("revocations/")


def is_steward_only_path(path: str) -> bool:
    return path.endswith(".asc") or path in STEWARD_ONLY_FILES or any(path.startswith(p) for p in STEWARD_ONLY_PREFIXES)


def is_rules_sensitive_path(path: str) -> bool:
    return path in RULES_SENSITIVE_FILES or any(path.startswith(p) for p in RULES_SENSITIVE_PREFIXES)


def classify_change_paths(paths: Iterable[str]) -> ChangeClassification:
    """Sort changed paths into declaration, maintenance, and steward-only buckets and name the resulting class.

    Steward-only paths make the whole change ``steward-only`` regardless of what else changed: a contributor
    PR may never carry them. Otherwise a change touching both declaration and maintenance paths is ``mixed``
    and must be split, because the two classes are reviewed and merged by different procedures.
    """
    result = ChangeClassification(change_class=CHANGE_CLASS_EMPTY)
    for path in sorted(set(paths)):
        if is_steward_only_path(path):
            result.steward_only_paths.append(path)
        elif is_declaration_change_path(path):
            result.declaration_paths.append(path)
        else:
            result.maintenance_paths.append(path)
            if is_rules_sensitive_path(path):
                result.rules_sensitive_paths.append(path)
    if result.steward_only_paths:
        result.change_class = CHANGE_CLASS_STEWARD_ONLY
    elif result.declaration_paths and result.maintenance_paths:
        result.change_class = CHANGE_CLASS_MIXED
    elif result.declaration_paths:
        result.change_class = CHANGE_CLASS_DECLARATION
    elif result.maintenance_paths:
        result.change_class = CHANGE_CLASS_MAINTENANCE
    return result


def scan_secret_armor(root: Path, files: Iterable[str], report: Report) -> None:
    for rel in files:
        p = root / rel
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if SECRET_ARMOR_RE.search(data):
            report.error(rel, "contains OpenPGP secret key armor; secret material must never enter the ledger")


def check_cert_pins(gpg: Gpg, root: Path, report: Report) -> CertInfo | None:
    """Rule 29 + subkey pin: the committed cert must match both independent pins."""
    cert_path = root / CERT_PATH
    if not cert_path.exists():
        report.error(CERT_PATH, "steward public certificate is missing")
        return None
    armor = cert_path.read_bytes()
    if SECRET_ARMOR_RE.search(armor):
        report.error(CERT_PATH, "certificate file contains secret key armor")
        return None
    if not PUBLIC_ARMOR_RE.search(armor):
        report.error(CERT_PATH, "certificate file is not an ASCII-armored public key block")
        return None
    try:
        primary_pin = read_pin(root, KEY_REF_PATH)
        subkey_pin = read_pin(root, SUBKEY_REF_PATH)
    except FailClosed as exc:
        report.error(None, str(exc))
        return None
    with gpg.ephemeral_home() as env:
        try:
            gpg.import_public_cert(env, armor)
            info = gpg.list_cert(env)
        except FailClosed as exc:
            report.error(CERT_PATH, str(exc))
            return None
    if info.primary != primary_pin:
        report.error(CERT_PATH, f"primary fingerprint {info.primary} does not equal {KEY_REF_PATH} pin {primary_pin}")
    sub = info.subkeys.get(subkey_pin)
    if sub is None:
        report.error(CERT_PATH, f"{SUBKEY_REF_PATH} pin {subkey_pin} is not a subkey of the committed certificate")
    else:
        if "s" not in sub.capabilities:
            report.error(SUBKEY_REF_PATH, f"pinned subkey {subkey_pin} has no signing capability")
        if not sub.usable_now:
            report.error(
                SUBKEY_REF_PATH, f"pinned signing subkey {subkey_pin} is expired or revoked (validity {sub.validity!r})"
            )
    return info
