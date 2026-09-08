# Phase 2 — Expert Answers

Recorded 2026-08-27 after all 5 questions were served in bulk.

| # | Question (short) | Answer |
|---|------------------|--------|
| Q1 | Document `constitution_hash` = SHA-256 of `constitution.json` | **Yes** |
| Q2 | Sign admissions with long-lived subkey only; verify against pinned primary fingerprint | **Yes** |
| Q3 | `verify-signatures.py` uses system gpg + ephemeral GNUPGHOME | **Yes** |
| Q4 | Pinned `requirements.txt` (pyyaml, jsonschema, cryptography) + Python 3.11 CI | **Yes** |
| Q5 | Phase 2 test checklist as committed pytest suite in CI | **Yes** |
