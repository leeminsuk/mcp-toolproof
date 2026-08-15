"""Freeze what the paper points at: repository, commit, artifact digests.

A reproducibility note that names no commit and no digest is a promise, not a
check.  This writes ``artifacts/v5/release.json``, which the paper and the
appendix both read, and ``artifacts/v5/SHA256SUMS``, which anyone can verify
against a clone with ``shasum -c``.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts" / "v5"
REPO_URL = "https://github.com/leeminsuk/mcp-toolproof"

# The logs every number in the paper is computed from, plus the freeze records.
ARTIFACTS = [
    "main-suite.jsonl", "holdout-suite.jsonl", "real-mcp-sdk-suite.jsonl",
    "llm-local-suite.jsonl", "drift-none.jsonl", "drift-receipt_annotation.jsonl",
    "drift-normalisation_upgrade.jsonl", "drift-unicode_nfc.jsonl",
    "drift-hash_basis_change.jsonl", "analysis.json", "freeze.json",
    "holdout-suite-freeze.json", "holdout-tooltable.json",
    "holdout-suite.jsonl.meta.json", "real-mcp-sdk-suite.jsonl.meta.json",
    "llm-local-suite.meta.json",
]
# The programs that produced them, in the order the pipeline runs.
CODE = ["toolspec.py", "provider.py", "toolsrv.py", "oracle.py", "detectors.py",
        "harness.py", "holdout.py", "mcp_server.py", "real_mcp.py", "llm_layer.py",
        "analyze.py", "make_paper.py", "make_report.py", "make_release.py"]
# Comments stay ASCII: the appendix prints these lines in a Courier face that
# carries no Hangul glyphs, and a glyph the font cannot map renders as tofu.
COMMANDS = [
    "v5/run_suites.sh                                    # main matrix 13,824 rows + 5 drift kinds",
    "python3 v5/holdout.py --seeds 3 --calls 12          # published-schema hold-out",
    "runtime/mcp-sdk-venv/bin/python v5/real_mcp.py --repeats 12   # official MCP SDK",
    "python3 v5/llm_layer.py --models qwen3:4b qwen2.5:7b gemma3:4b gemma4:12b \\",
    "    llama3.1:8b llama3.2:3b mistral:7b --calls 3 --out artifacts/v5/llm-local-suite.jsonl",
    "python3 v5/analyze.py --main artifacts/v5/main-suite.jsonl \\",
    "    --llm-local artifacts/v5/llm-local-suite.jsonl --drift artifacts/v5/drift-*.jsonl \\",
    "    --real-mcp artifacts/v5/real-mcp-sdk-suite.jsonl \\",
    "    --holdout artifacts/v5/holdout-suite.jsonl --out artifacts/v5/analysis.json",
    "python3 -m pytest tests/test_v5.py                  # regression tests",
    "python3 v5/make_release.py && python3 v5/make_paper.py && python3 v5/make_report.py",
]


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            sha.update(block)
    return sha.hexdigest()


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def main() -> None:
    entries = []
    for name in ARTIFACTS:
        path = ART / name
        if not path.exists():
            continue
        lines = sum(1 for _ in path.open("rb")) if path.suffix == ".jsonl" else None
        entries.append({"file": f"artifacts/v5/{name}", "bytes": path.stat().st_size,
                        "rows": lines, "sha256": digest(path)})
    code = [{"file": f"v5/{name}", "sha256": digest(ROOT / "v5" / name)}
            for name in CODE if (ROOT / "v5" / name).exists()]
    code += [{"file": name, "sha256": digest(ROOT / name)}
             for name in ("requirements.txt", "requirements-mcp.txt", "tests/test_v5.py")
             if (ROOT / name).exists()]
    release = {
        "repository": REPO_URL,
        "commit": git("rev-parse", "HEAD"),
        "commit_short": git("rev-parse", "--short", "HEAD"),
        "dirty": bool(git("status", "--porcelain")),
        "python": subprocess.run([sys.executable, "--version"], capture_output=True,
                                 text=True).stdout.strip(),
        "commands": COMMANDS,
        "artifacts": entries,
        "code": code,
    }
    # newline="\n" so the freeze records are byte-identical across operating
    # systems; a Windows default of os.linesep would break shasum -c elsewhere.
    (ART / "release.json").write_text(
        json.dumps(release, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    sums = "\n".join(f"{e['sha256']}  {Path(e['file']).name}" for e in entries)
    (ART / "SHA256SUMS").write_text(sums + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"commit": release["commit_short"], "dirty": release["dirty"],
                      "artifacts": len(entries), "code": len(code)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
