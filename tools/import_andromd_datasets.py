#!/usr/bin/env python3
"""Validate AndroMD CSVs and commit them to this branch through Git LFS.

This script intentionally performs no builds, tests, or GitHub Actions runs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

BRANCH = "hardening/complete-antivirus-no-ci"
REPOSITORY_FRAGMENT = "zojajiali4-cpu/ANTIVIRUS-AL-Ai"
EXPECTED_ROWS = 600_298
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
LABELS = {"benign", "malware"}


def run(args: list[str], *, check: bool = True, capture: bool = True) -> str:
    p = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and p.returncode:
        detail = (p.stderr or p.stdout or "").strip()
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(args)}\n{detail}")
    return (p.stdout or "").strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(4 * 1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def validate_csv(path: Path, kind: str, db: sqlite3.Connection) -> dict:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"File not found: {path}")

    table = kind
    if kind == "zeroone":
        expected_columns = 119
        expected_features = 116
    elif kind == "mnf":
        expected_columns = 302
        expected_features = 300
    else:
        raise ValueError(f"Unsupported dataset kind: {kind}")

    db.execute(f"DROP TABLE IF EXISTS {table}")
    db.execute(f"CREATE TABLE {table} (sha TEXT PRIMARY KEY, label TEXT NOT NULL) WITHOUT ROWID")
    counts: Counter[str] = Counter()
    row_count = 0

    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError(f"{path.name}: empty CSV") from None

        if len(header) != expected_columns:
            raise ValueError(
                f"{path.name}: expected {expected_columns} columns, found {len(header)}"
            )
        if header[0].strip().lower() != "sha256" or header[-1].strip().lower() != "label":
            raise ValueError(f"{path.name}: expected sha256 as first and Label as last column")
        if kind == "zeroone" and header[1].strip().upper() != "TOTCLASSES":
            raise ValueError(f"{path.name}: expected TOTCLASSES as the second column")
        if len(set(header)) != len(header):
            raise ValueError(f"{path.name}: duplicate column names found")

        with db:
            for line_number, row in enumerate(reader, start=2):
                if len(row) != expected_columns:
                    raise ValueError(
                        f"{path.name}:{line_number}: expected {expected_columns} fields, "
                        f"found {len(row)}"
                    )

                sample_hash = row[0].strip().lower()
                if not HASH_RE.fullmatch(sample_hash):
                    raise ValueError(f"{path.name}:{line_number}: invalid SHA-256 value")

                label = row[-1].strip().lower()
                if label not in LABELS:
                    raise ValueError(f"{path.name}:{line_number}: invalid label {row[-1]!r}")

                if kind == "zeroone":
                    try:
                        total_classes = int(row[1].strip())
                    except ValueError:
                        raise ValueError(
                            f"{path.name}:{line_number}: TOTCLASSES is not an integer"
                        ) from None
                    if total_classes < 0:
                        raise ValueError(f"{path.name}:{line_number}: negative TOTCLASSES")
                    features = row[2:-1]
                else:
                    features = row[1:-1]

                if len(features) != expected_features:
                    raise ValueError(f"{path.name}:{line_number}: unexpected feature count")
                if any(value.strip() not in {"0", "1"} for value in features):
                    raise ValueError(
                        f"{path.name}:{line_number}: non-binary value in indicator features"
                    )

                try:
                    db.execute(
                        f"INSERT INTO {table} (sha, label) VALUES (?, ?)",
                        (sample_hash, label),
                    )
                except sqlite3.IntegrityError:
                    raise ValueError(
                        f"{path.name}:{line_number}: duplicate SHA-256 {sample_hash}"
                    ) from None

                counts[label] += 1
                row_count += 1

    if row_count != EXPECTED_ROWS:
        raise ValueError(
            f"{path.name}: expected {EXPECTED_ROWS:,} data rows for AndroMD V1, "
            f"found {row_count:,}"
        )

    return {
        "kind": kind,
        "path": path,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "rows": row_count,
        "columns": expected_columns,
        "features": expected_features,
        "labels": dict(counts),
    }


def compare_datasets(db: sqlite3.Connection) -> dict:
    z = db.execute("SELECT COUNT(*) FROM zeroone").fetchone()[0]
    m = db.execute("SELECT COUNT(*) FROM mnf").fetchone()[0]
    missing_mnf = db.execute(
        "SELECT COUNT(*) FROM zeroone z LEFT JOIN mnf m ON m.sha=z.sha WHERE m.sha IS NULL"
    ).fetchone()[0]
    missing_zeroone = db.execute(
        "SELECT COUNT(*) FROM mnf m LEFT JOIN zeroone z ON z.sha=m.sha WHERE z.sha IS NULL"
    ).fetchone()[0]
    label_mismatches = db.execute(
        "SELECT COUNT(*) FROM zeroone z JOIN mnf m ON m.sha=z.sha WHERE m.label<>z.label"
    ).fetchone()[0]
    result = {
        "zeroone_rows": z,
        "mnf_rows": m,
        "zeroone_hashes_missing_from_mnf": missing_mnf,
        "mnf_hashes_missing_from_zeroone": missing_zeroone,
        "label_mismatches": label_mismatches,
    }
    if any((missing_mnf, missing_zeroone, label_mismatches)) or z != m:
        raise ValueError(f"ZeroOne/MNF cross-dataset mismatch: {result}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeroone", type=Path, help="Path to AndroMD_ZeroOne_Dataset.csv")
    parser.add_argument("--mnf", type=Path, help="Path to AndroMD_MNF_Dataset.csv")
    args = parser.parse_args()

    supplied = [(args.zeroone, "zeroone"), (args.mnf, "mnf")]
    supplied = [(p, kind) for p, kind in supplied if p is not None]
    if not supplied:
        parser.error("provide --zeroone and/or --mnf")

    root = Path(run(["git", "rev-parse", "--show-toplevel"])).resolve()
    os.chdir(root)
    # Fetch branch pointers without downloading any existing LFS payloads.
    os.environ["GIT_LFS_SKIP_SMUDGE"] = "1"

    origin = run(["git", "remote", "get-url", "origin"])
    if REPOSITORY_FRAGMENT.lower() not in origin.lower():
        raise RuntimeError(f"Unexpected origin remote: {origin}")

    current_branch = run(["git", "branch", "--show-current"])
    if current_branch != BRANCH:
        raise RuntimeError(
            f"Switch to {BRANCH!r} first; current branch is {current_branch!r}"
        )
    if run(["git", "status", "--porcelain"]):
        raise RuntimeError("Working tree is not clean; commit or stash unrelated changes first")

    run(["git", "fetch", "origin", BRANCH])
    run(["git", "pull", "--ff-only", "origin", BRANCH])
    run(["git", "lfs", "version"])
    run(["git", "lfs", "install", "--local"])

    for _, kind in supplied:
        target = f"datasets/AndroMD_{'ZeroOne' if kind == 'zeroone' else 'MNF'}_Dataset.csv"
        attr = run(["git", "check-attr", "filter", "--", target])
        if not attr.endswith("filter: lfs"):
            raise RuntimeError(f"Git LFS tracking is not active for {target}: {attr}")

    db_fd, db_path = tempfile.mkstemp(prefix="andromd-", suffix=".sqlite")
    os.close(db_fd)
    db = sqlite3.connect(db_path)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA temp_store=FILE")

    try:
        reports = []
        for source, kind in supplied:
            reports.append(validate_csv(source, kind, db))

        cross_check = None
        kinds = {r["kind"] for r in reports}
        if kinds == {"zeroone", "mnf"}:
            cross_check = compare_datasets(db)

        targets = []
        for report in reports:
            target = root / "datasets" / (
                "AndroMD_ZeroOne_Dataset.csv" if report["kind"] == "zeroone"
                else "AndroMD_MNF_Dataset.csv"
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            source = report["path"]
            if source != target.resolve():
                shutil.copy2(source, target)
            if target.stat().st_size != report["bytes"] or sha256_file(target) != report["sha256"]:
                raise RuntimeError(f"Copy verification failed for {target}")
            targets.append((target, report))

        stage_paths = [str(path.relative_to(root)) for path, _ in targets]
        run(["git", "add", "--", *stage_paths])

        for path, report in targets:
            rel = str(path.relative_to(root))
            pointer = run(["git", "show", f":{rel}"])
            expected = (
                "version https://git-lfs.github.com/spec/v1\n"
                f"oid sha256:{report['sha256']}\n"
                f"size {report['bytes']}"
            )
            if pointer.strip() != expected.strip():
                raise RuntimeError(
                    f"{rel} is not staged as the expected Git LFS pointer; refusing commit"
                )

        staged = set(run(["git", "diff", "--cached", "--name-only"]).splitlines())
        unexpected = staged - set(stage_paths)
        if unexpected:
            raise RuntimeError(f"Unexpected staged files: {sorted(unexpected)}")

        changed = subprocess.run(
            ["git", "diff", "--cached", "--quiet"], check=False
        ).returncode != 0

        if changed:
            run(["git", "commit", "-m", "Add validated AndroMD datasets via Git LFS"])

        # Explicit LFS push also makes a retry safe when the Git commit already exists.
        run(["git", "lfs", "push", "origin", BRANCH])
        run(["git", "push", "origin", BRANCH])
        run(["git", "fetch", "origin", BRANCH])
        run(["git", "lfs", "fsck"])
        remote_sha = run(["git", "ls-remote", "origin", f"refs/heads/{BRANCH}"]).split()[0]
        local_sha = run(["git", "rev-parse", "HEAD"])
        if remote_sha != local_sha:
            raise RuntimeError(
                f"Remote branch verification failed: remote={remote_sha}, local={local_sha}"
            )

        print("\nSUCCESS — LFS push completed and remote branch ref verified.")
        for report in reports:
            print(
                f"{report['kind']}: {report['rows']:,} rows, {report['columns']} columns, "
                f"{report['bytes']:,} bytes, SHA-256 {report['sha256']}, "
                f"labels={report['labels']}"
            )
        if cross_check is not None:
            print(f"ZeroOne/MNF cross-check: {cross_check}")
        print(f"Commit: {local_sha}")
        print("No build, tests, or GitHub Actions were run.")
        return 0
    finally:
        db.close()
        try:
            os.unlink(db_path)
        except OSError:
            pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
