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
EXPECTED_LABEL_COUNTS = {"benign": 397_814, "malware": 202_484}
ZEROONE_HEADER = ["sha256","TOTCLASSES","XML","WWW","WINDOW","UTIL","UTF","URL","URI","UDP","TRANSPORT","TOR","TELEPHONY","SYSTEM","SUBSCRIBER","STORAGE","SSL","SOCKET","SMS","SIM","SIGNATURE","SHELL","SHAREDPREFERENCES","SERVICE","SERVER","SERIAL","SENDTEXTMESSAGE","SEND","SECURITY","SD","SCREENSHOT","RUNTIME","RUNNABLE","RESOURCE","REGISTRY","REFLECT","READ","RAR","PROXY","PROPERT","PROCESS","PRIVATEKEY","POWERMANAGER","POLICY","PNG","PKG_NAME","PERMISSION","PDF","PATH","PARENT","PACKET","PACKAGE","OUTPUTSTREAM","ONRECEIVE","OBJECT","NOTIFICATION","NEWINSTANCE","NETWORK","NETMASK","NET","NATIVE","NAMING","MKDIR","MESSAGE","MEMORY","MEDIA","MAP","LOOKUP","LONGITUDE","LOCATION","LOCALHOST","LOADLIBRARY","LOADEDAPK","LOADCLASS","LOAD","LATITUDE","JSON","JAR","INVO","INTENT","INSTANCE","INPUTSTREAM","INPUTSOURCE","INITIALIZED","IMEI","HTTP","HOST","GOTO","FTP","FILE","EXEC","ETHERNET","ENCRYPT","DRIVER","DEX","DEVICE","DECRYPT","DECODE","DATAGRAM","CONTENT","CONTACTS","CONNECT","CLONE","CLIENT","CLASSLOADER","CIPHER","CHECK","CACHE","BROADCAST","BASE","AUTH","AUDIO","APP","APK","AES","ADDRESS","ACTIVITY","ACCESS","Label"]
MNF_HEADER = ["sha256","write","broadcast","WRITE_USE_APP_FEATURE_SURVEY","WRITE_USER_DICTIONARY","WRITE_SYNC_SETTINGS","WRITE_SOCIAL_STREAM","WRITE_SMS","WRITE_SETTINGS","WRITE_SECURE_SETTINGS","WRITE_SECURE","WRITE_RECORD_AUDIO","WRITE_PROFILE","WRITE_PHONE_STATE","WRITE_OWNER_DATA","WRITE_ONLY","WRITE_MMS","WRITE_MEDIA_STORAGE","WRITE_INTERNAL_STORAGE","WRITE_HISTORY_BOOKMARKS","WRITE_GSERVICES","WRITE_GMAIL","WRITE_EXTERNAL_STORAGES","WRITE_EXTERNAL_STORAGE","WRITE_DB","WRITE_CONTACTS","WRITE_CLIPS","WRITE_CALL_LOG","WRITE_CALENDAR","WRITE_APP_WIDGET_DATA","WRITE_APN_STORAGE","WRITE_APN_SETTINGS","WRITE_APN_SETTING","WIFI_LOCK","WAKE_LOCK","VPN","VOIP_INTERFACE","VIRUS_SCAN","VIBRATE","USE_SYNC_KIT","USE_SIP","USE_FINGERPRINT","USE_CREDENTIALS","USES_POLICY_FORCE_LOCK","USEFMRADIO","UPDATE_SHORTCUT","UPDATE_DEVICE_STATS","UPDATE_CREDENTIALS","UPDATE_COUNT","UPDATE_BADGE","UPDATE_APP_OPS_STATS","UNINSTALL_SHORTCUT","UAPUSH_MESSAGE","TRANSMIT_IR","THEME_PROVIDER_ACCESS","SYSTEM_OVERLAY_WINDOW","SYSTEM_ALERT_WINDOW","SUBSCRIBED_FEEDS_WRITE","SUBSCRIBED_FEEDS_READ","STATUS_BAR_SERVICE","START_WIDGET_SERVICE","SOFT_RESET","SIM_STATE_READY","SIGNAL_PERSISTENT_PROCESSES","SHUTDOWN","SHARE","SET_WALLPAPER_HINTS","SET_WALLPAPER_COMPONENT","SET_WALLPAPER","SET_TIME_ZONE","SET_TIME","SET_PROCESS_LIMIT","SET_PROCESS_FOREGROUND","SET_PREFERRED_APPLICATIONS","SET_POINTER_SPEED","SET_ORIENTATION","SET_DEBUG_APP","SET_ANIMATION_SCALE","SET_ALWAYS_FINISH","SET_ALARM","SET_ACTIVITY_WATCHER","SEND_SMS_NO_CONFIRMATION","SEND_SMS","SEND_RESPOND_VIA_MESSAGE","SEND_DOWNLOAD_COMPLETED_INTENTS","RUN_INSTRUMENTATION","RIDE_EXTERNAL_STORAGE","RESTART_PACKAGES","REQUEST_SUPERUSER","REQUEST_INSTALL_PACKAGES","REQUEST_IGNORE_BATTERY_OPTIMIZATIONS","REQUEST","REORDER_TASKS","REMOTE_CONTROL","RECORD_VIDEO","RECORD_AUDIO","RECIVER","RECEIVE_WAP_PUSH","RECEIVE_USER_PRESENT","RECEIVE_SMS","RECEIVE_SENDTO","RECEIVE_MMS","RECEIVE_BOOT_COMPLETE","REBOOT_IPO","REBOOT","REAL_GET_TASKS","READ_WRITE_ALL_VOICEMAIL","READ_USER_DICTIONARY","READ_SYNC_STATS","READ_SYNC_SETTINGS","READ_SOCIAL_STREAM","READ_SMS","READ_SETTINGS","READ_SECURE_SETTINGS","READ_RECORD_AUDIO","READ_PROFILE","READ_PHONE_STATE","READ_PHONE_NUMBERS","READ_OWNER_DATA","READ_ONLY","READ_NETWORK_USAGE_HISTORY","READ_MSG_PREF","READ_MMS","READ_MESSAGES","READ_LOGS","READ_KEY_DETAILS","READ_INTERNAL_STORAGE","READ_INSTALL_SESSIONS","READ_INPUT_STATE","READ_HISTORY_BOOKMARKS","READ_GSERVICES","READ_GMAIL","READ_FRAME_BUFFER","READ_EXTERNAL_STORAGE","READ_DB","READ_CONTENT_PROVIDER","READ_CONTACTS","READ_CLIPS","READ_CELL_BROADCASTS","READ_CALL_LOG","READ_CALENDAR","READ_ATTACHMENT","READ_APP_WIDGET_DATA","READ_APP_BADGE","READ_APN_SETTINGS","RAISED_THREAD_PRIORITY","QUICKBOOT_POWERON","PROVIDER_INSERT_BADGE","PROCESS_OUTGOING_CALLS","PROCESS_INCOMING_CALLS","PLUGIN","PERSISTENT_ACTIVITY","PERMISSION_NAME","PAYMENT","PACKAGE_USAGE_STATS","MOVE_PACKAGE","MOUNT_UNMOUNT_FILESYSTEMS","MOUNT_FORMAT_FILESYSTEMS","MODIFY_PHONE_STATE","MODIFY_NETWORK_ACCOUNTING","MODIFY_AUDIO_SETTINGS","MIPUSH_RECEIVE","MESSAGE","MEDIA_CONTENT_CONTROL","MASTER_CLEAR","MAPS_RECEIVE","MANAGE_USERS","MANAGE_USB","MANAGE_NETWORK_POLICY","MANAGE_FINGERPRINT","MANAGE_DOCUMENTS","MANAGE_DEVICE_ADMINS","MANAGE_APP_TOKENS","MANAGE_ACCOUNTS","LOCATION","LAUNCH_PERSONAL_PAGE_SERVICE","LAUNCH_APP","LAUNCH","KILL_BACKGROUND_PROCESSES","JPUSH_MESSAGE","JOLOPAY","INTERNET","INTERNAL_SYSTEM_WINDOW","INTERACT_ACROSS_USERS_FULL","INTERACT_ACROSS_USERS","INSTALL_SHORTCUT","INSTALL_PACKAGES","INSTALL_LOCATION_PROVIDER","INSTALL_DRM","INJECT_EVENTS","HARDWARE_TEST","GOOGLE_AUTH","GLOBAL_SEARCH_CONTROL","GLOBAL_SEARCH","GET_TOP_ACTIVITY_INFO","GET_TASKS","GET_QRCODE_INFO","GET_PACKAGE_SIZE","GET_INTENT_SENDER_INTENT","GET_DETAILED_TASKS","GET_CLIPS","GET_ACCOUNTS","FULL_SCREEN","FORE_SERVICE","FORCE_STOP_PACKAGES","FORCE_BACK","FLASHLIGHT","FLAG_ACTIVITY_NEW_TASK","FACTORY_TEST","EXPAND_STATUS_BAR","DUMP","DOWNLOAD_WITHOUT_NOTIFICATION","DOWNLOAD_CACHE_NON_PURGEABLE","DISABLE_KEYGUARD","DIAGNOSTIC","DEVICE_STATE","DEVICE_POWER","DELETE_PACKAGES","DELETE_MESSAGES","DELETE_CACHE_FILES","CREATE_SHORTCUT","CONTROL_LOCATION_UPDATES","CONNECTIVITY_INTERNAL","CLOUD_SERVICE","CLOUD_MANAGER","CLEAR_APP_USER_DATA","CLEAR_APP_CACHE","CHANGE_WIMAX_STATE","CHANGE_WIFI_STATE","CHANGE_WIFI_MULTICAST_STATE","CHANGE_NETWORK_STATE","CHANGE_CONFIGURATION","CHANGE_COMPONENT_ENABLED_STATE","CHANGE_BADGE","CARDNIU_SDK_SERVICE","CAPTURE_AUDIO_OUTPUT","CAMERA","CALL_PRIVILEGED","CALL_PHONE","CACHE_WRITE_PERMISSION","CACHE_READ_PERMISSION","BROADCAST_WAP_PUSH","BROADCAST_STICKY","BROADCAST_SMS","BROADCAST_PACKAGE_REPLACED","BROADCAST_PACKAGE_REMOVED","BROADCAST_PACKAGE_INSTALL","BROADCAST_PACKAGE_CHANGED","BROADCAST_PACKAGE_ADDED","BROADCAST_BADGE","BRICK","BODY_SENSORS","BLUETOOTH_ADMIN","BLUETOOTH","BIND_WALLPAPER","BIND_VPN_SERVICE","BIND_SERVICE_ADMIN","BIND_REMOTEVIEWS","BIND_QUICK_SETTINGS_TILE","BIND_NOTIFICATION_LISTENER_SERVICE","BIND_JOB_SERVICE","BIND_INPUT_METHOD","BIND_DIRECTORY_SEARCH","BIND_DEVICE_ADMIN","BIND_APPWIDGET","BIND_ACCESSIBILITY_SERVICE","BATTERY_STATS","AUTHENTICATE_ACCOUNTS","ANSWER_PHONE","ADD_VOICEMAIL","ADD_SYSTEM_SERVICE","ACTIVITY_RECOGNITION","ACCOUNT_MANAGER","ACCES_MOCK_LOCATION","ACCESS_WIMAX_STATE","ACCESS_WIFI_STATE","ACCESS_WEATHERCLOCK_PROVIDER","ACCESS_WALLET_SERVICE","ACCESS_WAKE_LOCK","ACCESS_SURFACE_FLINGER","ACCESS_SUPERUSER","ACCESS_SERVICE","ACCESS_PROVIDER","ACCESS_NOTIFICATION_POLICY","ACCESS_NETWORK_STATE","ACCESS_MTK_MMHW","ACCESS_MOCK_LOCATION","ACCESS_LOCATION","ACCESS_LAUNCHER_DATA","ACCESS_GPS","ACCESS_FIND_LOCATION","ACCESS_DRM","ACCESS_DOWNLOAD_MANAGER","ACCESS_COARSE","ACCESS_CHECKIN_PROPERTIES","ACCESS_CELL_ID","ACCESS_CACHE_FILESYSTEM","ACCESS_BROWSER","ACCESS_BLUETOOTH_SHARE","ACCESS_ASSISTED_GPS","ACCESS_ALL_DOWNLOADS","Label"]
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
        expected_header = ZEROONE_HEADER if kind == "zeroone" else MNF_HEADER
        if header != expected_header:
            mismatches = [
                f"column {index + 1}: expected {expected!r}, found {actual!r}"
                for index, (expected, actual) in enumerate(zip(expected_header, header))
                if expected != actual
            ]
            if len(header) != len(expected_header):
                mismatches.append(
                    f"expected {len(expected_header)} columns, found {len(header)}"
                )
            raise ValueError(
                f"{path.name}: header does not match the frozen AndroMD V1 schema: "
                + "; ".join(mismatches[:8])
            )

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
    if dict(counts) != EXPECTED_LABEL_COUNTS:
        raise ValueError(
            f"{path.name}: class counts differ from the published AndroMD V1 record; "
            f"expected {EXPECTED_LABEL_COUNTS}, found {dict(counts)}"
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
    expected_origin = re.compile(
        r"(?:github\\.com[:/])" + re.escape(REPOSITORY_FRAGMENT) + r"(?:\\.git)?$",
        re.IGNORECASE,
    )
    if not expected_origin.search(origin):
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

        # Each source is copied into the worktree and stored again in .git/lfs.
        # Reserve additional space for the temporary SQLite duplicate index.
        payload_bytes = sum(report["bytes"] for report in reports)
        required_free = (2 * payload_bytes) + (256 * 1024 * 1024)
        free_bytes = shutil.disk_usage(root).free
        if free_bytes < required_free:
            raise RuntimeError(
                f"Insufficient free disk space: need about {required_free:,} bytes, "
                f"have {free_bytes:,}. Free phone storage or import one dataset at a time."
            )

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
