#!/usr/bin/env python3
"""Record a malware-scan disposition as structured evidence, bound to an artifact's SHA-256.

R0 wants Windows npm `.node` and CLI `.exe` scans to become evidence records
bound to artifact SHA-256, scanner/signature versions, result, reviewer, and
timestamp — not the free-form issue-comment prose docs/RELEASING.md's
"Checksum-identified Windows scan" section describes today. This is the
operator-run tool that produces that record: run it, by hand, on the
disposable VM after scanning, against the same release-scan-manifest.json
(scripts/write-release-scan-manifest.py) that manifest digest was verified
against. It appends to that manifest's `scan_evidence` array in place, so the
evidence stays bound to the exact manifest it was verified from — it does not
go argument-by-argument onto a fresh document, `--in-place` is the only mode.

Prints the recorded entry as JSON to stdout too, so it can be pasted directly
into the tracking issue (e.g. #191) alongside the manifest evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VALID_RESULTS = {"clean", "detected"}


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def find_artifact(manifest: dict[str, Any], artifact_path: str) -> dict[str, Any]:
    for record in manifest.get("artifacts", []):
        if record["path"] == artifact_path:
            return record
    available = ", ".join(record["path"] for record in manifest.get("artifacts", []))
    raise SystemExit(f"error: {artifact_path!r} is not an artifact in this manifest. Available: {available}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="release-scan-manifest.json to update")
    parser.add_argument("--artifact", required=True, help="artifact path exactly as recorded in the manifest")
    parser.add_argument("--scanner-product", required=True, help='e.g. "ESET Endpoint Antivirus"')
    parser.add_argument("--scanner-engine-version", required=True)
    parser.add_argument("--scanner-signature-version", required=True)
    parser.add_argument("--result", required=True, choices=sorted(VALID_RESULTS))
    parser.add_argument(
        "--detection-name",
        help="required when --result=detected; the exact detection name reported",
    )
    parser.add_argument("--reviewer", required=True, help="who ran and is vouching for this scan")
    parser.add_argument(
        "--timestamp",
        help="ISO-8601 timestamp (default: now, UTC)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.result == "detected" and not args.detection_name:
        print("error: --detection-name is required when --result=detected", file=sys.stderr)
        return 1
    if args.result == "clean" and args.detection_name:
        print("error: --detection-name must not be set when --result=clean", file=sys.stderr)
        return 1

    timestamp = args.timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+\d{2}:\d{2}|Z)", timestamp):
        print(f"error: --timestamp {timestamp!r} is not ISO-8601 (e.g. 2026-08-16T12:00:00Z)", file=sys.stderr)
        return 1

    manifest = load_manifest(args.manifest)
    artifact = find_artifact(manifest, args.artifact)

    entry = {
        "artifact_path": artifact["path"],
        "artifact_sha256": artifact["sha256"],
        "scanner_product": args.scanner_product,
        "scanner_engine_version": args.scanner_engine_version,
        "scanner_signature_version": args.scanner_signature_version,
        "result": args.result,
        "detection_name": args.detection_name,
        "reviewer": args.reviewer,
        "timestamp": timestamp,
    }

    manifest.setdefault("scan_evidence", []).append(entry)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"Recorded scan evidence in {args.manifest}:")
    print(json.dumps(entry, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
