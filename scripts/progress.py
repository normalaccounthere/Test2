#!/usr/bin/env python3
"""Utilities for managing progress.json in the recon pipeline."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STAGE_ORDER = [
    "subdomain_enumeration",
    "dns_resolution",
    "port_scanning",
    "http_probing",
    "historical_url_gathering",
    "live_crawling",
    "url_normalization",
    "javascript_analysis",
    "secret_discovery",
    "cloud_exposure_detection",
    "subdomain_takeover_detection",
    "cors_misconfiguration_detection",
    "ssrf_endpoint_discovery",
    "open_redirect_discovery",
    "sensitive_and_default_credential_detection",
    "nuclei_batch_scanning",
]

COMPLETE_STAGE = "complete"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_valid_stage_name(stage: str, allow_empty: bool = False) -> bool:
    if allow_empty and stage == "":
        return True
    return stage == COMPLETE_STAGE or stage in STAGE_ORDER


def _validate_stage_name(stage: str, field_name: str, allow_empty: bool = False) -> None:
    if not isinstance(stage, str):
        raise ValueError(f"{field_name} must be a string, got {type(stage).__name__}")
    if not _is_valid_stage_name(stage, allow_empty=allow_empty):
        allowed = ", ".join(STAGE_ORDER + [COMPLETE_STAGE])
        if allow_empty:
            allowed = f"<empty>, {allowed}"
        raise ValueError(f"invalid {field_name}: '{stage}'. Allowed values: {allowed}")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalized)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _stage_rank(stage: str) -> int:
    if stage == "":
        return -1
    if stage == COMPLETE_STAGE:
        return len(STAGE_ORDER)
    if stage in STAGE_ORDER:
        return STAGE_ORDER.index(stage)
    return -1


def _coerce_optional_int(raw: Any, field_name: str) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        value = raw.strip()
        if value == "":
            return None
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer, got '{raw}'") from exc
    raise ValueError(f"{field_name} must be an integer, got {type(raw).__name__}")


def normalize_progress(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("progress payload must be a JSON object")

    target_domain_raw = payload.get("target_domain", "")
    target_domain = target_domain_raw if isinstance(target_domain_raw, str) else str(target_domain_raw)

    last_completed_stage_raw = payload.get("last_completed_stage", "")
    last_completed_stage = str(last_completed_stage_raw)
    _validate_stage_name(last_completed_stage, "last_completed_stage", allow_empty=True)

    next_stage_raw = payload.get("next_stage", STAGE_ORDER[0])
    next_stage = str(next_stage_raw)
    _validate_stage_name(next_stage, "next_stage")

    current_batch = _coerce_optional_int(payload.get("current_batch", 1), "current_batch")
    if current_batch is None:
        current_batch = 1

    run_id_raw = payload.get("run_id", None)
    run_id = None if run_id_raw is None else str(run_id_raw)

    total_batches = _coerce_optional_int(payload.get("total_batches", None), "total_batches")
    if total_batches is not None and total_batches < 0:
        raise ValueError("total_batches must be >= 0")

    last_processed_file_raw = payload.get("last_processed_file", None)
    last_processed_file = None if last_processed_file_raw in (None, "") else str(last_processed_file_raw)

    timestamp_raw = payload.get("timestamp", "")
    timestamp = timestamp_raw if isinstance(timestamp_raw, str) and timestamp_raw else now_iso()

    normalized: dict[str, Any] = {
        "target_domain": target_domain,
        "last_completed_stage": last_completed_stage,
        "next_stage": next_stage,
        "current_batch": current_batch,
        "timestamp": timestamp,
        "run_id": run_id,
        "total_batches": total_batches,
        "last_processed_file": last_processed_file,
    }
    return normalized


def load_progress(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"progress file not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid progress file '{path}': JSON is corrupted ({exc.msg})") from exc
    return normalize_progress(payload)


def write_progress(path: Path, payload: dict[str, Any]) -> None:
    normalized = normalize_progress(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_file: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as handle:
            temp_file = handle.name
            handle.write(json.dumps(normalized, indent=2, sort_keys=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        Path(temp_file).replace(path)
    finally:
        if temp_file is not None:
            tmp_path = Path(temp_file)
            if tmp_path.exists():
                tmp_path.unlink()


def build_progress(
    target_domain: str,
    last_completed_stage: str,
    next_stage: str,
    current_batch: int,
    run_id: str | None = None,
    total_batches: int | None = None,
    last_processed_file: str | None = None,
) -> dict[str, Any]:
    progress = {
        "target_domain": target_domain,
        "last_completed_stage": last_completed_stage,
        "next_stage": next_stage,
        "current_batch": current_batch,
        "timestamp": now_iso(),
        "run_id": run_id,
        "total_batches": total_batches,
        "last_processed_file": last_processed_file,
    }
    return normalize_progress(progress)


def stage_after(stage: str) -> str:
    if stage not in STAGE_ORDER:
        return COMPLETE_STAGE
    index = STAGE_ORDER.index(stage) + 1
    return STAGE_ORDER[index] if index < len(STAGE_ORDER) else COMPLETE_STAGE


def cmd_init(args: argparse.Namespace) -> int:
    _validate_stage_name(args.last_completed_stage, "last_completed_stage", allow_empty=True)
    _validate_stage_name(args.next_stage, "next_stage")
    if args.total_batches is not None and args.total_batches < 0:
        raise ValueError("total_batches must be >= 0")

    progress = build_progress(
        target_domain=args.target_domain,
        last_completed_stage=args.last_completed_stage,
        next_stage=args.next_stage,
        current_batch=args.current_batch,
        run_id=args.run_id,
        total_batches=args.total_batches,
        last_processed_file=args.last_processed_file,
    )
    write_progress(Path(args.output), progress)
    print(json.dumps(progress, indent=2))
    return 0


def cmd_advance(args: argparse.Namespace) -> int:
    _validate_stage_name(args.last_completed_stage, "last_completed_stage", allow_empty=True)
    _validate_stage_name(args.next_stage, "next_stage")
    if args.total_batches is not None and args.total_batches < 0:
        raise ValueError("total_batches must be >= 0")

    progress_path = Path(args.progress)
    progress = load_progress(progress_path)
    progress["last_completed_stage"] = args.last_completed_stage
    progress["next_stage"] = args.next_stage
    progress["current_batch"] = args.current_batch
    if args.run_id is not None:
        progress["run_id"] = args.run_id
    if args.total_batches is not None:
        progress["total_batches"] = args.total_batches
    if args.last_processed_file is not None:
        progress["last_processed_file"] = args.last_processed_file
    progress["timestamp"] = now_iso()
    write_progress(progress_path, progress)
    print(json.dumps(progress, indent=2))
    return 0


def cmd_next(args: argparse.Namespace) -> int:
    progress = load_progress(Path(args.progress))
    next_stage = progress.get("next_stage", STAGE_ORDER[0])
    _validate_stage_name(next_stage, "next_stage")
    print(next_stage)
    return 0


def cmd_merge_latest(args: argparse.Namespace) -> int:
    root = Path(args.artifacts_dir)
    candidates = sorted(root.rglob("progress.json"))
    if not candidates:
        raise FileNotFoundError(f"no progress.json files found under {root}")

    def sort_key(path: Path) -> tuple[datetime, int, int, int]:
        payload = load_progress(path)
        timestamp = _parse_timestamp(payload.get("timestamp"))
        last_stage_rank = _stage_rank(payload.get("last_completed_stage", ""))
        next_stage_rank = _stage_rank(payload.get("next_stage", STAGE_ORDER[0]))
        current_batch = payload.get("current_batch", 1)
        return (timestamp, last_stage_rank, next_stage_rank, current_batch)

    latest = max(candidates, key=sort_key)
    payload = load_progress(latest)
    write_progress(Path(args.output), payload)
    print(json.dumps(payload, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    init_parser = subcommands.add_parser("init", help="Create a new progress.json file")
    init_parser.add_argument("--target-domain", required=True)
    init_parser.add_argument("--last-completed-stage", default="")
    init_parser.add_argument("--next-stage", default=STAGE_ORDER[0])
    init_parser.add_argument("--current-batch", type=int, default=1)
    init_parser.add_argument("--run-id")
    init_parser.add_argument("--total-batches", type=int)
    init_parser.add_argument("--last-processed-file")
    init_parser.add_argument("--output", default="progress.json")
    init_parser.set_defaults(func=cmd_init)

    advance_parser = subcommands.add_parser("advance", help="Advance an existing progress.json file")
    advance_parser.add_argument("--progress", default="progress.json")
    advance_parser.add_argument("--last-completed-stage", required=True)
    advance_parser.add_argument("--next-stage", required=True)
    advance_parser.add_argument("--current-batch", type=int, default=1)
    advance_parser.add_argument("--run-id")
    advance_parser.add_argument("--total-batches", type=int)
    advance_parser.add_argument("--last-processed-file")
    advance_parser.set_defaults(func=cmd_advance)

    next_parser = subcommands.add_parser("next", help="Print the next stage")
    next_parser.add_argument("--progress", default="progress.json")
    next_parser.set_defaults(func=cmd_next)

    merge_parser = subcommands.add_parser("merge-latest", help="Find the latest checkpoint from downloaded artifacts")
    merge_parser.add_argument("--artifacts-dir", required=True)
    merge_parser.add_argument("--output", default="progress.json")
    merge_parser.set_defaults(func=cmd_merge_latest)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
