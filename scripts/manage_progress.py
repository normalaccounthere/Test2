import json
import os
import sys
from datetime import datetime, timezone

PROGRESS_FILE = "progress.json"


def init_progress(target_domain: str):
    progress = {
        "target_domain": target_domain,
        "last_completed_stage": "",
        "next_stage": "subdomain_enumeration",
        "current_batch": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stages": {
            "subdomain_enumeration": {"status": "pending", "output": "subs.txt"},
            "dns_resolution": {"status": "pending", "output": "resolved.txt"},
            "port_scanning": {"status": "pending", "output": "ports.txt"},
            "http_probing": {"status": "pending", "output": "alive.txt"},
            "historical_urls": {"status": "pending", "output": "historical_urls.txt"},
            "live_crawling": {"status": "pending", "output": "crawled_urls.txt"},
            "url_normalization": {"status": "pending", "output": "normalized_urls.txt"},
            "js_analysis": {"status": "pending", "output": "js_files.txt"},
            "secret_discovery": {"status": "pending", "output": "secrets.txt"},
            "cloud_exposure": {"status": "pending", "output": "cloud_exposures.txt"},
            "subdomain_takeover": {"status": "pending", "output": "takeovers.txt"},
            "cors_testing": {"status": "pending", "output": "cors_findings.txt"},
            "ssrf_discovery": {"status": "pending", "output": "ssrf_candidates.txt"},
            "open_redirect": {"status": "pending", "output": "redirect_findings.txt"},
            "sensitive_files": {"status": "pending", "output": "sensitive_files.txt"},
            "default_creds": {"status": "pending", "output": "default_creds.txt"},
            "nuclei_scanning": {"status": "pending", "output": "nuclei_results.txt"},
        },
    }
    write_progress(progress)
    return progress


def write_progress(progress: dict):
    progress["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(PROGRESS_FILE, "w") as f:
        json.dump(progress, f, indent=2)


def read_progress() -> dict:
    if not os.path.exists(PROGRESS_FILE):
        return None
    with open(PROGRESS_FILE, "r") as f:
        return json.load(f)


def mark_complete(progress: dict, stage: str):
    if stage in progress["stages"]:
        progress["stages"][stage]["status"] = "completed"
    progress["last_completed_stage"] = stage
    stages_order = [
        "subdomain_enumeration", "dns_resolution", "port_scanning", "http_probing",
        "historical_urls", "live_crawling", "url_normalization", "js_analysis",
        "secret_discovery", "cloud_exposure", "subdomain_takeover", "cors_testing",
        "ssrf_discovery", "open_redirect", "sensitive_files", "default_creds",
        "nuclei_scanning",
    ]
    found = False
    for s in stages_order:
        if found:
            progress["next_stage"] = s
            break
        if s == stage:
            found = True
    if stage == stages_order[-1]:
        progress["next_stage"] = "complete"
    write_progress(progress)


def set_stage_status(progress: dict, stage: str, status: str):
    if stage in progress["stages"]:
        progress["stages"][stage]["status"] = status
    write_progress(progress)


def set_batch(progress: dict, batch: int):
    progress["current_batch"] = batch
    write_progress(progress)


def should_run_stage(progress: dict, stage: str) -> bool:
    if stage not in progress["stages"]:
        return False
    return progress["stages"][stage]["status"] != "completed"


def get_next_stage(progress: dict) -> str:
    stages_order = [
        "subdomain_enumeration", "dns_resolution", "port_scanning", "http_probing",
        "historical_urls", "live_crawling", "url_normalization", "js_analysis",
        "secret_discovery", "cloud_exposure", "subdomain_takeover", "cors_testing",
        "ssrf_discovery", "open_redirect", "sensitive_files", "default_creds",
        "nuclei_scanning",
    ]
    for s in stages_order:
        if progress["stages"].get(s, {}).get("status") != "completed":
            return s
    return "complete"


def get_summary(progress: dict) -> str:
    total = len(progress["stages"])
    completed = sum(1 for s in progress["stages"].values() if s["status"] == "completed")
    return f"Progress: {completed}/{total} stages complete | Next: {progress['next_stage']} | Batch: {progress['current_batch']}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage_progress.py <command> [args]")
        print("Commands: init <domain>, read, complete <stage>, status <stage> <status>, batch <n>, summary")
        sys.exit(1)

    command = sys.argv[1]

    if command == "init":
        if len(sys.argv) < 3:
            print("Error: init requires a domain argument")
            sys.exit(1)
        progress = init_progress(sys.argv[2])
        print(f"Initialized progress for {sys.argv[2]}")
        print(get_summary(progress))

    elif command == "read":
        progress = read_progress()
        if progress:
            print(json.dumps(progress, indent=2))
        else:
            print("No progress file found")
            sys.exit(1)

    elif command == "complete":
        if len(sys.argv) < 3:
            print("Error: complete requires a stage name")
            sys.exit(1)
        progress = read_progress()
        if not progress:
            print("No progress file found")
            sys.exit(1)
        mark_complete(progress, sys.argv[2])
        print(f"Marked {sys.argv[2]} as complete")
        print(get_summary(progress))

    elif command == "status":
        if len(sys.argv) < 4:
            print("Error: status requires stage and status")
            sys.exit(1)
        progress = read_progress()
        if not progress:
            print("No progress file found")
            sys.exit(1)
        set_stage_status(progress, sys.argv[2], sys.argv[3])
        print(f"Set {sys.argv[2]} status to {sys.argv[3]}")

    elif command == "batch":
        if len(sys.argv) < 3:
            print("Error: batch requires a number")
            sys.exit(1)
        progress = read_progress()
        if not progress:
            print("No progress file found")
            sys.exit(1)
        set_batch(progress, int(sys.argv[2]))
        print(f"Set batch to {sys.argv[2]}")

    elif command == "summary":
        progress = read_progress()
        if not progress:
            print("No progress file found")
            sys.exit(1)
        print(get_summary(progress))
        print(f"Target: {progress['target_domain']}")
        for stage, info in progress["stages"].items():
            print(f"  {stage}: {info['status']}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
