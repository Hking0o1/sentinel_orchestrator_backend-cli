import argparse
import requests
import json
import sys
import os
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# -----------------------------
# Engine imports (NEW)
# -----------------------------
from engine.services.scan_submitter import ScanSubmitter, ScanSubmissionError
from engine.scheduler.runtime import init_scheduler, get_scheduler
from config.settings import settings

# -----------------------------
# Configuration
# -----------------------------
BACKEND_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:80")
console = Console()

# -----------------------------
# ASCII Art Poster (UNCHANGED)
# -----------------------------
def print_header():
    title = r"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ╚═╝
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝
           ... DevSecOps Orchestration Engine ...
    """
    console.print(Panel.fit(Text(title, style="bold cyan"), border_style="blue"))

# -----------------------------
# Helpers
# -----------------------------
def print_error(message, details=None):
    console.print(f"[bold red]❌ Error:[/bold red] {message}")
    if details:
        console.print(Panel(str(details), title="Details", border_style="red"))

def print_success(message):
    console.print(f"[bold green]✅ Success:[/bold green] {message}")

def get_auth_token(username, password):
    token_url = f"{BACKEND_API_URL}/api/v1/auth/token"
    data = {"username": username, "password": password}
    try:
        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception:
        return None

# -----------------------------
# Scheduler bootstrap
# -----------------------------
def ensure_scheduler_initialized():
    try:
        return get_scheduler()
    except RuntimeError:
        return init_scheduler(
            max_tokens=settings.SCHEDULER_MAX_TOKENS,
            max_concurrent_tasks=settings.SCHEDULER_MAX_CONCURRENT_TASKS,
        )

# -----------------------------
# Scan submission
# -----------------------------
def handle_start_scan(token, args):
    """
    Phase 1.5–correct scan submission.
    """

    # ---- HARD VALIDATION (THIS WAS MISSING) ----
    if args.profile.lower() == "web":
        if not args.url:
            raise SystemExit("❌ WEB scan requires --url")
    else:
        if not args.src:
            raise SystemExit("❌ Non-WEB scan requires --src")

    # ---- Canonical scan request ----
    scan_request = {
        "profile": args.profile.upper(),
        "enable_ai": False,
    }

    if args.profile.lower() == "web":
        scan_request["target_url"] = args.url
    else:
        scan_request["source_code_path"] = args.src

    console.print("[dim]Scan request payload:[/dim]")
    console.print(json.dumps(scan_request, indent=2))

    # ---- Local engine path ----
    try:
        scheduler = ensure_scheduler_initialized()
        submitter = ScanSubmitter(scheduler)

        with console.status("[bold yellow]Submitting scan to local engine...", spinner="earth"):
            scan_id = submitter.submit_scan(scan_request)

        print_success("Scan accepted by local engine!")

        table = Table(title="Scan Details", show_header=True, header_style="bold magenta")
        table.add_column("Field", style="dim")
        table.add_column("Value", style="bold white")
        table.add_row("Scan ID", scan_id)
        table.add_row("Profile", scan_request["profile"])
        table.add_row(
            "Target",
            scan_request.get("target_url") or scan_request.get("source_code_path"),
        )
        console.print(table)
        return

    except ScanSubmissionError:
        console.print("[dim]Local engine unavailable, falling back to API...[/dim]")

    # ---- API fallback ----
    scan_url = f"{BACKEND_API_URL}/api/v1/scans/start"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "profile": args.profile.lower(),
    }

    if args.url:
        payload["target_url"] = args.url

    if args.src:
        payload["source_code_path"] = args.src

    if args.cookie:
        payload["auth_cookie"] = args.cookie

    console.print("[dim]API payload:[/dim]")
    console.print(json.dumps(payload, indent=2))

    with console.status("[bold yellow]Launching scan via API...", spinner="earth"):
        response = requests.post(
            scan_url,
            headers=headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()

        print_success("Scan job accepted via API!")

        table = Table(title="Scan Details", show_header=True, header_style="bold magenta")
        table.add_column("Field", style="dim")
        table.add_column("Value", style="bold white")
        table.add_row("Job ID", data.get("job_id"))
        table.add_row("Profile", data.get("profile"))
        table.add_row("Target", data.get("target_url") or "Local Source")

        console.print(table)

# -----------------------------
# CLI Entry
# -----------------------------
def main():
    print_header()

    parser = argparse.ArgumentParser(description="Project Sentinel CLI")

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", default=os.environ.get("SENTINEL_USER"))
    auth_group.add_argument("-p", "--password", default=os.environ.get("SENTINEL_PASSWORD"))

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("start-scan", help="Start a scan")
    scan_parser.add_argument("--profile", required=True, choices=["web", "developer", "full"])
    scan_parser.add_argument("--url", help="Target URL (WEB scans)")
    scan_parser.add_argument("--src", help="Source path (CODE/IAC scans)")
    scan_parser.add_argument("--cookie", help="Auth cookie")
    scan_parser.set_defaults(func=handle_start_scan)

    args = parser.parse_args()

    token = get_auth_token(args.username, args.password)
    if not token:
        console.print("[dim]Auth token not available (local engine mode assumed)[/dim]")

    args.func(token, args)

if __name__ == "__main__":
    main()
