import argparse
import json
import os
import sys
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def _bootstrap_project_path() -> None:
    """
    Ensure repository root is importable when running:
    `python cli/cli.py ...` or `python -m cli.cli ...`
    """
    repo_root = Path(__file__).resolve().parent.parent
    root_str = str(repo_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


_bootstrap_project_path()


BACKEND_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:80")
console = Console()


def print_header() -> None:
    try:
        console.print(Panel.fit("Sentinel CLI", border_style="blue"))
    except UnicodeEncodeError:
        print("Sentinel CLI")


def print_success(message: str) -> None:
    console.print(f"[bold green]Success:[/bold green] {message}")


def scan_command_help() -> str:
    return (
        "Profiles and required flags:\n"
        "  web       -> requires --url\n"
        "  developer -> requires --src\n"
        "  full      -> requires both --url and --src\n\n"
        "AI flags:\n"
        "  --enable-ai   (default)\n"
        "  --disable-ai\n\n"
        "Examples:\n"
        "  python -m cli.cli start-scan --profile web --url https://example.com --enable-ai\n"
        "  python -m cli.cli start-scan --profile developer --src ./myrepo --disable-ai\n"
        "  python -m cli.cli start-scan --profile full --url https://example.com --src ./myrepo"
    )


def get_auth_token(username: str | None, password: str | None) -> str | None:
    token_url = f"{BACKEND_API_URL}/api/v1/auth/token"
    data = {"username": username, "password": password}
    try:
        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception:
        return None


def ensure_scheduler_initialized():
    from engine.scheduler.runtime import get_scheduler, init_scheduler
    from config.settings import settings

    try:
        return get_scheduler()
    except RuntimeError:
        return init_scheduler(
            max_tokens=settings.SCHEDULER_MAX_TOKENS,
            max_concurrent_tasks=settings.SCHEDULER_MAX_CONCURRENT_TASKS,
        )


def _validate_scan_args(args) -> None:
    profile = args.profile.lower()
    if profile == "web":
        if not args.url:
            raise SystemExit("WEB scan requires --url")
        return
    if profile == "developer":
        if not args.src:
            raise SystemExit("DEVELOPER scan requires --src")
        return
    if profile == "full":
        if not args.url or not args.src:
            raise SystemExit("FULL scan requires both --url and --src")
        return
    raise SystemExit(f"Unsupported profile: {args.profile}")


def handle_start_scan(token: str | None, args) -> None:
    _validate_scan_args(args)

    scan_request = {
        "profile": args.profile.upper(),
        "enable_ai": args.enable_ai,
    }
    if args.url:
        scan_request["target_url"] = args.url
    if args.src:
        scan_request["source_code_path"] = args.src

    console.print("[dim]Scan request payload:[/dim]")
    console.print(json.dumps(scan_request, indent=2))

    # Local mode only when auth token is not available
    if not token:
        try:
            from engine.services.scan_submitter import ScanSubmissionError, ScanSubmitter

            scheduler = ensure_scheduler_initialized()
            submitter = ScanSubmitter(scheduler)

            with console.status("[bold yellow]Submitting scan to local engine...", spinner="earth"):
                submitter.submit_scan(scan_request)

            print_success("Scan accepted by local engine!")
            return
        except Exception as exc:
            console.print(f"[dim]Local engine unavailable ({exc}), falling back to API...[/dim]")

    scan_url = f"{BACKEND_API_URL}/api/v1/scans/start"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "profile": args.profile.lower(),
        "enable_ai": args.enable_ai,
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
        response = requests.post(scan_url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()

    print_success("Scan job accepted via API!")
    table = Table(title="Scan Details", show_header=True, header_style="bold magenta")
    table.add_column("Field", style="dim")
    table.add_column("Value", style="bold white")
    table.add_row("Scan ID", data.get("scan_id", ""))
    table.add_row("Profile", str(data.get("profile", "")))
    table.add_row("Target", payload.get("target_url") or payload.get("source_code_path") or "")
    console.print(table)


def main() -> None:
    print_header()

    parser = argparse.ArgumentParser(
        description="Project Sentinel CLI",
        epilog="Use `python -m cli.cli start-scan -h` for profile flags and examples.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", default=os.environ.get("SENTINEL_USER"))
    auth_group.add_argument("-p", "--password", default=os.environ.get("SENTINEL_PASSWORD"))

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "start-scan",
        help="Start a scan",
        description="Start a scan with explicit profile/target requirements.",
        epilog=scan_command_help(),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    scan_parser.add_argument(
        "--profile",
        required=True,
        choices=["web", "developer", "full"],
        help="Scan mode: web|developer|full.",
    )
    scan_parser.add_argument("--url", help="Target URL (required for web/full)")
    scan_parser.add_argument("--src", help="Source path (required for developer/full)")
    scan_parser.add_argument("--cookie", help="Auth cookie")
    scan_parser.add_argument(
        "--enable-ai",
        dest="enable_ai",
        action="store_true",
        default=True,
        help="Enable AI post-processing (default: enabled)",
    )
    scan_parser.add_argument(
        "--disable-ai",
        dest="enable_ai",
        action="store_false",
        help="Disable AI post-processing",
    )
    scan_parser.set_defaults(func=handle_start_scan)

    args = parser.parse_args()
    token = get_auth_token(args.username, args.password)
    if not token:
        console.print("[dim]Auth token not available (local engine mode assumed)[/dim]")

    args.func(token, args)


if __name__ == "__main__":
    main()
