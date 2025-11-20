import argparse
import requests
import json
import sys
import os
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.json import JSON
from rich.prompt import Prompt

# --- Configuration ---
BACKEND_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:80")

# Initialize Rich Console
console = Console()

# --- Helper Functions ---

def print_header():
    """Prints a beautiful ASCII header."""
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

def print_error(message, details=None):
    """Prints a styled error message."""
    console.print(f"[bold red]❌ Error:[/bold red] {message}")
    if details:
        console.print(Panel(details, title="Details", border_style="red"))

def print_success(message):
    """Prints a styled success message."""
    console.print(f"[bold green]✅ Success:[/bold green] {message}")

def get_auth_token(username, password):
    """
    Authenticates against the backend API with a loading spinner.
    """
    token_url = f"{BACKEND_API_URL}/api/v1/auth/token"
    data = {"username": username, "password": password}
    
    with console.status("[bold green]Authenticating...", spinner="dots"):
        try:
            response = requests.post(token_url, data=data, timeout=10)
            response.raise_for_status()
            return response.json()["access_token"]
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                print_error("Authentication failed", "Incorrect username or password.")
            else:
                print_error("Server Error", f"{e.response.status_code} {e.response.text}")
        except requests.exceptions.RequestException as e:
            print_error("Connection Error", f"Failed to connect to {token_url}.\nIs the backend running?")
    return None

def handle_start_scan(token, args):
    """
    Starts a scan and displays a rich table of the job details.
    """
    scan_url = f"{BACKEND_API_URL}/api/v1/scans/start"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "profile": args.profile,
        "target_url": args.url,
        "source_code_path": args.src
    }
    
    # Validate arguments based on profile (client-side)
    if args.profile in ['developer', 'full'] and not args.src:
        print_error("Missing Argument", f"--src is required for the '{args.profile}' profile.")
        sys.exit(1)
    if args.profile in ['web', 'full'] and not args.url:
        print_error("Missing Argument", f"--url is required for the '{args.profile}' profile.")
        sys.exit(1)

    with console.status(f"[bold yellow]Requesting '{args.profile}' scan...", spinner="earth"):
        try:
            response = requests.post(scan_url, headers=headers, data=json.dumps(payload), timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Display success
            print_success("Scan job accepted by backend!")
            
            # Create a summary table
            table = Table(title="Scan Job Details", show_header=True, header_style="bold magenta")
            table.add_column("Field", style="dim")
            table.add_column("Value", style="bold white")
            
            table.add_row("Job ID", data.get("job_id"))
            table.add_row("Profile", data.get("profile"))
            table.add_row("Target", data.get("target_url") or "Local Source")
            table.add_row("Status", data.get("status"))
            
            console.print(table)
            console.print(f"\n[dim]View results at: http://localhost:4000/scans/{data.get('job_id')}[/dim]")

        except requests.exceptions.HTTPError as e:
            print_error("Failed to start scan", e.response.text)
        except requests.exceptions.RequestException:
            print_error("Network Error", "Failed to reach backend.")

def handle_get_status(token, args):
    """
    Retrieves scan status.
    """
    # Placeholder logic for now
    console.print(Panel(f"Checking status for Job ID: [bold]{args.job_id}[/bold]", title="Status Check", border_style="yellow"))
    console.print("[italic]This feature requires the backend /status endpoint implementation.[/italic]")


def main():
    print_header()

    parser = argparse.ArgumentParser(description="Project Sentinel CLI")
    
    # Auth args
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", default=os.environ.get("SENTINEL_USER", "admin@example.com"))
    auth_group.add_argument("-p", "--password", default=os.environ.get("SENTINEL_PASSWORD", "SuperSecurePassword123"))
    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Start Scan Command
    scan_parser = subparsers.add_parser("start-scan", help="Initiate a new security scan.")
    scan_parser.add_argument("--profile", required=True, choices=['developer', 'web', 'full'], help="Scan profile")
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--src", help="Source code path")
    scan_parser.set_defaults(func=handle_start_scan)

    # Status Command
    status_parser = subparsers.add_parser("get-status", help="Get scan status.")
    status_parser.add_argument("job_id", help="Job ID")
    status_parser.set_defaults(func=handle_get_status)

    args = parser.parse_args()

    # Authenticate
    token = get_auth_token(args.username, args.password)
    if not token:
        sys.exit(1)
    
    # Run Command
    args.func(token, args)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Aborted by user.[/bold red]")