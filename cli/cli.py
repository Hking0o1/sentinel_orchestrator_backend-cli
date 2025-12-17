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
from rich.live import Live
from rich.spinner import Spinner

# --- Configuration ---
BACKEND_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:80")
console = Console()

# --- ASCII Art Poster ---
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

# --- Helper Functions ---

def print_error(message, details=None):
    console.print(f"[bold red]❌ Error:[/bold red] {message}")
    if details:
        console.print(Panel(str(details), title="Details", border_style="red"))

def print_success(message):
    console.print(f"[bold green]✅ Success:[/bold green] {message}")

def get_auth_token(username, password):
    """
    Authenticates against the backend API and returns a JWT token.
    """
    token_url = f"{BACKEND_API_URL}/api/v1/auth/token"
    data = {"username": username, "password": password}
    try:
        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print_err("Authentication failed: Incorrect username or password.")
        else:
            print_err(f"Authentication error: {e.response.status_code} {e.response.text}")
    except requests.exceptions.RequestException as e:
        print_err(f"Failed to connect to backend at {token_url}. Is it running?")
    return None

def handle_start_scan(token, args):
    scan_url = f"{BACKEND_API_URL}/api/v1/scans/start"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {
        "profile": args.profile,
        "target_url": args.url,
        "source_code_path": args.src,
        "auth_cookie": args.cookie
    }
    
    with console.status(f"[bold yellow]Launching '{args.profile}' scan...", spinner="earth"):
        try:
            response = requests.post(scan_url, headers=headers, data=json.dumps(payload), timeout=30)
            response.raise_for_status()
            data = response.json()
            
            print_success("Scan job accepted!")
            
            table = Table(title="Scan Details", show_header=True, header_style="bold magenta")
            table.add_column("Field", style="dim")
            table.add_column("Value", style="bold white")
            table.add_row("Job ID", data.get("job_id"))
            table.add_row("Profile", data.get("profile"))
            table.add_row("Target", data.get("target_url") or "Local Source")
            
            console.print(table)
            console.print(f"\n[dim]View results: http://localhost:4000/app/scans/{data.get('job_id')}[/dim]")
            
        except Exception as e:
            print_error("Failed to start scan", str(e))
        
def handle_get_status(token, args):
    """
    (Placeholder) Sends a request to get the status of a scan.
    """
    print(f"\n--- (Placeholder) ---")
    print(f"Retrieving status for Job ID: {args.job_id}...")
    print(f"This would call a (future) '/api/v1/scans/status/{args.job_id}' endpoint.")
    print(f"Authorization Header: Bearer {token[:10]}...")


def main():
    print_header()
    parser = argparse.ArgumentParser(description="Project Sentinel CLI")
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-u", "--username", default=os.environ.get("SENTINEL_USER", "admin@example.com"))
    auth_group.add_argument("-p", "--password", default=os.environ.get("SENTINEL_PASSWORD", "SuperSecurePassword123"))
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("start-scan", help="Start a scan")
    scan_parser.add_argument("--profile", required=True, choices=['developer', 'web', 'full'])
    scan_parser.add_argument("--url", help="Target URL")
    scan_parser.add_argument("--src", help="Source path")
    scan_parser.add_argument("--cookie", help="Auth cookie")
    scan_parser.set_defaults(func=handle_start_scan)

    args = parser.parse_args()
    token = get_auth_token(args.username, args.password)
    if token:
        args.func(token, args)

if __name__ == "__main__":
    main()