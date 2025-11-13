import argparse
import requests
import json
import sys
import os

# --- Configuration ---
# Load the backend URL from an environment variable, falling back to localhost
BACKEND_API_URL = os.environ.get("SENTINEL_API_URL", "http://localhost:80")

# --- ASCII Art Poster ---
POSTER = r"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ╚═╝
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗██╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝
           ... DevSecOps Orchestration Engine ...
"""

# --- Helper Functions ---

def print_err(message):
    """Prints an error message to stderr."""
    print(f"\n[ERROR] {message}\n", file=sys.stderr)

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
    """
    Sends a request to the backend API to start a new security scan.
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
        print_err(f"--src is required for the '{args.profile}' profile.")
        sys.exit(1)
    if args.profile in ['web', 'full'] and not args.url:
        print_err(f"--url is required for the '{args.profile}' profile.")
        sys.exit(1)

    print(f"\nRequesting '{args.profile}' scan...")
    try:
        response = requests.post(scan_url, headers=headers, data=json.dumps(payload), timeout=30)
        response.raise_for_status()
        print("\n[SUCCESS] Scan job accepted by backend.")
        print(json.dumps(response.json(), indent=2))
    except requests.exceptions.HTTPError as e:
        print_err(f"Failed to start scan: {e.response.status_code} {e.response.text}")
    except requests.exceptions.RequestException:
        print_err(f"Failed to connect to backend at {scan_url}.")
        
def handle_get_status(token, args):
    """
    (Placeholder) Sends a request to get the status of a scan.
    """
    print(f"\n--- (Placeholder) ---")
    print(f"Retrieving status for Job ID: {args.job_id}...")
    print(f"This would call a (future) '/api/v1/scans/status/{args.job_id}' endpoint.")
    print(f"Authorization Header: Bearer {token[:10]}...")


def main():
    """
    Main entry point for the Project Sentinel CLI tool.
    """
    parser = argparse.ArgumentParser(
        description=POSTER,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # --- Global Authentication Arguments ---
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "-u", "--username",
        help="Username for API authentication. (Env: SENTINEL_USER)",
        default=os.environ.get("SENTINEL_USER", "admin@example.com")
    )
    auth_group.add_argument(
        "-p", "--password",
        help="Password for API authentication. (Env: SENTINEL_PASSWORD)",
        default=os.environ.get("SENTINEL_PASSWORD", "SuperSecurePassword123")
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- 'start-scan' command ---
    scan_parser = subparsers.add_parser(
        "start-scan", 
        help="Initiate a new security scan job.",
        description="Starts an asynchronous security scan on the backend. The profile determines which tools run.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    scan_parser.add_argument(
        "--profile",
        required=True,
        choices=['developer', 'web', 'full'],
        help="""
  - developer: Fast code-level scans (SAST, SCA). Requires --src.
  - web:       Dynamic scans of a live web app (DAST, Resilience). Requires --url.
  - full:      The most comprehensive scan. Requires --url and --src.
"""
    )
    scan_parser.add_argument(
        "--url", 
        help="Target URL for 'web' and 'full' profiles (e.g., https://staging.my-app.com)."
    )
    scan_parser.add_argument(
        "--src", 
        help="Path to the source code for 'developer' and 'full' profiles. (Must be accessible by the worker)."
    )
    scan_parser.set_defaults(func=handle_start_scan)

    # --- 'get-status' command ---
    status_parser = subparsers.add_parser(
        "get-status", 
        help="Retrieve the status of a specific scan job.",
        description="Fetches the status and results for a previously initiated scan."
    )
    status_parser.add_argument(
        "job_id", 
        help="The unique Job ID of the scan to check (e.g., mock_job_id_12345)."
    )
    status_parser.set_defaults(func=handle_get_status)

    args = parser.parse_args()

    # --- CLI Logic to handle commands ---
    print("Authenticating with Project Sentinel API...")
    token = get_auth_token(args.username, args.password)
    if not token:
        sys.exit(1)
    
    print("Authentication successful.")
    
    # Call the function associated with the chosen sub-command
    args.func(token, args)

if __name__ == "__main__":
    main()

