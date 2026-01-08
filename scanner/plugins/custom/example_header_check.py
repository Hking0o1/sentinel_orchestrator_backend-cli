import requests
from typing import List, Dict, Any
from scanner.plugins.base import BaseScannerPlugin, PluginContext, PluginResult

class HeaderSecurityPlugin(BaseScannerPlugin):
    """
    A simple custom plugin to check security headers.
    Demonstrates how to write a plugin without touching the core engine.
    """

    @property
    def name(self) -> str:
        return "Custom Header Inspector"

    @property
    def version(self) -> str:
        return "0.1.0"

    @property
    def profile(self) -> str:
        return "web"  # Runs only on web targets

    def run(self, context: PluginContext) -> PluginResult:
        findings = []
        logs = []
        target = context.target_url

        if not target:
            return PluginResult(self.name, True, [], "Skipped: No target URL")

        try:
            logs.append(f"Checking headers for {target}...")
            
            # Perform the scan logic
            # verify=False is used to avoid crashing on self-signed certs during internal testing
            response = requests.head(target, timeout=5, verify=False)
            headers = {k.lower(): v for k, v in response.headers.items()}

            # Logic: Check for X-Content-Type-Options
            if 'x-content-type-options' not in headers:
                findings.append({
                    "tool": f"Plugin: {self.name}",
                    "severity": "LOW",
                    "title": "Missing Security Header",
                    "description": "X-Content-Type-Options header is missing.",
                    "details": "This header prevents MIME-sniffing attacks.",
                    "remediation": "Add 'X-Content-Type-Options: nosniff' to your server config.",
                    "location": target
                })
            else:
                logs.append("X-Content-Type-Options found.")

            return PluginResult(self.name, True, findings, "\n".join(logs))

        except Exception as e:
            return PluginResult(self.name, False, [], f"Plugin crashed: {str(e)}")

# --- CLI Test Block ---
# You can run this file directly to test it!
# python scanner/plugins/custom/example_header_check.py
if __name__ == "__main__":
    # Mock context for testing
    ctx = PluginContext(target_url="http://example.com", source_path=None, output_dir=".", auth_cookie=None)
    plugin = HeaderSecurityPlugin()
    result = plugin.run(ctx)
    
    print(f"--- Results for {plugin.name} ---")
    print(result.findings)