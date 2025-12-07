import requests
import logging
import os

logger = logging.getLogger("project_sentinel.integrations.notifier")

class NotificationService:
    def __init__(self):
        # We read this directly from env to keep it optional/flexible
        self.webhook_url = os.getenv("NOTIFICATION_WEBHOOK_URL")

    def send_scan_complete(self, project_name: str, status: str, finding_count: int, critical_count: int, report_url: str):
        """
        Sends a notification card to a webhook.
        Auto-detects Slack vs Generic formats.
        """
        if not self.webhook_url:
            return

        logger.info(f"Sending notification to webhook for {project_name}...")
        
        # Determine status color
        color = "#10b981" # Green
        if status == "FAILED": color = "#ef4444" # Red
        elif critical_count > 0: color = "#ef4444" # Red

        # 1. Slack-specific payload (if 'slack' is in URL)
        if "slack.com" in self.webhook_url:
            payload = {
                "text": f"*Project Sentinel Scan: {project_name}*\nStatus: {status}\nFindings: {finding_count} ({critical_count} Critical)\n<{report_url}|Download Report>"
            }
        
        # 2. Generic / Discord / Teams Payload (Embeds)
        else:
            payload = {
                "username": "Project Sentinel",
                "embeds": [
                    {
                        "title": f"Scan Completed: {project_name}",
                        "color": int(color.replace("#", ""), 16),
                        "fields": [
                            {"name": "Status", "value": status, "inline": True},
                            {"name": "Total Findings", "value": str(finding_count), "inline": True},
                            {"name": "Critical Issues", "value": str(critical_count), "inline": True},
                            {"name": "Report", "value": f"[Download PDF]({report_url})"}
                        ]
                    }
                ]
            }

        try:
            requests.post(self.webhook_url, json=payload, timeout=5)
            logger.info("Notification sent.")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

notifier = NotificationService()