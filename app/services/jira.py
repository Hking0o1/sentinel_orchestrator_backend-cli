import logging
from jira import JIRA
from config.settings import settings
from typing import List, Dict, Any

logger = logging.getLogger("project_sentinel.integrations.jira")

class JiraService:
    def __init__(self):
        self.client = None
        self.enabled = False
        
        # Only initialize if ALL credentials are present
        if settings.JIRA_SERVER and settings.JIRA_USERNAME and settings.JIRA_API_TOKEN:
            try:
                self.client = JIRA(
                    server=settings.JIRA_SERVER,
                    basic_auth=(settings.JIRA_USERNAME, settings.JIRA_API_TOKEN)
                )
                self.enabled = True
                logger.info("Jira integration enabled.")
            except Exception as e:
                logger.error(f"Failed to connect to Jira: {e}")
        else:
            logger.info("Jira credentials not set. Ticket creation will be skipped.")

    def create_tickets(self, tickets: List[Dict[str, Any]]) -> int:
        """
        Creates Jira tickets for a list of findings.
        Returns the number of tickets created.
        """
        if not self.enabled or not self.client:
            return 0

        created_count = 0
        for ticket in tickets:
            try:
                # Map our internal priority to Jira priority
                # Adjust these names based on your specific Jira project configuration
                jira_priority = "High" 
                if ticket.get('priority') == "CRITICAL":
                    jira_priority = "Highest"
                elif ticket.get('priority') == "MEDIUM":
                    jira_priority = "Medium"

                issue_dict = {
                    'project': {'key': settings.JIRA_PROJECT_KEY},
                    'summary': f"[Sentinel] {ticket.get('title')}",
                    'description': (
                        f"**Vulnerability Report**\n\n"
                        f"{ticket.get('description')}\n\n"
                        f"--- \n"
                        f"*Severity:* {ticket.get('priority')}\n"
                        f"*Remediation:* {ticket.get('remediation')}\n"
                        f"*Source:* Project Sentinel Automated Scan"
                    ),
                    'issuetype': {'name': 'Bug'},
                    # Uncomment if your Jira uses priorities
                    # 'priority': {'name': jira_priority} 
                }
                
                new_issue = self.client.create_issue(fields=issue_dict)
                logger.info(f"Created Jira ticket: {new_issue.key}")
                created_count += 1
            except Exception as e:
                logger.error(f"Failed to create ticket for '{ticket.get('title')}': {e}")
        
        return created_count

# Create a singleton instance
jira_service = JiraService()