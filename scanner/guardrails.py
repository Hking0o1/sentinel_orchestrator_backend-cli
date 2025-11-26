import re
import json
from typing import Any, Dict, List, Union

# --- PII Regex Patterns ---
# We use specific patterns to identify sensitive data.
PII_PATTERNS = [
    # Email Addresses (e.g. user@company.com)
    (r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '<EMAIL_REDACTED>'),
    
    # IPv4 Addresses (e.g. 192.168.1.1) - avoiding version numbers like 1.2.3
    (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '<IP_REDACTED>'),
    
    # Credit Card Numbers (Simple generic pattern for 13-16 digits)
    (r'\b(?:\d[ -]*?){13,16}\b', '<CREDIT_CARD_REDACTED>'),
    
    # Social Security Numbers (US)
    (r'\b\d{3}-\d{2}-\d{4}\b', '<SSN_REDACTED>'),
    
    # API Keys / Tokens (Generic high-entropy strings)
    # Looks for "key", "token", "secret" followed by 32+ chars
    (r'(?i)(api_key|access_token|secret|password)[\"\']?\s*[:=]\s*[\"\']?([a-zA-Z0-9\-_]{32,})[\"\']?', r'\1=<KEY_REDACTED>'),
    
    # AWS Access Key ID
    (r'AKIA[0-9A-Z]{16}', '<AWS_ACCESS_KEY_REDACTED>'),
    
    # Authorization Headers (Bearer tokens)
    (r'(Bearer\s+)([a-zA-Z0-9\-_.]+)', r'\1<TOKEN_REDACTED>')
]

def redact_text(text: str) -> str:
    """
    Applies all PII regex patterns to a string.
    """
    if not text:
        return ""
    
    redacted_text = text
    for pattern, replacement in PII_PATTERNS:
        try:
            redacted_text = re.sub(pattern, replacement, redacted_text)
        except Exception:
            # If regex fails, return original to avoid breaking flow, but log it in real app
            pass
            
    return redacted_text

def redact_pii_from_data(data: Any) -> Any:
    """
    Recursively traverses a dictionary, list, or string and redacts PII.
    This prepares data for safe sending to an LLM.
    """
    if isinstance(data, str):
        return redact_text(data)
        
    elif isinstance(data, dict):
        # Process dictionary values recursively
        new_dict = {}
        for k, v in data.items():
            # Check if the key itself suggests sensitive data
            if any(sensitive in k.lower() for sensitive in ['password', 'secret', 'token', 'auth']):
                new_dict[k] = "<REDACTED_VALUE>"
            else:
                new_dict[k] = redact_pii_from_data(v)
        return new_dict
        
    elif isinstance(data, list):
        # Process list items recursively
        return [redact_pii_from_data(item) for item in data]
        
    else:
        # Return numbers, booleans, None as is
        return data