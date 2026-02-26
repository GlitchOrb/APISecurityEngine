# SSRF Protection

Server-Side Request Forgery happens when user inputs specify URLs that the backend API will issue HTTP requests against, potentially allowing unauthenticated or pivot-oriented access toward internal network services (AWS Metadata IP `169.254.169.254`, localhost management consoles).

## Defensive Strategy
Strict allowlisting domains. For resolving IP addresses, use socket validation blocking completely arbitrary ranges. DNS resolution must occur **prior** to validation to prevent TOCTOU (Time-Of-Check to Time-Of-Use) and DNS Rebinding.

---

### Python (ssrf-protect + requests)

```python
import ipaddress
import socket
from urllib.parse import urlparse

# Define a strict private local bounds
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # Cloud Provider Metadata
    ipaddress.ip_network('127.0.0.0/8'),     # Loopback
]

def is_safe_url(user_input_url: str) -> bool:
    """
    Resolves the submitted domain to its A record natively, and 
    compares the numerical IP against blocked private structures.
    """
    parsed = urlparse(user_input_url)
    if parsed.scheme not in ["http", "https"]:
        return False
        
    try:
        # Resolve hostname to block IP literal spoofing and TOCTOU DNS Rebinding 
        # BEFORE firing the requests.get()
        ip_addr = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_addr)
        
        for network in FORBIDDEN_NETWORKS:
            if ip in network:
                return False
                
        return True
    except Exception:
        return False

# Usage
import requests

def fetch_webhook(url: str):
    if not is_safe_url(url):
        raise ValueError("Unsafe SSRF URL blocked")
        
    return requests.get(url, timeout=5)
```
