import os
import httpx
import json
from mcp.server.fastmcp import FastMCP
from typing import Optional, List, Dict, Any

mcp = FastMCP("Wazuh_SIEM_Analyst")

# Configuration
# Users should set these environment variables when running the server
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://<WAZUH_SERVER_IP>:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "wazuh")

# Context about your specific environment's capabilities
ENVIRONMENT_CONTEXT = """
SYSTEM CONTEXT FOR ANALYSIS:
This environment is a MiniSOC Lab running Wazuh. It has specific detection capabilities:
1. Sysmon/MITRE: Custom rules are configured to detect advanced threats mapped to MITRE ATT&CK, 
   including Process Injection (T1055), Credential Dumping (T1003), and Powershell Abuse (T1059).
2. Web Security: WPScan rules are active to detect WordPress scanning and enumeration.
3. Network: Mikrotik router logs are being monitored for IPsec errors and login anomalies.

When analyzing, prioritize alerts that map to these specific MITRE techniques.
"""

async def get_wazuh_token(client: httpx.AsyncClient) -> str:
    """Authenticates with the Wazuh API and retrieves a JWT token."""
    auth_url = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        response = await client.get(
            auth_url, 
            auth=(WAZUH_USER, WAZUH_PASSWORD),
            timeout=10.0,
            verify=False # Often needed for self-signed Wazuh certs
        )
        response.raise_for_status()
        return response.json()['data']['token']
    except Exception as e:
        raise RuntimeError(f"Authentication failed: {str(e)}")

@mcp.tool()
async def fetch_threat_summary(limit: int = 20, min_level: int = 5) -> str:
    """
    Fetches a high-level summary of recent security alerts.
    
    Use this FIRST to get an overview of the current threat landscape.
    If you see something suspicious, use 'get_alert_details' to investigate further.
    
    Args:
        limit: Number of alerts (default 20).
        min_level: Severity level 0-15 (default 5). Level 12+ are critical.
    """
    alerts_url = f"{WAZUH_API_URL}/alerts"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            token = await get_wazuh_token(client)
            headers = {"Authorization": f"Bearer {token}"}
            params = {
                "limit": limit,
                "sort": "-timestamp",
                "level": min_level
            }
            
            response = await client.get(alerts_url, headers=headers, params=params)
            response.raise_for_status()
            alerts = response.json().get('data', {}).get('items', [])
            
            if not alerts:
                return "No active threats found matching criteria."

            # Summarize for the LLM
            summary = []
            for alert in alerts:
                summary.append({
                    "alert_id": alert.get("id"),
                    "timestamp": alert.get("timestamp"),
                    "rule_description": alert.get("rule", {}).get("description"),
                    "severity": alert.get("rule", {}).get("level"),
                    "mitre_technique": alert.get("rule", {}).get("mitre", {}).get("id"),
                    "agent": alert.get("agent", {}).get("name")
                })

            return json.dumps({
                "analyst_note": ENVIRONMENT_CONTEXT,
                "threat_summary": summary
            }, indent=2)

        except Exception as e:
            return f"Error fetching summary: {str(e)}"

@mcp.tool()
async def get_alert_details(alert_id: str) -> str:
    """
    Fetches the full raw log and metadata for a SPECIFIC alert ID.
    
    Use this to perform deep-dive analysis on a specific suspicious event 
    identified in the summary.
    """
    # Wazuh doesn't have a direct "get alert by ID" endpoint in all versions,
    # so we search for it.
    alerts_url = f"{WAZUH_API_URL}/alerts"

    async with httpx.AsyncClient(verify=False) as client:
        try:
            token = await get_wazuh_token(client)
            headers = {"Authorization": f"Bearer {token}"}
            params = {
                "search": alert_id,
                "limit": 1
            }
            
            response = await client.get(alerts_url, headers=headers, params=params)
            response.raise_for_status()
            items = response.json().get('data', {}).get('items', [])
            
            if not items:
                return f"Alert ID {alert_id} not found."
            
            # Return the full, raw JSON for deep analysis
            return json.dumps(items[0], indent=2)

        except Exception as e:
            return f"Error fetching details: {str(e)}"

if __name__ == "__main__":
    mcp.run()