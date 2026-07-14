"""
abuseipdb_client.py
--------------------
Handles communication with the AbuseIPDB API. This gives us a
SECOND opinion on an IP's reputation, focused specifically on
abuse reports (brute force, spam, scanning) rather than malware
detection like VirusTotal.

Using two sources instead of one mirrors real SOC practice:
never trust a single threat intel feed blindly.
"""

import requests
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.config import ABUSEIPDB_API_KEY

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def query_ip_abuse(ip_address: str) -> dict:
    """
    Queries AbuseIPDB for abuse reports on an IP address.
    Returns a dict with key stats, or an error dict on failure.
    """
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,  # only count reports from the last 90 days
    }

    try:
        response = requests.get(
            ABUSEIPDB_BASE_URL, headers=headers, params=params, timeout=15
        )
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error contacting AbuseIPDB: {e}"}

    if response.status_code == 429:
        return {"error": "AbuseIPDB rate limit hit. Wait and try again."}

    if response.status_code != 200:
        return {"error": f"Unexpected AbuseIPDB response: {response.status_code}"}

    data = response.json()

    try:
        d = data["data"]
        return {
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),  # 0-100
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", "Unknown"),
            "isp": d.get("isp", "Unknown"),
            "is_public": d.get("isPublic", True),
            "last_reported_at": d.get("lastReportedAt", None),
        }
    except KeyError:
        return {"error": "Unexpected response format from AbuseIPDB."}


# Quick manual test
if __name__ == "__main__":
    result = query_ip_abuse("8.8.8.8")
    print(result)