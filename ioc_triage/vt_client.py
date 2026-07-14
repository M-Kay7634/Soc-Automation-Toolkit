"""
vt_client.py
------------
Handles all communication with the VirusTotal API.
Keeping this in its own file means if VirusTotal ever changes
their API, we only need to update this one file - nothing else
in the project needs to know HOW the API call works, just that
it returns a clean result.
"""

import requests
import sys
import os

# Allow importing from the shared/ folder one level up
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.config import VT_API_KEY

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def query_ip(ip_address: str) -> dict:
    """
    Queries VirusTotal for reputation info on an IP address.
    Returns a dict with the key stats we care about, or an
    error dict if something went wrong.
    """
    url = f"{VT_BASE_URL}/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=15)
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error contacting VirusTotal: {e}"}

    # VirusTotal free tier allows 4 requests/minute - if you go over,
    # you get a 429 status code. We handle it gracefully instead of
    # crashing, which is exactly what a real SOC tool needs to do.
    if response.status_code == 429:
        return {"error": "Rate limit hit. Wait a minute and try again."}

    if response.status_code == 404:
        return {"error": "No data found for this IP in VirusTotal."}

    if response.status_code != 200:
        return {"error": f"Unexpected VirusTotal response: {response.status_code}"}

    data = response.json()

    # Extract just the fields we care about, rather than dumping
    # the entire raw JSON (which is huge and mostly noise for our purpose)
    try:
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        return {
            "indicator": ip_address,
            "type": "ip",
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "undetected_votes": stats.get("undetected", 0),
            "country": attributes.get("country", "Unknown"),
            "asn_owner": attributes.get("as_owner", "Unknown"),
        }
    except KeyError:
        return {"error": "Unexpected response format from VirusTotal."}


# Quick manual test - only runs if you execute this file directly
if __name__ == "__main__":
    # 8.8.8.8 is Google's public DNS - safe test IP, always available
    result = query_ip("8.8.8.8")
    print(result)