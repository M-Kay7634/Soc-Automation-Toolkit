"""
ioc_utils.py
------------
Utility functions to detect what TYPE of indicator (IOC) we're
dealing with. This matters because VirusTotal has different API
endpoints for IPs, domains, URLs, and file hashes - we need to know
which one to call.
"""

import re


def detect_ioc_type(indicator: str) -> str:
    """
    Given a string, figure out if it's an IP, domain, URL, or file hash.
    Returns one of: 'ip', 'url', 'domain', 'md5', 'sha1', 'sha256', 'unknown'
    """
    indicator = indicator.strip()

    # IPv4 pattern - four numbers 0-255 separated by dots
    ipv4_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    if re.match(ipv4_pattern, indicator):
        octets = indicator.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return "ip"

    # URL - starts with http:// or https://
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"

    # File hashes - identified purely by length and hex characters
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "md5"
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "sha256"

    # Domain - contains a dot, no spaces, not caught by above
    domain_pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, indicator):
        return "domain"

    return "unknown"


# Quick manual test - run this file directly to check it works
if __name__ == "__main__":
    test_values = [
        "8.8.8.8",
        "https://example.com/malware.exe",
        "d41d8cd98f00b204e9800998ecf8427e",  # md5
        "malicious-domain.com",
        "not a valid indicator at all",
    ]
    for val in test_values:
        print(f"{val!r:50} -> {detect_ioc_type(val)}")