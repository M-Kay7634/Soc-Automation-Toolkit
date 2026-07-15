"""
web_log_parser.py
-------------------
Parses Apache/Nginx-style Combined Log Format access logs and
flags common attack patterns: SQL injection, directory traversal,
and vulnerability scanning tools.

Example log line:
203.0.113.77 - - [15/Jan/2026:10:20:12 +0000] "GET /login.php?user=admin&pass=admin HTTP/1.1" 401 300 "-" "python-requests/2.28"
"""

import re

# Parses the standard Combined Log Format structure.
# Note: the request field is captured as ONE block between quotes,
# not split into method/path/protocol up front - attack payloads
# (like SQLi strings) often contain spaces, which would break a
# naive \S+ path capture. We split the request manually afterward.
LOG_LINE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


def _split_request(request: str) -> tuple:
    """
    Splits a raw request string like 'GET /path?query HTTP/1.1'
    into (method, path, protocol) - manually, because the path
    portion may itself contain spaces (e.g. SQLi payloads), so we
    can't just use str.split() blindly. We take the first word as
    the method and the last word (if it looks like a protocol) as
    the protocol, and treat everything in between as the path.
    """
    parts = request.split(" ")
    if len(parts) < 2:
        return request, "", ""

    method = parts[0]
    if re.match(r"^HTTP/\d", parts[-1]):
        path = " ".join(parts[1:-1])
        protocol = parts[-1]
    else:
        path = " ".join(parts[1:])
        protocol = ""

    return method, path, protocol

# Known attack signatures - real SOC detection rules are more
# sophisticated (often using dedicated WAF rule sets like OWASP
# CRS), but this demonstrates the same underlying concept:
# pattern-matching known-bad indicators in request data.
SQLI_PATTERNS = [
    r"'\s*OR\s*'1'\s*=\s*'1",
    r"UNION\s+SELECT",
    r"DROP\s+TABLE",
    r"--\s*$",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"etc/passwd",
    r"win\.ini",
]

# User agents commonly used by scanning/exploitation tools
SCANNER_USER_AGENTS = [
    "sqlmap", "nikto", "nmap", "python-requests", "curl", "masscan",
]


def parse_log_file(filepath: str) -> list:
    """
    Reads a web access log and returns a list of structured
    dicts with attack-pattern flags already attached.
    """
    events = []

    with open(filepath, "r") as f:
        for line_number, line in enumerate(f, start=1):
            match = LOG_LINE_PATTERN.search(line)
            if not match:
                continue

            path = _split_request(match.group("request"))[1]
            user_agent = match.group("user_agent")

            events.append({
                "line_number": line_number,
                "ip": match.group("ip"),
                "timestamp": match.group("timestamp"),
                "method": _split_request(match.group("request"))[0],
                "path": path,
                "status": int(match.group("status")),
                "user_agent": user_agent,
                "is_sqli_attempt": _matches_any(path, SQLI_PATTERNS),
                "is_path_traversal": _matches_any(path, PATH_TRAVERSAL_PATTERNS),
                "is_scanner_agent": _is_scanner_agent(user_agent),
            })

    return events


def _matches_any(text: str, patterns: list) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def _is_scanner_agent(user_agent: str) -> bool:
    ua_lower = user_agent.lower()
    return any(tool in ua_lower for tool in SCANNER_USER_AGENTS)


# Quick manual test
if __name__ == "__main__":
    events = parse_log_file("sample_logs/access.log")
    print(f"Parsed {len(events)} log lines\n")

    flagged = [e for e in events if e["is_sqli_attempt"] or e["is_path_traversal"] or e["is_scanner_agent"]]
    print(f"Flagged {len(flagged)} suspicious requests:\n")
    for e in flagged:
        flags = []
        if e["is_sqli_attempt"]:
            flags.append("SQLi")
        if e["is_path_traversal"]:
            flags.append("PathTraversal")
        if e["is_scanner_agent"]:
            flags.append("ScannerUA")
        print(f"  [{','.join(flags):20}] {e['ip']:16} {e['path']}")