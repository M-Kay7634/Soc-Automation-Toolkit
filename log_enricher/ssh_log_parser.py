"""
ssh_log_parser.py
------------------
Parses Linux SSH auth logs (auth.log / secure log format) into
structured records. This is the "extract" step of log analysis -
turning messy text into data we can actually query and aggregate.

Real auth.log lines look like:
Jan 15 10:20:01 server01 sshd[1201]: Failed password for root from 192.168.1.50 port 54321 ssh2
Jan 15 10:21:01 server01 sshd[1207]: Accepted password for manish from 10.0.0.15 port 51000 ssh2
"""

import re


# One regex per event type is easier to read and debug than one
# giant regex trying to match everything at once.
FAILED_PASSWORD_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)"
)

ACCEPTED_LOGIN_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<port>\d+)"
)


def parse_log_file(filepath: str) -> list:
    """
    Reads an auth.log file and returns a list of structured
    dicts, one per recognized event. Unrecognized lines
    (like 'Connection closed by...') are silently skipped -
    we only care about login attempts for this parser.
    """
    events = []

    with open(filepath, "r") as f:
        for line_number, line in enumerate(f, start=1):
            failed_match = FAILED_PASSWORD_PATTERN.search(line)
            if failed_match:
                events.append({
                    "line_number": line_number,
                    "event_type": "failed_login",
                    "timestamp": failed_match.group("timestamp"),
                    "host": failed_match.group("host"),
                    "user": failed_match.group("user"),
                    "ip": failed_match.group("ip"),
                    "port": failed_match.group("port"),
                })
                continue

            accepted_match = ACCEPTED_LOGIN_PATTERN.search(line)
            if accepted_match:
                events.append({
                    "line_number": line_number,
                    "event_type": "successful_login",
                    "timestamp": accepted_match.group("timestamp"),
                    "host": accepted_match.group("host"),
                    "user": accepted_match.group("user"),
                    "ip": accepted_match.group("ip"),
                    "port": accepted_match.group("port"),
                    "method": accepted_match.group("method"),
                })

    return events


# Quick manual test
if __name__ == "__main__":
    events = parse_log_file("sample_logs/auth.log")
    print(f"Parsed {len(events)} recognized events\n")
    for e in events[:5]:
        print(e)