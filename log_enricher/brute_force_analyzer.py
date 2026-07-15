"""
brute_force_analyzer.py
------------------------
Takes the structured events from ssh_log_parser.py and uses pandas
to find patterns: which IPs are hammering the server with failed
logins, and whether any of them eventually succeeded (a huge red
flag - it means a brute force attack may have WORKED).
"""

import pandas as pd


# If an IP has this many or more failed login attempts, we flag it
# as a likely brute-force source. 5 is a common, conservative
# starting threshold used in real detection rules (e.g. fail2ban
# defaults to a similar range) - tune this based on your environment.
BRUTE_FORCE_THRESHOLD = 5


def events_to_dataframe(events: list) -> pd.DataFrame:
    """
    Converts the list of event dicts into a pandas DataFrame -
    this unlocks fast filtering, grouping, and aggregation that
    would be painful to write by hand with plain Python loops.
    """
    return pd.DataFrame(events)


def find_brute_force_ips(df: pd.DataFrame) -> pd.DataFrame:
    """
    Groups failed login attempts by source IP and returns any IP
    that crosses the brute-force threshold, sorted by attempt count
    descending (worst offenders first - what an analyst wants to see).
    """
    failed = df[df["event_type"] == "failed_login"]

    counts = (
        failed.groupby("ip")
        .agg(
            failed_attempts=("ip", "count"),
            usernames_tried=("user", lambda x: sorted(set(x))),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )

    suspicious = counts[counts["failed_attempts"] >= BRUTE_FORCE_THRESHOLD]
    return suspicious.sort_values("failed_attempts", ascending=False)


def find_compromised_accounts(df: pd.DataFrame) -> pd.DataFrame:
    """
    THE most important check: did any IP that failed multiple times
    ALSO eventually succeed? That combination is a strong signal
    the brute force attack worked and the account is compromised.
    """
    failed_ips = set(df[df["event_type"] == "failed_login"]["ip"])
    successful = df[df["event_type"] == "successful_login"]

    compromised = successful[successful["ip"].isin(failed_ips)]
    return compromised[["timestamp", "ip", "user", "method"]]


# Quick manual test
if __name__ == "__main__":
    from ssh_log_parser import parse_log_file

    events = parse_log_file("sample_logs/auth.log")
    df = events_to_dataframe(events)

    print("=== Brute Force Source IPs ===")
    brute_force = find_brute_force_ips(df)
    print(brute_force.to_string(index=False))

    print("\n=== Compromised Account Check ===")
    compromised = find_compromised_accounts(df)
    if compromised.empty:
        print("No IPs that failed logins also succeeded - no compromise detected.")
    else:
        print("WARNING - the following logins succeeded from IPs with prior failures:")
        print(compromised.to_string(index=False))