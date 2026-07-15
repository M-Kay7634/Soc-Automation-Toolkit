"""
windows_log_analyzer.py
-------------------------
Analyzes exported Windows Security Event Logs (CSV format) for
common attack chain patterns:
  - Brute force: repeated 4625 (failed logon) events
  - Account compromise: 4625 spike followed by a 4624 (success)
    from the same account/IP
  - Persistence: 4720 (account created) shortly after a compromise
  - Privilege escalation: 4732 (added to a privileged group)

Since this is structured CSV data (not raw unstructured text like
the SSH/web logs), we use pandas directly instead of regex - a good
example of choosing the right tool for the data format you're given.
"""

import pandas as pd

BRUTE_FORCE_THRESHOLD = 5

EVENT_ID_MEANINGS = {
    4624: "successful_logon",
    4625: "failed_logon",
    4720: "account_created",
    4732: "added_to_privileged_group",
}


def load_events(filepath: str) -> pd.DataFrame:
    """
    Loads the Windows event export CSV and adds a human-readable
    event_type column based on the numeric EventID - analysts
    think in terms of "failed logon", not "4625".
    """
    df = pd.read_csv(filepath)
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"])
    df["event_type"] = df["EventID"].map(EVENT_ID_MEANINGS).fillna("other")
    return df


def find_brute_force_accounts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Groups failed logons (4625) by account + source IP, flags
    any combination crossing the threshold.
    """
    failed = df[df["event_type"] == "failed_logon"]

    counts = (
        failed.groupby(["Account", "SourceIP"])
        .agg(
            failed_attempts=("EventID", "count"),
            first_seen=("TimeCreated", "min"),
            last_seen=("TimeCreated", "max"),
        )
        .reset_index()
    )

    suspicious = counts[counts["failed_attempts"] >= BRUTE_FORCE_THRESHOLD]
    return suspicious.sort_values("failed_attempts", ascending=False)


def find_compromised_accounts(df: pd.DataFrame) -> pd.DataFrame:
    """
    The critical check: did an account/IP pair that failed multiple
    times ALSO succeed afterward? That's a strong signal the brute
    force attack worked.
    """
    failed = df[df["event_type"] == "failed_logon"]
    failed_pairs = set(zip(failed["Account"], failed["SourceIP"]))

    successful = df[df["event_type"] == "successful_logon"]

    compromised_rows = []
    for _, row in successful.iterrows():
        pair = (row["Account"], row["SourceIP"])
        if pair in failed_pairs:
            fail_count = len(failed[
                (failed["Account"] == row["Account"]) &
                (failed["SourceIP"] == row["SourceIP"])
            ])
            compromised_rows.append({
                "Account": row["Account"],
                "SourceIP": row["SourceIP"],
                "prior_failed_attempts": fail_count,
                "success_time": row["TimeCreated"],
            })

    return pd.DataFrame(compromised_rows)


def find_post_compromise_activity(df: pd.DataFrame, compromised: pd.DataFrame) -> pd.DataFrame:
    """
    For each compromised account, checks for suspicious follow-on
    activity (account creation, privilege escalation) occurring
    AFTER the successful logon - this is what turns "someone
    guessed a password" into "active incident requiring response".
    """
    if compromised.empty:
        return pd.DataFrame()

    suspicious_events = df[df["event_type"].isin(["account_created", "added_to_privileged_group"])]

    post_compromise_rows = []
    for _, comp_row in compromised.iterrows():
        follow_on = suspicious_events[
            (suspicious_events["Account"] == comp_row["Account"]) &
            (suspicious_events["SourceIP"] == comp_row["SourceIP"]) &
            (suspicious_events["TimeCreated"] >= comp_row["success_time"])
        ]
        for _, fo_row in follow_on.iterrows():
            post_compromise_rows.append({
                "compromised_account": comp_row["Account"],
                "attacker_ip": comp_row["SourceIP"],
                "follow_on_event": fo_row["event_type"],
                "time": fo_row["TimeCreated"],
                "details": fo_row["Message"],
            })

    return pd.DataFrame(post_compromise_rows)


# Quick manual test
if __name__ == "__main__":
    df = load_events("sample_logs/windows_events.csv")

    print("=== Brute Force Detection ===")
    brute_force = find_brute_force_accounts(df)
    print(brute_force.to_string(index=False) if not brute_force.empty else "None detected.")

    print("\n=== Compromised Account Check ===")
    compromised = find_compromised_accounts(df)
    print(compromised.to_string(index=False) if not compromised.empty else "None detected.")

    print("\n=== Post-Compromise Activity (Persistence / Privilege Escalation) ===")
    post_compromise = find_post_compromise_activity(df, compromised)
    if post_compromise.empty:
        print("None detected.")
    else:
        print("CRITICAL - attacker took follow-on action after compromising an account:")
        print(post_compromise.to_string(index=False))