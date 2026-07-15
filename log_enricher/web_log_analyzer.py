"""
web_log_analyzer.py
---------------------
Aggregates parsed web log events into an attacker-ranked summary -
same pattern as brute_force_analyzer.py for SSH logs, applied to
web attack patterns instead.
"""

import pandas as pd


def events_to_dataframe(events: list) -> pd.DataFrame:
    return pd.DataFrame(events)


def summarize_attackers(df: pd.DataFrame) -> pd.DataFrame:
    """
    Groups all flagged (suspicious) requests by source IP and
    summarizes what kind of attack behavior each IP showed.
    This gives an analyst a ranked "who's attacking us and how"
    view instead of a flat list of individual requests.
    """
    flagged = df[
        df["is_sqli_attempt"] | df["is_path_traversal"] | df["is_scanner_agent"]
    ]

    if flagged.empty:
        return pd.DataFrame()

    summary = (
        flagged.groupby("ip")
        .agg(
            total_flagged_requests=("ip", "count"),
            sqli_attempts=("is_sqli_attempt", "sum"),
            path_traversal_attempts=("is_path_traversal", "sum"),
            scanner_requests=("is_scanner_agent", "sum"),
            user_agents=("user_agent", lambda x: sorted(set(x))),
            first_seen=("timestamp", "min"),
        )
        .reset_index()
    )

    return summary.sort_values("total_flagged_requests", ascending=False)


def classify_severity(summary_row: dict) -> str:
    """
    Simple severity classification based on attack type - SQLi and
    path traversal are treated as more severe than generic scanning,
    since they indicate active exploitation attempts rather than
    just reconnaissance.
    """
    if summary_row["sqli_attempts"] > 0 or summary_row["path_traversal_attempts"] > 0:
        return "HIGH"
    elif summary_row["scanner_requests"] >= 3:
        return "MEDIUM"
    else:
        return "LOW"


# Quick manual test
if __name__ == "__main__":
    from web_log_parser import parse_log_file

    events = parse_log_file("sample_logs/access.log")
    df = events_to_dataframe(events)

    summary = summarize_attackers(df)
    if summary.empty:
        print("No suspicious activity detected.")
    else:
        summary["severity"] = summary.apply(classify_severity, axis=1)
        print(summary.to_string(index=False))