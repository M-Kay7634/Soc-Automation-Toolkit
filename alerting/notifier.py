"""
notifier.py
------------
Sends alerts when something MALICIOUS/PHISHING is detected -
this is what turns the toolkit from "detection" into
"detection + automated response" (the core idea behind SOAR -
Security Orchestration, Automation and Response - platforms).

Supports two channels, both optional and independently configured
via .env:
  - Email (SMTP) - works with Gmail using an App Password
  - Slack (webhook) - a simple HTTP POST, no SDK needed

If neither is configured, alerts just print to the console -
the tool still works, it just doesn't notify anyone externally.
"""

import os
import smtplib
import requests
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")  # Gmail App Password, NOT your real password
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")


def send_alert(subject: str, message: str) -> None:
    """
    Sends an alert through every configured channel. Always prints
    to console too, so you have a record even if email/Slack aren't
    set up yet (useful during development/testing).
    """
    print(f"\n🚨 ALERT: {subject}\n{message}\n")

    if SMTP_USERNAME and SMTP_PASSWORD and ALERT_EMAIL_TO:
        _send_email(subject, message)

    if SLACK_WEBHOOK_URL:
        _send_slack(subject, message)


def _send_email(subject: str, message: str) -> None:
    """
    Sends an email alert via SMTP. For Gmail: you must use an
    App Password (not your normal password) - generate one at
    https://myaccount.google.com/apppasswords (requires 2FA enabled).
    """
    try:
        msg = MIMEText(message)
        msg["Subject"] = f"[SOC Toolkit Alert] {subject}"
        msg["From"] = SMTP_USERNAME
        msg["To"] = ALERT_EMAIL_TO

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # encrypts the connection before login
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, ALERT_EMAIL_TO, msg.as_string())

        print("  ✅ Email alert sent")
    except Exception as e:
        # Alerting failures should never crash the main detection
        # pipeline - log it and move on, don't let a notification
        # problem stop the actual security analysis
        print(f"  ⚠️ Email alert failed: {e}")


def _send_slack(subject: str, message: str) -> None:
    """
    Sends an alert to a Slack channel via an Incoming Webhook.
    Set one up at https://api.slack.com/messaging/webhooks -
    no bot/app approval needed for a simple webhook.
    """
    try:
        payload = {"text": f"*🚨 {subject}*\n{message}"}
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if response.status_code == 200:
            print("  ✅ Slack alert sent")
        else:
            print(f"  ⚠️ Slack alert failed: HTTP {response.status_code}")
    except Exception as e:
        print(f"  ⚠️ Slack alert failed: {e}")


def should_alert(verdict: str) -> bool:
    """
    Centralizes the decision of what's alert-worthy. Keeping this
    in one place means every module (IOC triage, log enricher,
    phishing analyzer) applies the same standard for what counts
    as "important enough to notify someone about."
    """
    return verdict in ("MALICIOUS", "PHISHING")


# Quick manual test - only tests the console output, since email/
# Slack require real credentials which aren't set in this test
if __name__ == "__main__":
    send_alert(
        subject="Test Alert - Malicious IP Detected",
        message="IP 45.155.205.233 flagged as MALICIOUS (17 VirusTotal vendors). "
                "This is a test alert to confirm the notifier module works.",
    )

    print(f"should_alert('MALICIOUS'): {should_alert('MALICIOUS')}")
    print(f"should_alert('CLEAN'): {should_alert('CLEAN')}")