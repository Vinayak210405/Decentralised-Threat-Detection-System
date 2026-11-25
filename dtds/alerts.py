"""Alert delivery: console, JSON-lines file, webhook (Slack/Teams/Discord-style), email.

Channels are configured from environment variables so no secrets live in code:

    DTDS_WEBHOOK_URL   POST {"text": ..., "alert": {...}} to this URL
    DTDS_SMTP_HOST, DTDS_SMTP_PORT, DTDS_SMTP_USER, DTDS_SMTP_PASSWORD,
    DTDS_ALERT_EMAIL_FROM, DTDS_ALERT_EMAIL_TO   send an email per alert
"""
from __future__ import annotations

import json
import os
import smtplib
import time
from dataclasses import asdict, dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional

from dtds.sharing.taxonomy import Category, Severity


@dataclass
class Alert:
    company: str
    title: str
    severity: int
    category: int
    ioc_hash: int
    reports: int
    known_locally: Optional[str] = None   # plaintext IOC if this company has seen it itself
    action: str = "blocked"
    timestamp: float = field(default_factory=time.time)

    def text(self) -> str:
        sev = Severity(self.severity).name
        cat = Category(self.category).name if self.category in Category._value2member_map_ else self.category
        what = self.known_locally or f"indicator hash {hex(self.ioc_hash)[:18]}..."
        return (f"[{self.company}] {sev} {self.title}: {what} reported by {self.reports} member "
                f"companies (category {cat}); action: {self.action}")


class ConsoleChannel:
    def send(self, alert: Alert) -> None:
        print("  ALERT " + alert.text())


class JsonlChannel:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, alert: Alert) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps({**asdict(alert), "ioc_hash": hex(alert.ioc_hash)}) + "\n")


class WebhookChannel:
    def __init__(self, url: str):
        self.url = url

    def send(self, alert: Alert) -> None:
        import requests
        requests.post(self.url, json={"text": alert.text(),
                                      "alert": {**asdict(alert), "ioc_hash": hex(alert.ioc_hash)}},
                      timeout=10)


class EmailChannel:
    def __init__(self, host: str, port: int, user: Optional[str], password: Optional[str],
                 sender: str, recipients: List[str]):
        self.host, self.port, self.user, self.password = host, port, user, password
        self.sender, self.recipients = sender, recipients

    def send(self, alert: Alert) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[DTDS] {Severity(alert.severity).name}: {alert.title}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(alert.text())
        with smtplib.SMTP(self.host, self.port, timeout=15) as s:
            s.starttls()
            if self.user:
                s.login(self.user, self.password or "")
            s.send_message(msg)


class Alerter:
    def __init__(self, channels: List):
        self.channels = channels
        self.sent: List[Alert] = []

    def send(self, alert: Alert) -> None:
        self.sent.append(alert)
        for ch in self.channels:
            try:
                ch.send(alert)
            except Exception as e:  # one broken channel must not stop the others
                print(f"  (alert channel {type(ch).__name__} failed: {e})")

    @classmethod
    def from_env(cls, log_path: Optional[Path] = None, console: bool = True) -> "Alerter":
        chans: List = []
        if console:
            chans.append(ConsoleChannel())
        if log_path:
            chans.append(JsonlChannel(log_path))
        env: Dict[str, str] = dict(os.environ)
        if env.get("DTDS_WEBHOOK_URL"):
            chans.append(WebhookChannel(env["DTDS_WEBHOOK_URL"]))
        if env.get("DTDS_SMTP_HOST") and env.get("DTDS_ALERT_EMAIL_TO"):
            chans.append(EmailChannel(env["DTDS_SMTP_HOST"], int(env.get("DTDS_SMTP_PORT", 587)),
                                      env.get("DTDS_SMTP_USER"), env.get("DTDS_SMTP_PASSWORD"),
                                      env.get("DTDS_ALERT_EMAIL_FROM", "dtds@localhost"),
                                      env["DTDS_ALERT_EMAIL_TO"].split(",")))
        return cls(chans)
