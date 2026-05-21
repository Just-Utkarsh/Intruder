"""Optional Telegram and email intrusion alerts."""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class AlertManager:
    def __init__(self, config: dict[str, Any]) -> None:
        alerts = config.get("alerts", {})
        self._telegram_enabled = alerts.get("telegram_enabled", False)
        self._telegram_token = alerts.get("telegram_bot_token", "")
        self._telegram_chat = alerts.get("telegram_chat_id", "")
        self._email_enabled = alerts.get("email_enabled", False)
        self._smtp_host = alerts.get("email_smtp_host", "")
        self._smtp_port = int(alerts.get("email_smtp_port", 587))
        self._email_from = alerts.get("email_from", "")
        self._email_to = alerts.get("email_to", "")
        self._email_password = alerts.get("email_password", "")

    async def notify_intrusion_async(self, incident_id: str, confidence: float) -> None:
        message = f"Intruder detected\nID: {incident_id}\nConfidence: {confidence:.2%}"
        if self._telegram_enabled:
            await self._send_telegram(message)
        if self._email_enabled:
            self._send_email("Intruder Detector Alert", message)

    def notify_intrusion(self, incident_id: str, confidence: float) -> None:
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.notify_intrusion_async(incident_id, confidence))
            else:
                loop.run_until_complete(self.notify_intrusion_async(incident_id, confidence))
        except RuntimeError:
            asyncio.run(self.notify_intrusion_async(incident_id, confidence))

    async def _send_telegram(self, text: str) -> None:
        if not self._telegram_token or not self._telegram_chat:
            return
        url = f"https://api.telegram.org/bot{self._telegram_token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(url, json={"chat_id": self._telegram_chat, "text": text})
        except Exception as e:
            logger.error("Telegram alert failed: %s", e)

    def _send_email(self, subject: str, body: str) -> None:
        if not all([self._smtp_host, self._email_from, self._email_to]):
            return
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self._email_from
        msg["To"] = self._email_to
        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port) as server:
                server.starttls()
                if self._email_password:
                    server.login(self._email_from, self._email_password)
                server.send_message(msg)
        except Exception as e:
            logger.error("Email alert failed: %s", e)
