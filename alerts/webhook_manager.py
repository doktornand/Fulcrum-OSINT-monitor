"""
alerts/webhook_manager.py — Gestionnaire d'alertes webhook pour FULCRUM

Supporte :
  - Webhooks HTTP génériques (POST JSON)
  - Slack (Incoming Webhooks)
  - Discord (Webhooks)
  - Telegram Bot API

Filtrage par sévérité configurable (critical_only, min_score).

Google-style docstrings. Aucune dépendance externe au-delà de requests.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("FULCRUM.alerts")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests non installé — alertes webhook désactivées")

# ---------------------------------------------------------------------------
# Formateurs de payload
# ---------------------------------------------------------------------------

def _format_slack(article: Dict[str, Any]) -> Dict[str, Any]:
    """Formate un article pour Slack (Block Kit).

    Args:
        article: Dict de l'article FULCRUM.

    Returns:
        Payload Slack Block Kit.
    """
    severity = article.get("severity", "INFO")
    score = article.get("risk_score", 0)
    title = article.get("title", "Sans titre")
    source = article.get("source", "?")
    link = article.get("link", "")

    color_map = {
        "FLASH": "#FF0000", "CRITICAL": "#FF2A6D",
        "HIGH": "#FF6B35", "MEDIUM": "#F5A623",
        "WATCH": "#5BC0EB", "INFO": "#9B9B9B",
    }

    return {
        "attachments": [{
            "color": color_map.get(severity, "#9B9B9B"),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*[{severity}]* {title}",
                    },
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Source: {source} | Score: {score}/100"},
                    ],
                },
                *([{"type": "actions", "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "Voir l'article"},
                     "url": link}
                ]}] if link else []),
            ],
        }]
    }


def _format_discord(article: Dict[str, Any]) -> Dict[str, Any]:
    """Formate un article pour Discord Webhook (Embed).

    Args:
        article: Dict de l'article FULCRUM.

    Returns:
        Payload Discord webhook.
    """
    severity = article.get("severity", "INFO")
    score = article.get("risk_score", 0)
    title = article.get("title", "Sans titre")
    source = article.get("source", "?")
    summary = article.get("summary", "")[:200]
    link = article.get("link", "")
    theatres = ", ".join(article.get("theatres", []))
    actors = ", ".join(article.get("actors", []))

    color_map = {
        "FLASH": 16711680, "CRITICAL": 16721005,
        "HIGH": 16737077, "MEDIUM": 16099875,
        "WATCH": 6013163, "INFO": 10197915,
    }

    embed: Dict[str, Any] = {
        "title": f"[{severity}] {title[:250]}",
        "description": summary,
        "color": color_map.get(severity, 10197915),
        "fields": [
            {"name": "Source", "value": source, "inline": True},
            {"name": "Risk Score", "value": str(score), "inline": True},
        ],
        "footer": {"text": "FULCRUM Intelligence Platform"},
    }
    if link:
        embed["url"] = link
    if theatres:
        embed["fields"].append({"name": "Théâtres", "value": theatres, "inline": True})
    if actors:
        embed["fields"].append({"name": "Acteurs", "value": actors, "inline": False})

    return {"embeds": [embed]}


def _format_telegram(article: Dict[str, Any], chat_id: str) -> Dict[str, Any]:
    """Formate un article pour l'API Telegram.

    Args:
        article: Dict de l'article FULCRUM.
        chat_id: ID du chat/canal Telegram.

    Returns:
        Payload API Telegram.
    """
    severity = article.get("severity", "INFO")
    score = article.get("risk_score", 0)
    title = article.get("title", "Sans titre")
    source = article.get("source", "?")
    link = article.get("link", "")

    emoji = {
        "FLASH": "🚨", "CRITICAL": "🔴", "HIGH": "🟠",
        "MEDIUM": "🟡", "WATCH": "🔵", "INFO": "⚪",
    }.get(severity, "⚪")

    text = f"{emoji} <b>[{severity}]</b> {title}\n\n"
    text += f"📡 <i>{source}</i> | Score: <b>{score}/100</b>"
    if link:
        text += f'\n\n<a href="{link}">→ Lire l\'article</a>'

    return {
        "chat_id": chat_id,
        "text": text[:4096],
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }


# ---------------------------------------------------------------------------
# WebhookManager
# ---------------------------------------------------------------------------

class WebhookManager:
    """Gestionnaire centralisé des alertes webhook FULCRUM.

    Args:
        config: Objet de configuration FULCRUM (section alerts).
        critical_only: Si True, n'envoie que les sévérités CRITICAL et FLASH.
        min_score: Score de risque minimum pour déclencher une alerte.

    Example:
        >>> manager = WebhookManager(config)
        >>> manager.send_alert(article_dict)
    """

    _CRITICAL_SEVERITIES = {"FLASH", "CRITICAL"}

    def __init__(
        self,
        config: Any,
        critical_only: bool = False,
        min_score: int = 70,
    ) -> None:
        self.critical_only = critical_only
        self.min_score = min_score

        # Extraction de la config
        if hasattr(config, "alerts"):
            alerts_cfg = config.alerts
            self.webhooks: List[str] = getattr(alerts_cfg, "webhooks", []) or []
            self.telegram_token: Optional[str] = getattr(alerts_cfg, "telegram_bot_token", None)
            self.telegram_chat: Optional[str] = getattr(alerts_cfg, "telegram_chat_id", None)
            self.slack_webhook: Optional[str] = getattr(alerts_cfg, "slack_webhook", None)
            self.discord_webhook: Optional[str] = getattr(alerts_cfg, "discord_webhook", None)
            if getattr(alerts_cfg, "critical_only", False):
                self.critical_only = True
        else:
            # Fallback dict config
            self.webhooks = (config.get("alerts.webhooks") if hasattr(config, "get") else []) or []
            self.telegram_token = config.get("alerts.telegram_bot_token") if hasattr(config, "get") else None
            self.telegram_chat = config.get("alerts.telegram_chat_id") if hasattr(config, "get") else None
            self.slack_webhook = config.get("alerts.slack_webhook") if hasattr(config, "get") else None
            self.discord_webhook = config.get("alerts.discord_webhook") if hasattr(config, "get") else None

        self._session = requests.Session() if REQUESTS_AVAILABLE else None

    # ------------------------------------------------------------------
    # Filtrage
    # ------------------------------------------------------------------

    def _should_alert(self, article: Dict[str, Any]) -> bool:
        """Détermine si un article doit déclencher une alerte.

        Args:
            article: Dict de l'article.

        Returns:
            True si l'alerte doit être envoyée.
        """
        severity = article.get("severity", "INFO")
        score = article.get("risk_score", 0)

        if self.critical_only and severity not in self._CRITICAL_SEVERITIES:
            return False

        if score < self.min_score:
            return False

        return True

    # ------------------------------------------------------------------
    # Envoi
    # ------------------------------------------------------------------

    def send_alert(self, article: Dict[str, Any]) -> bool:
        """Envoie une alerte pour un article si les critères sont remplis.

        Args:
            article: Dict de l'article FULCRUM.

        Returns:
            True si au moins une alerte a été envoyée avec succès.
        """
        if not self._should_alert(article):
            return False

        sent = False

        # Webhooks génériques
        for url in self.webhooks:
            if self._post(url, article):
                sent = True

        # Slack
        if self.slack_webhook:
            payload = _format_slack(article)
            if self._post(self.slack_webhook, payload):
                sent = True

        # Discord
        if self.discord_webhook:
            payload = _format_discord(article)
            if self._post(self.discord_webhook, payload):
                sent = True

        # Telegram
        if self.telegram_token and self.telegram_chat:
            payload = _format_telegram(article, self.telegram_chat)
            tg_url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            if self._post(tg_url, payload):
                sent = True

        return sent

    def send_batch(self, articles: List[Dict[str, Any]], delay: float = 0.5) -> int:
        """Envoie des alertes pour une liste d'articles.

        Args:
            articles: Liste d'articles triés par score décroissant.
            delay: Délai entre chaque envoi (rate limiting).

        Returns:
            Nombre d'alertes envoyées.
        """
        count = 0
        for art in articles:
            if self.send_alert(art):
                count += 1
                if delay > 0:
                    time.sleep(delay)
        return count

    def _post(self, url: str, payload: Dict[str, Any]) -> bool:
        """Envoie un payload JSON vers une URL.

        Args:
            url: URL cible.
            payload: Données JSON à envoyer.

        Returns:
            True si succès (HTTP 2xx).
        """
        if not self._session:
            return False
        try:
            resp = self._session.post(
                url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning(f"Webhook {url[:50]}… échec: {exc}")
            return False
