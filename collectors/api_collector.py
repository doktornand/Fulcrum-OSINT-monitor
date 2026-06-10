"""
collectors/api_collector.py — Collecteurs API temps réel pour FULCRUM

Sources supportées (sans dépendance IA/LLM) :
  - CISA KEV API (Known Exploited Vulnerabilities)
  - ACLED API (Armed Conflict Location & Event Data)
  - HIBP (HaveIBeenPwned) API v3
  - Ransomware.live API

Toute clé API est configurée dans fulcrum_config.yml (section api_keys).

Google-style docstrings.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger("FULCRUM.api")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning("requests non installé — collecteurs API désactivés")

# ---------------------------------------------------------------------------
# Client HTTP de base
# ---------------------------------------------------------------------------

class _BaseAPICollector:
    """Client HTTP commun aux collecteurs API.

    Args:
        timeout: Timeout des requêtes HTTP en secondes.
        api_key: Clé API optionnelle.
    """

    def __init__(self, timeout: int = 15, api_key: Optional[str] = None) -> None:
        self.timeout = timeout
        self.api_key = api_key
        self._session: Optional[Any] = None

        if REQUESTS_AVAILABLE:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": "FULCRUM/3.0 (Intelligence Platform)"})

    def _get(self, url: str, params: Optional[Dict] = None, headers: Optional[Dict] = None) -> Optional[Any]:
        """Exécute une requête GET JSON.

        Args:
            url: URL de l'endpoint.
            params: Paramètres de requête optionnels.
            headers: Headers HTTP supplémentaires.

        Returns:
            Données JSON parsées ou None en cas d'erreur.
        """
        if not self._session:
            return None
        try:
            resp = self._session.get(
                url, params=params, headers=headers, timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.debug(f"API GET {url} erreur: {exc}")
            return None


# ---------------------------------------------------------------------------
# CISA KEV API
# ---------------------------------------------------------------------------

class CISAKevCollector(_BaseAPICollector):
    """Collecteur pour le catalogue KEV de la CISA.

    L'API KEV est publique et ne nécessite pas de clé API.
    URL : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

    Example:
        >>> collector = CISAKevCollector()
        >>> articles = collector.fetch(limit=50)
    """

    _API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch(self, limit: int = 50, days_back: int = 30) -> List[Dict[str, Any]]:
        """Récupère les vulnérabilités KEV récentes.

        Args:
            limit: Nombre maximum de vulnérabilités à retourner.
            days_back: Fenêtre temporelle en jours.

        Returns:
            Liste de dicts articles normalisés.
        """
        data = self._get(self._API_URL)
        if not data:
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
        articles = []

        for vuln in vulnerabilities:
            date_added = vuln.get("dateAdded", "")
            try:
                pub_date = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if pub_date < cutoff:
                    continue
            except (ValueError, TypeError):
                pass

            cve_id = vuln.get("cveID", "")
            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            description = vuln.get("shortDescription", "")
            action = vuln.get("requiredAction", "")
            due_date = vuln.get("dueDate", "")

            title = f"[KEV] {cve_id} — {vendor} {product}"
            summary = (
                f"{description} | Action requise: {action} | Échéance: {due_date}"
            )

            articles.append({
                "source": "CISA KEV Catalog",
                "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "source_type": "api",
                "title": title,
                "summary": summary,
                "link": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}",
                "published": date_added + "T00:00:00+00:00" if date_added else datetime.now(timezone.utc).isoformat(),
                "category": "Cyber - Exploits & CVEs",
                "confidence": 10,
                "tags": ["kev", "cisa", "actively_exploited"],
                "in_kev": True,
                "cves": [cve_id] if cve_id else [],
                "severity": "CRITICAL",
            })

            if len(articles) >= limit:
                break

        logger.info(f"CISA KEV: {len(articles)} vulnérabilités récentes récupérées")
        return articles


# ---------------------------------------------------------------------------
# ACLED API
# ---------------------------------------------------------------------------

class ACLEDCollector(_BaseAPICollector):
    """Collecteur pour l'API ACLED (conflits armés).

    Nécessite une clé API ACLED (gratuit pour la recherche).
    Voir : https://developer.acleddata.com/

    Args:
        api_key: Clé API ACLED.
        email: Email associé au compte ACLED (requis pour l'authentification).

    Example:
        >>> collector = ACLEDCollector(api_key="xxx", email="user@example.com")
        >>> articles = collector.fetch(country="Ukraine", limit=50)
    """

    _API_BASE = "https://api.acleddata.com/acled/read"

    def __init__(self, api_key: str, email: str, timeout: int = 20) -> None:
        super().__init__(timeout=timeout, api_key=api_key)
        self.email = email

    def fetch(
        self,
        country: Optional[str] = None,
        region: Optional[int] = None,
        days_back: int = 7,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Récupère les événements de conflit récents.

        Args:
            country: Filtrer par pays (ex: "Ukraine").
            region: Filtrer par région ACLED (ex: 11 = Europe de l'Est).
            days_back: Nombre de jours à couvrir.
            limit: Nombre maximum d'événements.

        Returns:
            Liste de dicts articles normalisés.
        """
        if not self.api_key:
            logger.warning("ACLED API : clé API manquante")
            return []

        since = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%d")

        params: Dict[str, Any] = {
            "key": self.api_key,
            "email": self.email,
            "event_date": since,
            "event_date_where": ">=",
            "limit": limit,
            "fields": "event_date|event_type|actor1|actor2|country|location|notes|fatalities",
        }
        if country:
            params["country"] = country
        if region:
            params["region"] = region

        data = self._get(self._API_BASE, params=params)
        if not data or "data" not in data:
            return []

        articles = []
        for event in data["data"]:
            country_name = event.get("country", "Unknown")
            location = event.get("location", "")
            event_type = event.get("event_type", "Event")
            actor1 = event.get("actor1", "")
            actor2 = event.get("actor2", "")
            notes = event.get("notes", "")
            fatalities = event.get("fatalities", 0)
            event_date = event.get("event_date", "")

            actors = [a for a in [actor1, actor2] if a]
            title = f"[ACLED] {event_type} — {location}, {country_name}"
            summary = f"{notes[:300]} | Acteurs: {', '.join(actors)} | Victimes: {fatalities}"

            articles.append({
                "source": f"ACLED — {country_name}",
                "source_url": "https://acleddata.com",
                "source_type": "api",
                "title": title,
                "summary": summary,
                "link": "https://acleddata.com/data-export-tool/",
                "published": event_date + "T00:00:00+00:00" if event_date else datetime.now(timezone.utc).isoformat(),
                "category": "Strategic - Conflicts & Battlefield",
                "confidence": 8,
                "tags": ["acled", "conflict", event_type.lower().replace(" ", "_")],
                "actors": actors,
                "conflict_related": True,
            })

        logger.info(f"ACLED: {len(articles)} événements récupérés")
        return articles


# ---------------------------------------------------------------------------
# Ransomware.live API
# ---------------------------------------------------------------------------

class RansomwareLiveCollector(_BaseAPICollector):
    """Collecteur pour l'API Ransomware.live.

    API publique, sans clé requise.

    Example:
        >>> collector = RansomwareLiveCollector()
        >>> articles = collector.fetch(limit=20)
    """

    _API_URL = "https://www.ransomware.live/api/recentvictims"

    def fetch(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Récupère les victimes ransomware récentes.

        Args:
            limit: Nombre maximum de victimes.

        Returns:
            Liste de dicts articles normalisés.
        """
        data = self._get(self._API_URL)
        if not isinstance(data, list):
            return []

        articles = []
        for victim in data[:limit]:
            group = victim.get("group_name", "Unknown Group")
            post_title = victim.get("post_title", "Unknown Victim")
            country = victim.get("country", "?")
            website = victim.get("website", "")
            post_url = victim.get("post_url", "https://ransomware.live")
            discovered = victim.get("discovered", datetime.now(timezone.utc).isoformat())

            title = f"[Ransomware] {group} → {post_title}"
            summary = f"Pays: {country} | Site: {website}"

            articles.append({
                "source": f"Ransomware.live — {group}",
                "source_url": post_url,
                "source_type": "api",
                "title": title,
                "summary": summary,
                "link": post_url,
                "published": discovered,
                "category": "Offensive - Malware & Ransomware",
                "confidence": 8,
                "tags": [f"group:{group.lower()}", "ransomware", "victim"],
                "ransomware_related": True,
                "darkweb_related": True,
            })

        logger.info(f"Ransomware.live: {len(articles)} victimes récupérées")
        return articles


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_api_collectors(config: Any) -> List[_BaseAPICollector]:
    """Instancie les collecteurs API selon la configuration.

    Args:
        config: Objet de configuration FULCRUM.

    Returns:
        Liste de collecteurs API instanciés et prêts.
    """
    collectors = []

    # CISA KEV (toujours actif)
    collectors.append(CISAKevCollector())

    # Ransomware.live (toujours actif)
    collectors.append(RansomwareLiveCollector())

    # ACLED (si clé disponible)
    acled_key = (config.get("api_keys.acled_key") if hasattr(config, "get") else None)
    acled_email = (config.get("api_keys.acled_email") if hasattr(config, "get") else None)
    if acled_key and acled_email:
        collectors.append(ACLEDCollector(api_key=acled_key, email=acled_email))
        logger.info("Collecteur ACLED activé")

    return collectors
