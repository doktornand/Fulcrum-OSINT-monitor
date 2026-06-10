"""
collectors/rss_collector.py — Collecteur RSS modulaire pour FULCRUM

Extrait du monolithe fulcrum2e.py avec améliorations :
  - Classe dédiée RSSCollector (séparation des responsabilités)
  - Rate limiting par host
  - Rotation User-Agent
  - Retry exponentiel configurable
  - Cache optionnel

Google-style docstrings.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
import threading
import time
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("FULCRUM.rss")

try:
    import feedparser
    FEEDPARSER_AVAILABLE = True
except ImportError:
    FEEDPARSER_AVAILABLE = False
    logger.warning("feedparser non installé — collecte RSS désactivée")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ---------------------------------------------------------------------------
# User-Agent Rotator
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/122.0.0.0",
]


def _random_ua() -> str:
    """Retourne un User-Agent aléatoire.

    Returns:
        String User-Agent.
    """
    return random.choice(_USER_AGENTS)


# ---------------------------------------------------------------------------
# Rate Limiter par host
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Rate limiter thread-safe par nom d'hôte.

    Args:
        max_rps: Requêtes maximum par seconde par hôte.
    """

    def __init__(self, max_rps: float = 2.0) -> None:
        self.min_interval = 1.0 / max_rps
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def acquire(self, host: str) -> None:
        """Attend si nécessaire pour respecter le rate limit.

        Args:
            host: Nom d'hôte cible.
        """
        with self._lock:
            now = time.time()
            elapsed = now - self._last.get(host, 0)
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last[host] = time.time()


# ---------------------------------------------------------------------------
# RSSCollector
# ---------------------------------------------------------------------------

class RSSCollector:
    """Collecteur de flux RSS avec gestion avancée des erreurs.

    Args:
        max_items_per_feed: Nombre max d'articles par flux.
        request_timeout: Timeout HTTP en secondes.
        retry_attempts: Nombre de tentatives en cas d'échec.
        retry_backoff: Facteur multiplicateur pour le backoff exponentiel.
        rate_limit_per_host: Requêtes max par seconde par hôte.
        concurrent_workers: Nombre de threads parallèles.
        user_agent_rotation: Active la rotation des User-Agents.
        cache: Objet cache optionnel (doit implémenter get/set).

    Example:
        >>> collector = RSSCollector(max_items_per_feed=20)
        >>> articles_raw = collector.fetch_feed("Cyber", {"name": "CISA", "url": "..."})
    """

    def __init__(
        self,
        max_items_per_feed: int = 25,
        request_timeout: int = 15,
        retry_attempts: int = 3,
        retry_backoff: float = 1.5,
        rate_limit_per_host: float = 2.0,
        concurrent_workers: int = 10,
        user_agent_rotation: bool = True,
        cache: Optional[Any] = None,
    ) -> None:
        self.max_items_per_feed = max_items_per_feed
        self.timeout = request_timeout
        self.retry_attempts = retry_attempts
        self.retry_backoff = retry_backoff
        self.concurrent_workers = concurrent_workers
        self.rotate_ua = user_agent_rotation
        self.cache = cache

        self._rate_limiter = _RateLimiter(rate_limit_per_host)
        self._session: Optional[Any] = None
        self._lock = threading.Lock()
        self.stats: Dict[str, Dict[str, int]] = {}

        if REQUESTS_AVAILABLE:
            self._session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=20, pool_maxsize=50
            )
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _get_headers(self) -> Dict[str, str]:
        """Construit les headers HTTP.

        Returns:
            Dict de headers.
        """
        ua = _random_ua() if self.rotate_ua else "FULCRUM/3.0"
        return {
            "User-Agent": ua,
            "Accept": "application/rss+xml, application/atom+xml, text/xml, */*",
            "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
        }

    def _fetch_url(self, url: str) -> Optional[str]:
        """Récupère le contenu d'une URL avec retry et rate limiting.

        Args:
            url: URL à récupérer.

        Returns:
            Contenu texte ou None en cas d'échec.
        """
        if not REQUESTS_AVAILABLE or not self._session:
            return None

        # Cache lookup
        if self.cache:
            cached = self.cache.get(f"rss:{url}")
            if cached:
                return cached

        host = urlparse(url).netloc
        self._rate_limiter.acquire(host)

        for attempt in range(self.retry_attempts):
            try:
                resp = self._session.get(
                    url, headers=self._get_headers(), timeout=self.timeout
                )
                resp.raise_for_status()

                if self.cache:
                    self.cache.set(f"rss:{url}", resp.text, ttl=3600)

                return resp.text

            except Exception as exc:
                if attempt < self.retry_attempts - 1:
                    wait = self.retry_backoff ** (attempt + 1)
                    logger.debug(f"Retry {attempt+1}/{self.retry_attempts} pour {url}: {exc}")
                    time.sleep(wait)
                else:
                    logger.debug(f"Échec définitif {url}: {exc}")

        return None

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def fetch_feed(
        self, category: str, source: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Récupère et parse un flux RSS.

        Args:
            category: Catégorie de la source.
            source: Dict de configuration de la source (name, url, confidence…).

        Returns:
            Liste de dicts représentant les articles bruts.
        """
        if not FEEDPARSER_AVAILABLE:
            return []

        source_name = source.get("name", "Unknown")
        url = source.get("url", "")
        max_items = source.get("max_items", self.max_items_per_feed)

        if not url:
            return []

        content = self._fetch_url(url)
        if not content:
            with self._lock:
                self.stats.setdefault(source_name, {"success": 0, "failed": 0})
                self.stats[source_name]["failed"] += 1
            return []

        try:
            feed = feedparser.parse(content)
        except Exception as exc:
            logger.error(f"Erreur parse {source_name}: {exc}")
            return []

        articles = []
        for entry in feed.entries[:max_items]:
            try:
                raw = self._entry_to_dict(entry, source, category)
                articles.append(raw)
            except Exception as exc:
                logger.debug(f"Erreur entrée {source_name}: {exc}")

        with self._lock:
            self.stats.setdefault(source_name, {"success": 0, "failed": 0})
            self.stats[source_name]["success"] += len(articles)

        return articles

    def _entry_to_dict(
        self, entry: Any, source: Dict[str, Any], category: str
    ) -> Dict[str, Any]:
        """Convertit une entrée feedparser en dict normalisé.

        Args:
            entry: Entrée feedparser.
            source: Config de la source.
            category: Catégorie de la source.

        Returns:
            Dict normalisé.
        """
        summary = (
            getattr(entry, "summary", "")
            or getattr(entry, "description", "")
            or ""
        )
        content_blocks = getattr(entry, "content", [])
        content_text = content_blocks[0].get("value", "") if content_blocks else ""

        return {
            "source": source.get("name", "Unknown"),
            "source_url": source.get("url", ""),
            "source_type": "rss",
            "title": self._clean(getattr(entry, "title", "Sans titre")),
            "summary": self._clean(summary),
            "content": self._clean(content_text, max_len=1000),
            "link": getattr(entry, "link", ""),
            "published": self._parse_date(entry),
            "category": category,
            "confidence": source.get("confidence", 5),
            "tags": list(source.get("tags", [])),
            "priority": source.get("priority"),
        }

    @staticmethod
    def _parse_date(entry: Any) -> str:
        """Extrait et normalise la date de publication.

        Args:
            entry: Entrée feedparser.

        Returns:
            Date ISO 8601.
        """
        for attr in ("published_parsed", "updated_parsed", "created_parsed"):
            t = getattr(entry, attr, None)
            if t and len(t) >= 6:
                try:
                    return datetime(*t[:6], tzinfo=timezone.utc).isoformat()
                except Exception:
                    pass

        for attr in ("published", "updated", "pubDate"):
            date_str = getattr(entry, attr, None)
            if date_str:
                for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"):
                    try:
                        return datetime.strptime(date_str, fmt).isoformat()
                    except ValueError:
                        pass
                try:
                    return datetime.fromisoformat(
                        date_str.replace("Z", "+00:00")
                    ).isoformat()
                except ValueError:
                    pass

        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _clean(text: Optional[str], max_len: int = 500) -> str:
        """Nettoie un texte HTML et limite sa longueur.

        Args:
            text: Texte brut potentiellement HTML.
            max_len: Longueur maximale en caractères.

        Returns:
            Texte nettoyé.
        """
        if not text:
            return ""
        clean = re.sub(r"<[^>]+>", "", str(text))
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean[:max_len]

    # ------------------------------------------------------------------
    # Collecte parallèle
    # ------------------------------------------------------------------

    def collect_categories(
        self, categories: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Collecte en parallèle toutes les catégories de sources.

        Args:
            categories: Liste de configurations de catégories.

        Returns:
            Liste de tous les articles collectés.
        """
        all_articles: List[Dict[str, Any]] = []

        for cat in categories:
            cat_name = cat.get("name", "Unknown")
            feeds = cat.get("feeds", [])

            if not feeds:
                continue

            logger.info(f"Collecte catégorie: {cat_name} ({len(feeds)} sources)")

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.concurrent_workers
            ) as executor:
                futures = {
                    executor.submit(self.fetch_feed, cat_name, src): src
                    for src in feeds
                }
                for future in concurrent.futures.as_completed(futures):
                    try:
                        articles = future.result()
                        with self._lock:
                            all_articles.extend(articles)
                    except Exception as exc:
                        logger.error(f"Erreur future: {exc}")

        return all_articles
