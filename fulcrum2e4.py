"""
FULCRUM — Full Spectrum Intelligence Fusion Platform
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Fusion des capacités : Wonitor (Cyber) + StratWatch (Géostratégique) + LeakHunter (Offensive)

Fonctionnalités unifiées :
  • Intelligence Cyber : CVEs, Exploits, Malware, Threat Intel
  • Intelligence Stratégique : Défense, Nucléaire, Aérospatiale, Conflits
  • Intelligence Offensive : Data Leaks, Breaches, Dark Web, Ransomware
  • Scoring composite : RISK_SCORE (0-100) + STRAT_SCORE (0-100)
  • Détection multi-domaines avec corrélation automatique
  • Dashboard "Ops Room" style renseignement militaire
  • Alertes en temps réel, rapports PDF, API REST
  • Cache Redis, rate limiting, proxy rotation

Usage :
  python fulcrum.py --mode cyber|strat|leak|fusion --export html|json|csv|pdf
  python fulcrum.py --dashboard --port 8080 --theme ops
  python fulcrum.py --alert-webhook slack --critical-only
  python fulcrum.py --api --port 5000

Dépendances :
  pip install feedparser requests rich beautifulsoup4 lxml pandas plotly
  pip install redis celery pdfkit markdown watchdog pyyaml
  pip install flask flask-cors flask-socketio eventlet
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import asyncio
import hashlib
import json
import csv
import re
import os
import sys
import argparse
import threading
import time
import random
import logging
import warnings
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Set, Any, Union, Generator
from urllib.parse import urlparse
from collections import Counter, defaultdict
from functools import wraps
from enum import Enum
import queue

# Suppress warnings
warnings.filterwarnings('ignore')

# ──────────────────────────────────────────────────────────────────────────────
# CORE DEPENDENCIES (optional with fallbacks)
# ──────────────────────────────────────────────────────────────────────────────

try:
    import feedparser
    FEEDPARSER_AVAILABLE = True
except ImportError:
    FEEDPARSER_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.columns import Columns
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback dummy console
    class Console:
        def print(self, *args, **kwargs): pass

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
# NEW MODULES (modular refactor — graceful fallback if unavailable)
# ──────────────────────────────────────────────────────────────────────────────

_MODULE_BASE = Path(__file__).parent

try:
    from analyzers.ioc_extractor import IOCExtractor as _IOCExtractor
    _IOC_EXTRACTOR = _IOCExtractor()
    IOC_EXTRACTOR_AVAILABLE = True
except Exception:
    _IOC_EXTRACTOR = None
    IOC_EXTRACTOR_AVAILABLE = False

try:
    from analyzers.scoring_engine import ScoringEngine as _ScoringEngine, compute_freshness_bonus
    _SCORING_ENGINE = _ScoringEngine()
    SCORING_ENGINE_AVAILABLE = True
except Exception:
    _SCORING_ENGINE = None
    SCORING_ENGINE_AVAILABLE = False

try:
    from analyzers.correlator import FuzzyDeduplicator, ClusterDetector, build_timeline
    CORRELATOR_AVAILABLE = True
except Exception:
    CORRELATOR_AVAILABLE = False

try:
    from persistence.sqlite_store import SQLiteStore
    SQLITE_STORE_AVAILABLE = True
except Exception:
    SQLITE_STORE_AVAILABLE = False

try:
    from alerts.webhook_manager import WebhookManager
    WEBHOOK_MANAGER_AVAILABLE = True
except Exception:
    WEBHOOK_MANAGER_AVAILABLE = False

try:
    from exporters.html_dashboard import HTMLDashboard
    HTML_DASHBOARD_AVAILABLE = True
except Exception:
    HTML_DASHBOARD_AVAILABLE = False

try:
    from exporters.json_exporter import JSONExporter
    JSON_EXPORTER_AVAILABLE = True
except Exception:
    JSON_EXPORTER_AVAILABLE = False

try:
    from analyzers.takeaway_generator import TakeawayGenerator
    TAKEAWAY_AVAILABLE = True
except Exception:
    TAKEAWAY_AVAILABLE = False

try:
    from exporters.report_generator import ReportGenerator
    REPORT_GENERATOR_AVAILABLE = True
except Exception:
    REPORT_GENERATOR_AVAILABLE = False

try:
    from orchestration.scheduler import FulcrumScheduler
    SCHEDULER_AVAILABLE = True
except Exception:
    SCHEDULER_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — CORRECTION : utilisation de ConfigLoader
# ──────────────────────────────────────────────────────────────────────────────

try:
    from config_loader import ConfigLoader
    CONFIG_LOADER_AVAILABLE = True
except ImportError:
    CONFIG_LOADER_AVAILABLE = False


class Config:
    """Configuration centrale avec chargement multi-formats (JSON/YAML).

    CORRECTION v2e2 : Intègre ConfigLoader pour validation Pydantic et profils.
    Fallback sur la config interne si ConfigLoader n'est pas disponible.
    """

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path(__file__).parent / "fulcrum_config.yml"
        self._loader = None
        self.data = {}

        # Essayer ConfigLoader d'abord (validation Pydantic, profils, etc.)
        if CONFIG_LOADER_AVAILABLE:
            try:
                self._loader = ConfigLoader(self.config_path)
                self.data = self._loader.raw if hasattr(self._loader, 'raw') else {}
                if hasattr(self._loader, 'config') and self._loader.config is not None:
                    self._pydantic_config = self._loader.config
                else:
                    self._pydantic_config = None
            except Exception as e:
                print(f"⚠ ConfigLoader error: {e}, using internal fallback")
                self._pydantic_config = None
                self.data = self._load_internal_config()
        else:
            self._pydantic_config = None
            self.data = self._load_internal_config()

        self._setup_logging()
        self._setup_cache()

    def _load_internal_config(self) -> dict:
        """Charge la configuration interne (fallback si ConfigLoader échoue)."""
        default_config = {
            "app": {
                "name": "FULCRUM Intelligence Platform",
                "version": "3.0",
                "description": "Full Spectrum Intelligence Fusion Center",
                "theme": "ops",
                "timezone": "UTC",
                "debug": False
            },
            "collection": {
                "max_items_per_feed": 25,
                "request_timeout": 15,
                "retry_attempts": 3,
                "retry_backoff": 1.5,
                "concurrent_workers": 10,
                "rate_limit_per_host": 2,
                "user_agent_rotation": True,
                "proxy_rotation": False,
                "deduplicate": True,
                "scraping_enabled": True
            },
            "cache": {
                "enabled": True,
                "type": "redis",
                "redis_url": "redis://localhost:6379/0",
                "ttl_seconds": 3600,
                "memory_max_items": 1000
            },
            "intelligence": {
                "scoring": {
                    "risk_weights": {
                        "critical": 40,
                        "exploit": 15,
                        "kev": 15,
                        "ransomware": 12,
                        "apt": 10,
                        "darkweb": 8
                    },
                    "strat_weights": {
                        "nuclear": 25,
                        "conflict": 15,
                        "weapons": 10,
                        "aerospace": 8,
                        "sanctions": 7,
                        "intel": 10
                    }
                },
                "thresholds": {
                    "critical_score": 85,
                    "high_score": 70,
                    "medium_score": 50,
                    "flash_threshold": 90
                }
            },
            "export": {
                "default_format": "html",
                "paths": {
                    "json": "fulcrum_export.json",
                    "csv": "fulcrum_export.csv",
                    "html": "fulcrum_dashboard.html",
                    "pdf": "fulcrum_report.pdf"
                },
                "auto_generate": True
            },
            "alerts": {
                "webhooks": [],
                "telegram_bot_token": None,
                "telegram_chat_id": None,
                "slack_webhook": None,
                "discord_webhook": None,
                "critical_only": False
            },
            "api": {
                "enabled": False,
                "host": "0.0.0.0",
                "port": 5000,
                "cors": True,
                "api_key": None
            },
            "categories": []
        }

        if self.config_path and self.config_path.exists():
            try:
                if self.config_path.suffix in ['.yml', '.yaml']:
                    import yaml
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        user_config = yaml.safe_load(f)
                else:
                    with open(self.config_path, 'r', encoding='utf-8') as f:
                        user_config = json.load(f)

                default_config = self._deep_merge(default_config, user_config)
            except Exception as e:
                print(f"⚠ Config load error: {e}, using defaults")

        return default_config

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = self._deep_merge(base[key], value)
            else:
                base[key] = value
        return base

    def _setup_logging(self):
        """Configure structured logging"""
        logging.basicConfig(
            level=logging.DEBUG if self.data.get('app', {}).get('debug', False) else logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fulcrum.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("FULCRUM")

    def _setup_cache(self):
        """Configure cache backend"""
        self.cache = None
        cache_cfg = self.data.get('cache', {})
        if cache_cfg.get('enabled', True):
            if cache_cfg.get('type') == 'redis' and REDIS_AVAILABLE:
                try:
                    self.cache = redis.Redis.from_url(cache_cfg.get('redis_url', 'redis://localhost:6379/0'))
                    self.cache.ping()
                    self.logger.info("Redis cache initialized")
                except Exception as e:
                    self.logger.warning(f"Redis connection failed: {e}, using memory cache")
                    self.cache = MemoryCache(cache_cfg.get('memory_max_items', 1000))
            else:
                self.cache = MemoryCache(cache_cfg.get('memory_max_items', 1000))

    def get(self, key: str, default=None):
        """Get config value by dot notation.

        CORRECTION : Supporte à la fois l'objet Pydantic (via ConfigLoader)
        et le dict interne.
        """
        # Priorité à ConfigLoader/Pydantic si disponible
        if self._pydantic_config is not None:
            try:
                result = self._pydantic_config.get(key, default)
                if result is not None:
                    # CORRECTION : Convertir les listes de modèles Pydantic en listes de dicts
                    # pour maintenir la compatibilité avec le code existant utilisant .get()
                    if isinstance(result, list) and len(result) > 0:
                        if hasattr(result[0], 'model_dump'):  # Pydantic v2
                            return [item.model_dump() for item in result]
                        elif hasattr(result[0], 'dict'):      # Pydantic v1 (fallback)
                            return [item.dict() for item in result]
                    return result
            except Exception:
                pass

        # Fallback sur le dict interne
        keys = key.split('.')
        value = self.data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def __getitem__(self, key):
        return self.get(key)

    @property
    def profiles(self) -> Dict[str, Any]:
        """Retourne les profils opérationnels définis dans la config."""
        if self._pydantic_config is not None:
            try:
                return getattr(self._pydantic_config, 'profiles', {})
            except Exception:
                pass
        return self.data.get('profiles', {})

    def get_profile_categories(self, profile_name: str) -> List[str]:
        """Retourne les catégories actives pour un profil donné."""
        profiles = self.profiles
        if profile_name in profiles:
            active = profiles[profile_name].get('active_categories', [])
            if active == "all":
                return [c.get('name') for c in self.data.get('categories', [])]
            return active
        return []


class MemoryCache:
    """Simple in-memory cache fallback"""
    def __init__(self, max_items=1000):
        self.cache = {}
        self.max_items = max_items

    def get(self, key):
        item = self.cache.get(key)
        if item and item['expires'] > time.time():
            return item['value']
        return None

    def set(self, key, value, ttl=3600):
        if len(self.cache) >= self.max_items:
            oldest = min(self.cache.keys(), key=lambda k: self.cache[k]['expires'])
            del self.cache[oldest]
        self.cache[key] = {'value': value, 'expires': time.time() + ttl}

    def delete(self, key):
        self.cache.pop(key, None)


# ──────────────────────────────────────────────────────────────────────────────
# INTELLIGENCE PATTERNS DATABASE
# ──────────────────────────────────────────────────────────────────────────────

class IntelligencePatterns:
    """Base de connaissances des patterns d'intelligence"""

    NUCLEAR_KEYWORDS = {
        'nuclear', 'nucléaire', 'nuke', 'warhead', 'ogive', 'icbm', 'slbm',
        'hypersonic', 'ballistic missile', 'missile balistique', 'plutonium',
        'uranium enrichment', 'enrichissement', 'centrifuge', 'reprocessing',
        'deterrence', 'dissuasion', 'first strike', 'triad', 'new start',
        'nonproliferation', 'prolifération', 'dirty bomb', 'nuclear test',
        'essai nucléaire', 'yield', 'kiloton', 'megaton', 'fissile',
        'iaea safeguards', 'breakout', 'tactical nuclear'
    }

    CONFLICT_KEYWORDS = {
        'airstrike', 'frappe', 'offensive', 'assault', 'shelling', 'bombardment',
        'front line', 'ceasefire', 'escalation', 'invasion', 'incursion',
        'counteroffensive', 'contre-offensive', 'attrition', 'drone strike',
        'cruise missile', 'precision strike', 'casualties', 'breakthrough',
        'encirclement', 'siege', 'amphibious', 'combined arms', 'insurgency',
        'guerrilla', 'terrorism', 'counterterrorism'
    }

    WEAPONS_KEYWORDS = {
        'f-35', 'f-22', 'rafale', 'eurofighter', 'su-57', 'j-20',
        'abrams', 'leopard', 'leclerc', 't-90', 'challenger',
        'himars', 'atacms', 'patriot', 's-400', 's-500', 'thaad', 'iron dome',
        'javelin', 'nlaw', 'stinger', 'manpads', 'bayraktar', 'shahed',
        'submarine', 'aircraft carrier', 'destroyer', 'frigate',
        'hypersonic glide', 'kinzhal', 'zircon', 'avangard'
    }

    ACTORS_KEYWORDS = {
        'russia', 'russie', 'ukraine', 'china', 'chine', 'north korea',
        'corée du nord', 'iran', 'israel', 'israël', 'usa', 'united states',
        'nato', 'otan', 'france', 'germany', 'allemagne', 'uk', 'royaume-uni',
        'hamas', 'hezbollah', 'houthi', 'wagner', 'isis', 'daesh', 'al-qaeda',
        'pmc', 'mercenary', 'milice', 'proxy',
        'pentagon', 'state department', 'kremlin', 'pla', 'irgc', 'mossad',
        'cia', 'dgse', 'bnd', 'mi6', 'gru', 'fsb', 'svr', 'nsa', 'gchq'
    }

    EXPLOIT_KEYWORDS = {
        '0day', 'zero-day', 'poc', 'proof-of-concept', 'exploit', 'rce',
        'remote code execution', 'weaponized', 'in-the-wild', 'actively exploited',
        'metasploit', 'cobalt strike', 'exploit kit', 'cve', 'vulnerability',
        'buffer overflow', 'heap overflow', 'use-after-free', 'privilege escalation'
    }

    RANSOMWARE_KEYWORDS = {
        'ransomware', 'lockbit', 'blackcat', 'alphv', 'clop', 'akira',
        'blackbasta', 'rhysida', 'play ransomware', 'royal ransomware',
        'scattered spider', 'double extortion', 'data extortion', 'darkside',
        'revil', 'sodinokibi', 'maze', 'conti', 'hive', 'lorenz'
    }

    APT_KEYWORDS = {
        'apt', 'nation-state', 'state-sponsored', 'lazarus', 'fancy bear',
        'cozy bear', 'volt typhoon', 'salt typhoon', 'sandworm', 'turla',
        'equation group', 'kimsuky', 'mustang panda', 'apt28', 'apt29',
        'charming kitten', 'phosphorus', 'muddywater', 'darkhotel', 'oceanlotus'
    }

    LEAK_KEYWORDS = {
        'data breach', 'leaked', 'dump', 'database exposed', 'exposed records',
        'credentials', 'plaintext passwords', 'personal data', 'pii exposed',
        'millions of records', 'unauthorized access', 'extortion', 'dark web',
        'breach', 'compromised', 'stolen data', 'data theft', 'information leak',
        'credentials dump', 'password leak', 'email leak', 'customer data'
    }

    AEROSPACE_KEYWORDS = {
        'launch', 'lancement', 'satellite', 'orbit', 'orbite', 'reentry',
        'space debris', 'asat', 'anti-satellite', 'starlink', 'gps jamming',
        'space force', 'reconnaissance satellite', 'spy satellite',
        'rocket', 'fusée', 'space station', 'lunar', 'cislunar'
    }

    THEATRES = {
        'ukraine': ['ukraine', 'russia', 'russie', 'dnipro', 'kharkiv', 'kherson', 'crimea', 'donbas'],
        'middle-east': ['israel', 'gaza', 'hamas', 'hezbollah', 'iran', 'yemen', 'houthi', 'lebanon', 'syria', 'iraq'],
        'asia-pacific': ['china', 'taiwan', 'south china sea', 'north korea', 'corée', 'indo-pacific', 'japan', 'korea'],
        'africa': ['sahel', 'mali', 'niger', 'burkina', 'wagner', 'somalia', 'sudan', 'ethiopia', 'libya'],
        'europe': ['nato', 'eu', 'european union', 'baltic', 'poland', 'germany', 'france', 'uk', 'balkans']
    }

    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    CVSS_PATTERN = re.compile(r'cvss[v\s:]*(\d+\.\d+)', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
    HASH_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
    HASH_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
    HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.IGNORECASE)
    URL_PATTERN = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+')
    BTC_PATTERN = re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
    ONION_PATTERN = re.compile(r'[a-z2-7]{16,56}\.onion', re.IGNORECASE)

    @classmethod
    def extract_iocs(cls, text: str) -> Dict[str, List[str]]:
        iocs = defaultdict(list)

        if cls.IPV4_PATTERN:
            iocs['ipv4'].extend(cls.IPV4_PATTERN.findall(text))
        if cls.IPV6_PATTERN:
            iocs['ipv6'].extend(cls.IPV6_PATTERN.findall(text))
        if cls.HASH_MD5:
            iocs['md5'].extend(cls.HASH_MD5.findall(text))
        if cls.HASH_SHA1:
            iocs['sha1'].extend(cls.HASH_SHA1.findall(text))
        if cls.HASH_SHA256:
            iocs['sha256'].extend(cls.HASH_SHA256.findall(text))
        if cls.DOMAIN_PATTERN:
            iocs['domain'].extend(cls.DOMAIN_PATTERN.findall(text))
        if cls.URL_PATTERN:
            iocs['url'].extend(cls.URL_PATTERN.findall(text))
        if cls.EMAIL_PATTERN:
            iocs['email'].extend(cls.EMAIL_PATTERN.findall(text))
        if cls.BTC_PATTERN:
            iocs['btc'].extend(cls.BTC_PATTERN.findall(text))
        if cls.ONION_PATTERN:
            iocs['onion'].extend(cls.ONION_PATTERN.findall(text))

        for key in iocs:
            iocs[key] = list(set(iocs[key]))[:10]

        return dict(iocs)

    @classmethod
    def extract_actors(cls, text: str) -> List[str]:
        found = []
        for actor in cls.ACTORS_KEYWORDS:
            if re.search(r'\b' + re.escape(actor) + r'\b', text.lower()):
                found.append(actor.title())
        return list(set(found))[:10]

    @classmethod
    def extract_weapons(cls, text: str) -> List[str]:
        found = []
        for weapon in cls.WEAPONS_KEYWORDS:
            if re.search(r'\b' + re.escape(weapon) + r'\b', text.lower()):
                found.append(weapon.upper())
        return list(set(found))[:8]

    @classmethod
    def detect_theatres(cls, text: str) -> List[str]:
        text_lower = text.lower()
        theatres = []
        for theatre, keywords in cls.THEATRES.items():
            if any(kw in text_lower for kw in keywords):
                theatres.append(theatre)
        return theatres


# ──────────────────────────────────────────────────────────────────────────────
# CORE DATA MODEL
# ──────────────────────────────────────────────────────────────────────────────

class IntelligenceDomain(Enum):
    CYBER = "cyber"
    STRATEGIC = "strategic"
    OFFENSIVE = "offensive"
    FUSION = "fusion"


@dataclass
class IntelligenceArticle:
    """Modèle de données unifié pour tous les types d'intelligence"""

    id: str = field(default_factory=lambda: hashlib.md5(str(time.time()).encode()).hexdigest()[:12])
    source: str = ""
    source_url: str = ""
    source_type: str = "rss"

    title: str = ""
    summary: str = ""
    content: str = ""
    link: str = ""
    published: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    category: str = ""
    domain: IntelligenceDomain = IntelligenceDomain.CYBER
    subcategory: str = ""
    tags: List[str] = field(default_factory=list)

    risk_score: int = 0
    strat_score: int = 0
    severity: str = "INFO"

    exploit_available: bool = False
    ransomware_related: bool = False
    apt_related: bool = False
    in_kev: bool = False

    nuclear_related: bool = False
    conflict_related: bool = False
    aerospace_related: bool = False
    weapons_related: bool = False
    sanctions_related: bool = False
    intel_related: bool = False

    leak_related: bool = False
    darkweb_related: bool = False
    extortion_related: bool = False
    leak_records: Optional[str] = None
    leak_volume: Optional[str] = None
    pii_types: List[str] = field(default_factory=list)

    cves: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    actors: List[str] = field(default_factory=list)
    weapon_systems: List[str] = field(default_factory=list)
    theatres: List[str] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)

    content_hash: str = ""
    confidence: int = 5
    processed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_score_breakdown: Dict[str, Any] = field(default_factory=dict)
    strat_score_breakdown: Dict[str, Any] = field(default_factory=dict)
    simhash: int = 0

    def __post_init__(self):
        self.content_hash = self._compute_hash()
        self._compute_simhash()
        self._enrich_all()

    def _compute_hash(self) -> str:
        normalized = re.sub(r'\W+', '', (self.title + self.source)[:100].lower())
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    def _compute_simhash(self) -> None:
        """Calcule le SimHash 64-bit du titre + résumé (déduplication fuzzy)."""
        if CORRELATOR_AVAILABLE:
            try:
                from analyzers.correlator import compute_simhash
                raw = compute_simhash(f"{self.title} {self.summary}")
                # CORRECTION : clamp à 63-bit pour compatibilité SQLite INTEGER signé
                self.simhash = raw & 0x7FFFFFFFFFFFFFFF if raw else 0
            except Exception:
                self.simhash = 0

    def _enrich_all(self):
        full_text = f"{self.title} {self.summary} {self.content}"
        full_lower = full_text.lower()

        self.cves = list(set(IntelligencePatterns.CVE_PATTERN.findall(full_text)))[:10]
        cvss_match = IntelligencePatterns.CVSS_PATTERN.search(full_text)
        if cvss_match:
            try:
                self.cvss_score = float(cvss_match.group(1))
            except:
                pass

        words = set(re.findall(r'\b\w+\b', full_lower))

        self.exploit_available = bool(IntelligencePatterns.EXPLOIT_KEYWORDS & words)
        self.ransomware_related = bool(IntelligencePatterns.RANSOMWARE_KEYWORDS & words)
        self.apt_related = bool(IntelligencePatterns.APT_KEYWORDS & words)
        self.leak_related = bool(IntelligencePatterns.LEAK_KEYWORDS & words)

        self.nuclear_related = bool(IntelligencePatterns.NUCLEAR_KEYWORDS & words)
        self.conflict_related = bool(IntelligencePatterns.CONFLICT_KEYWORDS & words)
        self.weapons_related = bool(IntelligencePatterns.WEAPONS_KEYWORDS & words)
        self.aerospace_related = bool(IntelligencePatterns.AEROSPACE_KEYWORDS & words)

        self.actors = IntelligencePatterns.extract_actors(full_text)
        self.weapon_systems = IntelligencePatterns.extract_weapons(full_text)
        self.theatres = IntelligencePatterns.detect_theatres(full_text)

        if IOC_EXTRACTOR_AVAILABLE and _IOC_EXTRACTOR:
            self.iocs = _IOC_EXTRACTOR.extract(full_text)
        else:
            self.iocs = IntelligencePatterns.extract_iocs(full_text)

        if self.leak_related:
            self._enrich_leak_data(full_text)

        self._compute_severity()
        self._compute_risk_score()
        self._compute_strat_score()

    def _enrich_leak_data(self, text: str):
        vol_patterns = [
            (r'(\d+(?:\.\d+)?)\s*(?:million|m)\s*(?:records?|users?|accounts?)', 1_000_000),
            (r'(\d+(?:\.\d+)?)\s*(?:billion|b)\s*(?:records?|users?|accounts?)', 1_000_000_000),
            (r'(\d+(?:\.\d+)?)\s*(?:thousand|k)\s*(?:records?|users?|accounts?)', 1_000),
            (r'(\d+(?:,\d+)?)\s*(?:records?|users?|accounts?)', 1)
        ]

        for pattern, multiplier in vol_patterns:
            match = re.search(pattern, text.lower())
            if match:
                try:
                    num = float(match.group(1).replace(',', ''))
                    total = int(num * multiplier)
                    if total >= 1_000_000:
                        self.leak_records = f"{total/1_000_000:.1f}M records"
                    elif total >= 1_000:
                        self.leak_records = f"{total/1_000:.1f}K records"
                    else:
                        self.leak_records = f"{total} records"
                    break
                except:
                    pass

        pii_keywords = ['password', 'email', 'ssn', 'social security', 'credit card',
                        'passport', 'address', 'phone', 'medical', 'health']
        self.pii_types = [p for p in pii_keywords if p in text.lower()]

        self.darkweb_related = any(kw in text.lower() for kw in ['dark web', 'darkweb', 'tor', '.onion', 'underground'])
        self.extortion_related = any(kw in text.lower() for kw in ['extortion', 'ransom', 'blackmail'])

    def _compute_severity(self):
        if SCORING_ENGINE_AVAILABLE and _SCORING_ENGINE:
            self.severity = _SCORING_ENGINE.compute_severity(
                self.title, self.summary, self.cvss_score
            )
            return

        # Fallback legacy
        text = f"{self.title} {self.summary}".upper()
        if any(x in text for x in ['NUCLEAR LAUNCH', 'BALLISTIC MISSILE', 'DECLARATION OF WAR',
                                   'ACTIVE SHOOTER', 'TERROR ATTACK', 'STATE OF EMERGENCY']):
            self.severity = "FLASH"
        elif any(x in text for x in ['CRITICAL', 'CVE-202', 'RCE', '0DAY', 'ZERO-DAY',
                                     'NUCLEAR', 'MISSILE TEST', 'WARHEAD']):
            self.severity = "CRITICAL"
        elif any(x in text for x in ['HIGH', 'URGENT', 'ACTIVELY EXPLOITED', 'ESCALATION',
                                     'INVASION', 'AIRSTRIKE']):
            self.severity = "HIGH"
        elif any(x in text for x in ['MEDIUM', 'MODERATE', 'BREACH', 'LEAK', 'SANCTIONS',
                                     'MILITARY EXERCISE', 'DEPLOYMENT']):
            self.severity = "MEDIUM"
        elif any(x in text for x in ['ANALYSIS', 'REPORT', 'ASSESSMENT', 'STRATEGY',
                                     'MODERNIZATION', 'PROCUREMENT']):
            self.severity = "WATCH"
        else:
            self.severity = "INFO"

        if self.cvss_score:
            if self.cvss_score >= 9.0:
                self.severity = "CRITICAL"
            elif self.cvss_score >= 7.0:
                self.severity = "HIGH"
            elif self.cvss_score >= 4.0:
                self.severity = "MEDIUM"

    def _compute_risk_score(self):
        if SCORING_ENGINE_AVAILABLE and _SCORING_ENGINE:
            breakdown = _SCORING_ENGINE.compute_risk_score(
                severity=self.severity,
                source_name=self.source,
                published_iso=self.published,
                exploit_available=self.exploit_available,
                in_kev=self.in_kev,
                ransomware_related=self.ransomware_related,
                apt_related=self.apt_related,
                darkweb_related=self.darkweb_related,
                extortion_related=self.extortion_related,
                leak_records=self.leak_records,
                cvss_score=self.cvss_score,
                confidence=self.confidence,
            )
            self.risk_score = breakdown.total
            self.risk_score_breakdown = breakdown.to_dict()
            return

        # Fallback legacy
        weights = {"CRITICAL": 45, "HIGH": 30, "MEDIUM": 20, "LOW": 10, "INFO": 5, "FLASH": 55}
        score = weights.get(self.severity, 10)
        if self.exploit_available:
            score += 12
        if self.in_kev:
            score += 12
        if self.ransomware_related:
            score += 10
        if self.apt_related:
            score += 8
        if self.darkweb_related:
            score += 7
        if self.extortion_related:
            score += 8
        if self.leak_records and 'M' in self.leak_records:
            try:
                num = float(self.leak_records.replace('M records', '').strip())
                score += 15 if num > 100 else 10 if num > 10 else 5
            except Exception:
                score += 5
        if self.cvss_score:
            score += int(self.cvss_score * 2)
        self.risk_score = min(score, 100)

    def _compute_strat_score(self):
        if SCORING_ENGINE_AVAILABLE and _SCORING_ENGINE:
            breakdown = _SCORING_ENGINE.compute_strat_score(
                severity=self.severity,
                nuclear_related=self.nuclear_related,
                conflict_related=self.conflict_related,
                weapons_related=self.weapons_related,
                aerospace_related=self.aerospace_related,
                sanctions_related=self.sanctions_related,
                intel_related=self.intel_related,
                actors_count=len(self.actors),
                theatres_count=len(self.theatres),
                source_name=self.source,
                published_iso=self.published,
            )
            self.strat_score = breakdown.total
            self.strat_score_breakdown = breakdown.to_dict()
            return

        # Fallback legacy
        score = 0
        if self.nuclear_related:
            score += 25
        if self.conflict_related:
            score += 15
        if self.weapons_related:
            score += 10
        if self.aerospace_related:
            score += 8
        if self.sanctions_related:
            score += 7
        if self.intel_related:
            score += 8
        if len(self.actors) >= 3:
            score += 5
        elif len(self.actors) >= 1:
            score += 2
        if len(self.theatres) >= 2:
            score += 5
        severity_boost = {"FLASH": 20, "CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "WATCH": 3}
        score += severity_boost.get(self.severity, 0)
        self.strat_score = min(score, 100)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['domain'] = self.domain.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> 'IntelligenceArticle':
        if 'domain' in data and isinstance(data['domain'], str):
            data['domain'] = IntelligenceDomain(data['domain'])
        return cls(**data)


# ──────────────────────────────────────────────────────────────────────────────
# COLLECTORS (Unified Feed Management)
# ──────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, max_requests_per_second=2):
        self.max_requests = max_requests_per_second
        self.last_request = {}
        self.lock = threading.Lock()

    def acquire(self, host: str):
        with self.lock:
            now = time.time()
            last = self.last_request.get(host, 0)
            elapsed = now - last
            if elapsed < 1.0 / self.max_requests:
                time.sleep((1.0 / self.max_requests) - elapsed)
            self.last_request[host] = time.time()


class UserAgentRotator:
    AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    ]

    @classmethod
    def get(cls) -> str:
        return random.choice(cls.AGENTS)


class UnifiedCollector:
    def __init__(self, config: Config):
        self.config = config
        self.console = Console() if RICH_AVAILABLE else None
        self.rate_limiter = RateLimiter(config.get('collection.rate_limit_per_host', 2))
        self.user_agent_rotation = config.get('collection.user_agent_rotation', True)
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        self.articles: List[IntelligenceArticle] = []
        self.lock = threading.Lock()
        self.stats = defaultdict(lambda: {"success": 0, "failed": 0, "timeout": 0})

        if self.session:
            adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=50)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/rss+xml, application/atom+xml, text/xml, application/xml, */*",
            "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        if self.user_agent_rotation:
            headers["User-Agent"] = UserAgentRotator.get()
        else:
            headers["User-Agent"] = self.config.get('app.user_agent', 'FULCRUM/3.0')

        return headers

    def _fetch_url(self, url: str, timeout: int = None) -> Optional[str]:
        if not REQUESTS_AVAILABLE:
            return None

        if self.config.cache:
            cached = self.config.cache.get(f"url:{url}")
            if cached:
                return cached

        timeout = timeout or self.config.get('collection.request_timeout', 15)
        max_attempts = self.config.get('collection.retry_attempts', 3)
        backoff = self.config.get('collection.retry_backoff', 1.5)

        host = urlparse(url).netloc
        self.rate_limiter.acquire(host)

        for attempt in range(max_attempts):
            try:
                resp = self.session.get(url, headers=self._get_headers(), timeout=timeout)
                resp.raise_for_status()

                if self.config.cache:
                    self.config.cache.set(f"url:{url}", resp.text,
                                          ttl=self.config.get('cache.ttl_seconds', 3600))

                return resp.text

            except requests.exceptions.Timeout:
                if attempt < max_attempts - 1:
                    time.sleep(backoff * (attempt + 1))
                else:
                    return None
            except Exception as e:
                self.config.logger.debug(f"Fetch error {url}: {e}")
                return None

        return None

    def fetch_feed(self, category: str, source: Dict) -> List[IntelligenceArticle]:
        if not FEEDPARSER_AVAILABLE:
            return []

        source_name = source.get('name', 'Unknown')
        source_url = source.get('url', '')
        max_items = source.get('max_items', self.config.get('collection.max_items_per_feed', 25))

        content = self._fetch_url(source_url)
        if not content:
            with self.lock:
                self.stats[source_name]["failed"] += 1
            return []

        try:
            feed = feedparser.parse(content)
        except Exception as e:
            self.config.logger.error(f"Parse error {source_name}: {e}")
            return []

        articles = []
        for entry in feed.entries[:max_items]:
            try:
                summary = (getattr(entry, 'summary', '') or
                          getattr(entry, 'description', '') or '')
                content_text = (getattr(entry, 'content', [{}])[0].get('value', '') if
                               hasattr(entry, 'content') else '')

                published = self._parse_date(entry)

                article = IntelligenceArticle(
                    source=source_name,
                    source_url=source_url,
                    source_type='rss',
                    title=self._clean(getattr(entry, 'title', 'Sans titre')),
                    summary=self._clean(summary),
                    content=self._clean(content_text, 1000),
                    link=getattr(entry, 'link', ''),
                    published=published,
                    category=category,
                    tags=source.get('tags', [])
                )

                article.confidence = source.get('confidence', 5)

                if source.get('priority') == 'critical':
                    article.tags.append('critical_source')

                articles.append(article)

            except Exception as e:
                self.config.logger.debug(f"Error parsing entry: {e}")
                continue

        with self.lock:
            self.stats[source_name]["success"] = len(articles)

        return articles

    def _parse_date(self, entry) -> str:
        for attr in ('published_parsed', 'updated_parsed', 'created_parsed'):
            t = getattr(entry, attr, None)
            if t and len(t) >= 6:
                try:
                    dt = datetime(*t[:6], tzinfo=timezone.utc)
                    return dt.isoformat()
                except:
                    pass

        for attr in ('published', 'updated', 'pubDate'):
            date_str = getattr(entry, attr, None)
            if date_str:
                try:
                    dt = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
                    return dt.isoformat()
                except:
                    try:
                        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                        return dt.isoformat()
                    except:
                        pass

        return datetime.now(timezone.utc).isoformat()

    def _clean(self, text: Optional[str], max_len: int = 500) -> str:
        if not text:
            return ""
        clean = re.sub(r'<[^>]+>', '', str(text))
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean[:max_len]

    def collect_all(self, mode: str = 'fusion') -> List[IntelligenceArticle]:
        all_articles = []
        categories = self.config.get('categories', [])

        if not categories:
            self.config.logger.warning("No categories configured")
            return []

        if mode == 'cyber':
            categories = [c for c in categories if 'cyber' in c.get('name', '').lower()
                         or 'exploit' in c.get('name', '').lower()
                         or 'cve' in c.get('name', '').lower()]
        elif mode == 'strat':
            categories = [c for c in categories if 'strat' in c.get('name', '').lower()
                         or 'nuclear' in c.get('name', '').lower()
                         or 'defense' in c.get('name', '').lower()]
        elif mode == 'leak':
            categories = [c for c in categories if 'leak' in c.get('name', '').lower()
                         or 'breach' in c.get('name', '').lower()
                         or 'ransomware' in c.get('name', '').lower()]

        if RICH_AVAILABLE and self.console:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                console=self.console,
                transient=True
            )
            progress.start()
        else:
            progress = None

        try:
            for cat in categories:
                cat_name = cat.get('name', 'Unknown')
                feeds = cat.get('feeds', [])

                if not feeds:
                    continue

                if progress:
                    task = progress.add_task(f"[cyan]{cat_name}[/cyan]", total=len(feeds))

                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.config.get('collection.concurrent_workers', 10)
                ) as executor:
                    futures = []
                    for source in feeds:
                        future = executor.submit(self.fetch_feed, cat_name, source)
                        futures.append(future)

                    for future in concurrent.futures.as_completed(futures):
                        articles = future.result()
                        with self.lock:
                            all_articles.extend(articles)
                        if progress:
                            progress.advance(task)
        finally:
            if progress:
                progress.stop()

        unique = self._deduplicate(all_articles)
        unique.sort(key=lambda a: (a.risk_score + a.strat_score), reverse=True)

        return unique

    def _deduplicate(self, articles: List[IntelligenceArticle]) -> List[IntelligenceArticle]:
        if CORRELATOR_AVAILABLE:
            try:
                dedup = FuzzyDeduplicator(threshold=0.85)
                return dedup.deduplicate(articles)
            except Exception:
                pass
        # Fallback MD5 hash
        seen: Set[str] = set()
        unique = []
        for art in articles:
            if art.content_hash not in seen:
                seen.add(art.content_hash)
                unique.append(art)
        return unique


# ──────────────────────────────────────────────────────────────────────────────
# SPECIALIZED SCRAPERS
# ──────────────────────────────────────────────────────────────────────────────

class AdvancedScraper:
    def __init__(self, config: Config):
        self.config = config
        self.console = Console() if RICH_AVAILABLE else None
        self.session = requests.Session() if REQUESTS_AVAILABLE else None

    def scrape_securityaffairs(self, max_items: int = 20) -> List[IntelligenceArticle]:
        if not BS4_AVAILABLE:
            return []

        articles = []
        urls = [
            "https://securityaffairs.com/category/data-breach/",
            "https://securityaffairs.com/category/cyber-crime/",
            "https://securityaffairs.com/"
        ]

        for url in urls[:2]:
            try:
                resp = self._fetch_url(url)
                if not resp:
                    continue

                soup = BeautifulSoup(resp, 'lxml')
                posts = soup.select('article.post') or soup.select('div.post')

                for post in posts[:max_items]:
                    title_tag = (post.select_one('h2.entry-title a') or
                                post.select_one('h1.entry-title a') or
                                post.select_one('.entry-title a'))

                    if not title_tag:
                        continue

                    title = title_tag.get_text(strip=True)
                    link = title_tag.get('href', '')
                    if not link.startswith('http'):
                        link = 'https://securityaffairs.com' + link

                    summary_tag = (post.select_one('div.entry-content p') or
                                  post.select_one('.entry-summary') or
                                  post.select_one('p'))
                    summary = summary_tag.get_text(strip=True)[:500] if summary_tag else ""

                    category = "Data Leaks & Breaches"
                    if 'cyber-crime' in url:
                        category = "Malware & Ransomware"

                    article = IntelligenceArticle(
                        source="Security Affairs",
                        source_url=link,
                        source_type="scrape",
                        title=title,
                        summary=summary,
                        link=link,
                        category=category,
                        confidence=9,
                        tags=['securityaffairs', 'premium_source']
                    )

                    articles.append(article)

            except Exception as e:
                self.config.logger.debug(f"SecurityAffairs scrape error: {e}")

        return articles

    def scrape_hibp(self) -> List[IntelligenceArticle]:
        if not REQUESTS_AVAILABLE:
            return []

        articles = []
        try:
            resp = self._fetch_url("https://haveibeenpwned.com/api/v3/latestbreach")
            if resp:
                data = json.loads(resp)
                article = IntelligenceArticle(
                    source="HaveIBeenPwned",
                    source_url=f"https://haveibeenpwned.com/PwnedWebsites#{data.get('Name', '')}",
                    source_type="api",
                    title=f"HIBP: {data.get('Name', 'Unknown')} breach - {data.get('PwnCount', 0):,} accounts",
                    summary=f"Domain: {data.get('Domain', '?')} | Date: {data.get('BreachDate', '?')}",
                    category="Data Leaks & Breaches",
                    leak_records=f"{data.get('PwnCount', 0):,} accounts",
                    pii_types=data.get('DataClasses', [])[:5],
                    confidence=10,
                    tags=['hibp', 'verified_breach']
                )
                articles.append(article)
        except Exception as e:
            self.config.logger.debug(f"HIBP error: {e}")

        return articles

    def scrape_ransomware_live(self) -> List[IntelligenceArticle]:
        if not REQUESTS_AVAILABLE:
            return []

        articles = []
        try:
            resp = self._fetch_url("https://www.ransomware.live/api/recentvictims")
            if resp:
                victims = json.loads(resp)[:15]
                for v in victims:
                    article = IntelligenceArticle(
                        source=f"Ransomware.live - {v.get('group_name', 'Unknown')}",
                        source_url=v.get('post_url', 'https://ransomware.live'),
                        source_type="api",
                        title=f"[Ransomware] {v.get('group_name', '?')} → {v.get('post_title', '?')}",
                        summary=f"Victim: {v.get('victim', '?')} | Country: {v.get('country', '?')}",
                        category="Malware & Ransomware",
                        ransomware_related=True,
                        tags=[f"group:{v.get('group_name', 'unknown')}"],
                        confidence=8
                    )
                    articles.append(article)
        except Exception as e:
            self.config.logger.debug(f"Ransomware.live error: {e}")

        return articles

    def _fetch_url(self, url: str) -> Optional[str]:
        if not self.session:
            return None

        try:
            headers = {
                "User-Agent": UserAgentRotator.get(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }
            resp = self.session.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            return None

    def run_all(self) -> List[IntelligenceArticle]:
        if not self.config.get('collection.scraping_enabled', True):
            return []

        articles = []

        if self.console:
            self.console.print("[dim cyan]  ↳ Running advanced scrapers...[/dim cyan]")

        articles.extend(self.scrape_securityaffairs())
        articles.extend(self.scrape_hibp())
        articles.extend(self.scrape_ransomware_live())

        return articles


# ──────────────────────────────────────────────────────────────────────────────
# ANALYZERS & REPORTING
# ──────────────────────────────────────────────────────────────────────────────

class IntelligenceAnalyzer:
    def __init__(self, articles: List[IntelligenceArticle], config: Config):
        self.articles = articles
        self.config = config

    def generate_full_stats(self) -> Dict:
        stats = {
            "total": len(self.articles),
            "by_domain": Counter(),
            "by_category": Counter(),
            "by_severity": Counter(),
            "by_source": Counter(),
            "by_date": defaultdict(int),
            "by_theatre": Counter(),
            "by_actor": Counter(),
            "by_weapon": Counter(),

            "exploit_count": 0,
            "ransomware_count": 0,
            "apt_count": 0,
            "kev_count": 0,
            "leak_count": 0,
            "darkweb_count": 0,
            "extortion_count": 0,

            "nuclear_count": 0,
            "conflict_count": 0,
            "weapons_count": 0,
            "aerospace_count": 0,
            "sanctions_count": 0,
            "intel_count": 0,

            "iocs_total": 0,
            "iocs_by_type": Counter(),

            "cve_count": 0,
            "top_cves": Counter(),

            "avg_risk_score": 0,
            "avg_strat_score": 0,
            "critical_count": 0,
            "flash_count": 0
        }

        now = datetime.now(timezone.utc)
        total_risk = 0
        total_strat = 0

        for art in self.articles:
            stats["by_domain"][art.domain.value] += 1
            stats["by_category"][art.category] += 1
            stats["by_severity"][art.severity] += 1
            stats["by_source"][art.source] += 1

            for theatre in art.theatres:
                stats["by_theatre"][theatre] += 1

            for actor in art.actors:
                stats["by_actor"][actor] += 1

            for weapon in art.weapon_systems:
                stats["by_weapon"][weapon] += 1

            if art.exploit_available:
                stats["exploit_count"] += 1
            if art.ransomware_related:
                stats["ransomware_count"] += 1
            if art.apt_related:
                stats["apt_count"] += 1
            if art.in_kev:
                stats["kev_count"] += 1
            if art.leak_related:
                stats["leak_count"] += 1
            if art.darkweb_related:
                stats["darkweb_count"] += 1
            if art.extortion_related:
                stats["extortion_count"] += 1

            if art.nuclear_related:
                stats["nuclear_count"] += 1
            if art.conflict_related:
                stats["conflict_count"] += 1
            if art.weapons_related:
                stats["weapons_count"] += 1
            if art.aerospace_related:
                stats["aerospace_count"] += 1
            if art.sanctions_related:
                stats["sanctions_count"] += 1
            if art.intel_related:
                stats["intel_count"] += 1

            for ioc_type, iocs in art.iocs.items():
                stats["iocs_total"] += len(iocs)
                stats["iocs_by_type"][ioc_type] += len(iocs)

            for cve in art.cves:
                stats["top_cves"][cve] += 1
                stats["cve_count"] += 1

            total_risk += art.risk_score
            total_strat += art.strat_score

            if art.severity == "CRITICAL":
                stats["critical_count"] += 1
            elif art.severity == "FLASH":
                stats["flash_count"] += 1

            try:
                pub = datetime.fromisoformat(art.published.replace('Z', '+00:00'))
                delta = (now - pub).days
                if delta == 0:
                    stats["by_date"]["24h"] += 1
                elif delta <= 7:
                    stats["by_date"]["7d"] += 1
                elif delta <= 30:
                    stats["by_date"]["30d"] += 1
                else:
                    stats["by_date"][">30d"] += 1
            except:
                pass

        if stats["total"] > 0:
            stats["avg_risk_score"] = total_risk / stats["total"]
            stats["avg_strat_score"] = total_strat / stats["total"]

        stats["top_cves"] = stats["top_cves"].most_common(10)

        return stats

    def get_critical_alerts(self, threshold: int = 85) -> List[IntelligenceArticle]:
        return [a for a in self.articles if a.risk_score + a.strat_score >= threshold]

    def get_flash_alerts(self) -> List[IntelligenceArticle]:
        return [a for a in self.articles if a.severity == "FLASH"]

    def get_correlations(self) -> Dict:
        correlations = {
            "cyber_strategic": 0,
            "leak_ransomware": 0,
            "apt_nuclear": 0,
        }

        for art in self.articles:
            if (art.exploit_available or art.ransomware_related) and \
               (art.nuclear_related or art.conflict_related):
                correlations["cyber_strategic"] += 1

            if art.leak_related and art.ransomware_related:
                correlations["leak_ransomware"] += 1

            if art.apt_related and art.nuclear_related:
                correlations["apt_nuclear"] += 1

        return correlations

    def generate_executive_summary(self) -> str:
        stats = self.generate_full_stats()

        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    FULCRUM EXECUTIVE INTELLIGENCE BRIEF                      ║
║                           {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  📊 COLLECTION SUMMARY                                                       ║
║  ──────────────────────────────────────────────────────────────────────────  ║
║  Total Intelligence Items: {stats['total']:>6}                                                 ║
║  FLASH Alerts:            {stats['flash_count']:>6}  ⚠️ IMMEDIATE ACTION REQUIRED                 ║
║  CRITICAL Alerts:         {stats['critical_count']:>6}                                                 ║
║                                                                              ║
║  🎯 DOMAIN BREAKDOWN                                                         ║
║  ──────────────────────────────────────────────────────────────────────────  ║
║  Cyber Intelligence:      {stats['by_domain'].get('cyber', 0):>6}                                                 ║
║  Strategic Intelligence:  {stats['by_domain'].get('strategic', 0):>6}                                                 ║
║  Offensive Intelligence:  {stats['by_domain'].get('offensive', 0):>6}                                                 ║
║                                                                              ║
║  🚨 THREAT LANDSCAPE                                                         ║
║  ──────────────────────────────────────────────────────────────────────────  ║
║  Exploits Detected:       {stats['exploit_count']:>6}                                                 ║
║  Ransomware Events:       {stats['ransomware_count']:>6}                                                 ║
║  APT Activities:          {stats['apt_count']:>6}                                                 ║
║  Data Leaks:              {stats['leak_count']:>6}                                                 ║
║  Dark Web Mentions:       {stats['darkweb_count']:>6}                                                 ║
║                                                                              ║
║  🌍 STRATEGIC INDICATORS                                                     ║
║  ──────────────────────────────────────────────────────────────────────────  ║
║  Nuclear Signals:         {stats['nuclear_count']:>6}                                                 ║
║  Conflict Indicators:     {stats['conflict_count']:>6}                                                 ║
║  Weapons Systems:         {stats['weapons_count']:>6}                                                 ║
║  Aerospace Activity:      {stats['aerospace_count']:>6}                                                 ║
║                                                                              ║
║  🔍 KEY ACTORS MENTIONED                                                    ║
║  ──────────────────────────────────────────────────────────────────────────  ║"""

        for actor, count in stats["by_actor"].most_common(10):
            summary += f"\n║  • {actor:<25} {count:>3} mentions                                          ║"

        summary += f"""
║                                                                              ║
║  💥 CRITICAL PRIORITIES                                                      ║
║  ──────────────────────────────────────────────────────────────────────────  ║"""

        for art in self.get_critical_alerts(90)[:5]:
            summary += f"\n║  🔴 [{art.risk_score + art.strat_score}/100] {art.title[:55]}"
            summary += f"\n║      {art.source} | {art.severity} | {art.category[:30]}"

        summary += """
║                                                                              ║
║  📈 CORRELATIONS                                                             ║
║  ──────────────────────────────────────────────────────────────────────────  ║"""

        corr = self.get_correlations()
        summary += f"""
║  Cyber-Strategic Nexus:   {corr['cyber_strategic']:>3} correlated events                                    ║
║  Leak-Ransomware Nexus:   {corr['leak_ransomware']:>3} correlated events                                    ║
║  APT-Nuclear Nexus:       {corr['apt_nuclear']:>3} correlated events                                    ║
║                                                                              ║
║  ═════════════════════════════════════════════════════════════════════════  ║
║  RECOMMENDATIONS:                                                           ║
║  • Activate incident response protocols for FLASH alerts                    ║
║  • Review all CRITICAL vulnerabilities within 24 hours                      ║
║  • Monitor mentioned Dark Web channels for potential data exposure          ║
║  • Escalate nuclear-related indicators to strategic analysis team           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        return summary


# ──────────────────────────────────────────────────────────────────────────────
# EXPORTERS (HTML, JSON, CSV, PDF)
# ──────────────────────────────────────────────────────────────────────────────

class Exporter:
    def __init__(self, config: Config):
        self.config = config

    def export_json(self, articles: List[IntelligenceArticle], stats: Dict = None) -> str:
        path = self.config.get('export.paths.json', 'fulcrum_export.json')

        if JSON_EXPORTER_AVAILABLE:
            try:
                exporter = JSONExporter(output_path=path)
                out = exporter.export(
                    articles=[a.to_dict() for a in articles],
                    stats=stats or {},
                    clusters={},
                    run_metadata={
                        "version": self.config.get('app.version', '3.0'),
                        "tool": self.config.get('app.name', 'FULCRUM'),
                    },
                )
                return str(out)
            except Exception as exc:
                import logging
                logging.getLogger("FULCRUM").warning(f"JSONExporter error: {exc}, falling back")

        # Fallback
        export_data = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "version": self.config.get('app.version', '3.0'),
                "total_articles": len(articles),
                "tool": self.config.get('app.name', 'FULCRUM')
            },
            "statistics": stats,
            "articles": [a.to_dict() for a in articles]
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)
        return path

    def export_csv(self, articles: List[IntelligenceArticle]) -> str:
        path = self.config.get('export.paths.csv', 'fulcrum_export.csv')

        if not articles:
            return path

        flat_data = []
        for art in articles:
            d = art.to_dict()
            d['cves'] = '|'.join(d.get('cves', []))
            d['actors'] = '|'.join(d.get('actors', []))
            d['weapon_systems'] = '|'.join(d.get('weapon_systems', []))
            d['theatres'] = '|'.join(d.get('theatres', []))
            d['tags'] = '|'.join(d.get('tags', []))
            d['pii_types'] = '|'.join(d.get('pii_types', []))
            d['iocs'] = json.dumps(d.get('iocs', {}))
            flat_data.append(d)

        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=flat_data[0].keys())
            writer.writeheader()
            writer.writerows(flat_data)

        return path

    def export_html(self, articles: List[IntelligenceArticle], analyzer: IntelligenceAnalyzer,
                    takeaway: Optional[Dict] = None) -> str:
        path = self.config.get('export.paths.html', 'fulcrum_dashboard.html')
        stats = analyzer.generate_full_stats()

        if HTML_DASHBOARD_AVAILABLE:
            try:
                dashboard = HTMLDashboard(output_path=path)
                out = dashboard.generate(
                    articles=[a.to_dict() for a in articles],
                    stats=stats,
                    takeaway=takeaway or {},
                )
                return str(out)
            except Exception as exc:
                import logging
                logging.getLogger("FULCRUM").warning(f"HTMLDashboard error: {exc}, falling back")

        critical_articles = analyzer.get_critical_alerts(85)
        html = self._generate_html_dashboard(articles, stats, critical_articles)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path

    def _generate_html_dashboard(self, articles: List[IntelligenceArticle], stats: Dict,
                                  critical: List[IntelligenceArticle]) -> str:

        cards_html = ""
        for art in articles[:100]:
            sev_class = art.severity.lower()
            score = art.risk_score + art.strat_score
            score_color = "#ff0040" if score >= 85 else "#ff6b00" if score >= 70 else "#ffb700" if score >= 50 else "#3fb950"

            flags = []
            if art.exploit_available:
                flags.append('<span class="flag exploit">⚡ EXPLOIT</span>')
            if art.ransomware_related:
                flags.append('<span class="flag ransom">💀 RANSOM</span>')
            if art.nuclear_related:
                flags.append('<span class="flag nuclear">☢ NUCL</span>')
            if art.leak_related:
                flags.append('<span class="flag leak">🔓 LEAK</span>')
            if art.darkweb_related:
                flags.append('<span class="flag darkweb">🌑 DARKWEB</span>')

            cves_html = ""
            if art.cves:
                cves_html = f'<div class="cves">{" ".join(f"<code>{cve}</code>" for cve in art.cves[:3])}</div>'

            actors_html = ""
            if art.actors:
                actor_spans = " ".join(f'<span class="actor">{a}</span>' for a in art.actors[:5])
                actors_html = f'<div class="actors">🎭 {actor_spans}</div>'

            cards_html += f"""
            <div class="card severity-{sev_class}" data-score="{score}" data-severity="{art.severity}">
                <div class="card-header">
                    <span class="badge" style="background:{self._get_category_color(art.category)}">{art.category[:20]}</span>
                    <span class="severity {sev_class}">{art.severity}</span>
                </div>
                <div class="score-bar">
                    <div class="score-fill" style="width:{score}%;background:{score_color}"></div>
                    <span class="score-label">{score}</span>
                </div>
                <div class="source">{art.source}</div>
                <h3><a href="{art.link}" target="_blank">{art.title}</a></h3>
                <p class="summary">{art.summary[:200]}</p>
                <div class="flags">{''.join(flags)}</div>
                {cves_html}
                {actors_html}
                <div class="meta">
                    <span>🕐 {art.published[:16].replace('T', ' ')}</span>
                    <span>📊 {art.risk_score}/{art.strat_score}</span>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FULCRUM — Intelligence Operations Center</title>
    <style>
        :root {{
            --bg-primary: #0a0c12;
            --bg-secondary: #111318;
            --bg-tertiary: #1a1d24;
            --border: #2a2e3a;
            --text-primary: #eef2ff;
            --text-secondary: #9ca3af;
            --accent-cyber: #00d4aa;
            --accent-strategic: #ff6b35;
            --accent-offensive: #ff2a6d;
            --critical: #ff0040;
            --high: #ff6b00;
            --medium: #ffb700;
            --low: #3fb950;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            background: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            line-height: 1.5;
        }}

        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 0, 0.02) 0px,
                rgba(0, 255, 0, 0.02) 2px,
                transparent 2px,
                transparent 4px
            );
            pointer-events: none;
            z-index: 9999;
        }}

        .header {{
            background: linear-gradient(135deg, #0a0c12 0%, #111318 100%);
            border-bottom: 2px solid var(--accent-cyber);
            padding: 1.5rem 2rem;
            position: relative;
        }}

        .header h1 {{
            font-size: 2rem;
            letter-spacing: -1px;
            background: linear-gradient(135deg, #00d4aa, #ff2a6d, #ff6b35);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .header .status {{
            position: absolute;
            top: 1.5rem;
            right: 2rem;
            font-size: 0.75rem;
            color: var(--text-secondary);
        }}

        .status .led {{
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #3fb950;
            box-shadow: 0 0 8px #3fb950;
            animation: pulse 2s infinite;
            margin-right: 0.5rem;
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            padding: 1.5rem 2rem;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
        }}

        .stat-card {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
        }}

        .stat-card .label {{
            font-size: 0.7rem;
            text-transform: uppercase;
            color: var(--text-secondary);
            letter-spacing: 0.05em;
        }}

        .stat-card .value {{
            font-size: 1.5rem;
            font-weight: bold;
            font-family: monospace;
        }}

        .filters {{
            padding: 1rem 2rem;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            align-items: center;
        }}

        .filter-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 0.3rem 0.8rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.75rem;
            transition: all 0.2s;
        }}

        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent-cyber);
            border-color: var(--accent-cyber);
            color: #000;
        }}

        .search-box {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 0.4rem 0.8rem;
            border-radius: 4px;
            font-family: monospace;
            width: 250px;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 1rem;
            padding: 1.5rem 2rem;
        }}

        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            transition: all 0.2s;
            position: relative;
            overflow: hidden;
        }}

        .card::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 3px;
        }}

        .card.severity-flash::before {{ background: #ff0040; box-shadow: 0 0 8px #ff0040; }}
        .card.severity-critical::before {{ background: #ff0040; }}
        .card.severity-high::before {{ background: #ff6b00; }}
        .card.severity-medium::before {{ background: #ffb700; }}
        .card.severity-low::before {{ background: #3fb950; }}

        .card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-cyber);
            box-shadow: 0 4px 20px rgba(0, 212, 170, 0.1);
        }}

        .card.hidden {{ display: none; }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}

        .badge {{
            font-size: 0.6rem;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }}

        .severity {{
            font-size: 0.6rem;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            font-weight: bold;
        }}

        .severity.flash {{ background: #ff0040; color: white; }}
        .severity.critical {{ background: #ff0040; color: white; }}
        .severity.high {{ background: #ff6b00; color: black; }}
        .severity.medium {{ background: #ffb700; color: black; }}
        .severity.low {{ background: #3fb950; color: black; }}

        .score-bar {{
            background: var(--border);
            height: 3px;
            border-radius: 2px;
            margin: 0.5rem 0;
            position: relative;
        }}

        .score-fill {{
            height: 100%;
            border-radius: 2px;
        }}

        .score-label {{
            position: absolute;
            right: 0;
            top: -1.2rem;
            font-size: 0.6rem;
            font-family: monospace;
        }}

        .source {{
            font-size: 0.7rem;
            color: var(--accent-cyber);
            margin-bottom: 0.5rem;
        }}

        .card h3 {{
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }}

        .card h3 a {{
            color: var(--text-primary);
            text-decoration: none;
        }}

        .card h3 a:hover {{
            color: var(--accent-cyber);
        }}

        .summary {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.75rem;
        }}

        .flags {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.25rem;
            margin-bottom: 0.5rem;
        }}

        .flag {{
            font-size: 0.55rem;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-weight: bold;
        }}

        .flag.exploit {{ background: #ff2a6d20; color: #ff2a6d; border: 1px solid #ff2a6d; }}
        .flag.ransom {{ background: #c0392b20; color: #c0392b; border: 1px solid #c0392b; }}
        .flag.nuclear {{ background: #ff6b3520; color: #ff6b35; border: 1px solid #ff6b35; }}
        .flag.leak {{ background: #e74c3c20; color: #e74c3c; border: 1px solid #e74c3c; }}
        .flag.darkweb {{ background: #8e44ad20; color: #8e44ad; border: 1px solid #8e44ad; }}

        .cves {{
            font-size: 0.65rem;
            margin-bottom: 0.5rem;
        }}

        .cves code {{
            background: var(--bg-tertiary);
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            margin-right: 0.25rem;
        }}

        .actors {{
            font-size: 0.65rem;
            color: var(--text-secondary);
        }}

        .actors .actor {{
            background: var(--bg-tertiary);
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            margin-right: 0.25rem;
        }}

        .meta {{
            display: flex;
            justify-content: space-between;
            font-size: 0.6rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
            padding-top: 0.5rem;
            border-top: 1px solid var(--border);
        }}

        footer {{
            text-align: center;
            padding: 1.5rem;
            color: var(--text-secondary);
            font-size: 0.7rem;
            border-top: 1px solid var(--border);
        }}

        #counter {{
            margin-left: auto;
            font-family: monospace;
            font-size: 0.75rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚡ FULCRUM · Intelligence Operations Center</h1>
        <div class="status">
            <span class="led"></span>
            <span>ACTIVE · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</span>
        </div>
    </div>

    <div class="stats-grid">
        <div class="stat-card"><div class="label">Total Intel</div><div class="value">{stats['total']}</div></div>
        <div class="stat-card"><div class="label">FLASH Alerts</div><div class="value" style="color:#ff0040">{stats['flash_count']}</div></div>
        <div class="stat-card"><div class="label">CRITICAL</div><div class="value" style="color:#ff0040">{stats['critical_count']}</div></div>
        <div class="stat-card"><div class="label">Data Leaks</div><div class="value">{stats['leak_count']}</div></div>
        <div class="stat-card"><div class="label">Nuclear</div><div class="value">{stats['nuclear_count']}</div></div>
        <div class="stat-card"><div class="label">Exploits</div><div class="value">{stats['exploit_count']}</div></div>
        <div class="stat-card"><div class="label">Ransomware</div><div class="value">{stats['ransomware_count']}</div></div>
        <div class="stat-card"><div class="label">IOCs</div><div class="value">{stats['iocs_total']}</div></div>
    </div>

    <div class="filters">
        <input type="text" class="search-box" id="search" placeholder="🔍 Search...">
        <button class="filter-btn active" data-filter="all">ALL</button>
        <button class="filter-btn" data-filter="FLASH">FLASH</button>
        <button class="filter-btn" data-filter="CRITICAL">CRITICAL</button>
        <button class="filter-btn" data-filter="HIGH">HIGH</button>
        <button class="filter-btn" data-filter="MEDIUM">MEDIUM</button>
        <span id="counter"></span>
    </div>

    <div class="grid" id="grid">
        {cards_html}
    </div>

    <footer>
        FULCRUM v3.0 · Full Spectrum Intelligence Platform · {datetime.now().year}
    </footer>

    <script>
        const cards = document.querySelectorAll('.card');
        const searchBox = document.getElementById('search');
        const filterBtns = document.querySelectorAll('.filter-btn');
        const counter = document.getElementById('counter');

        let currentFilter = 'all';

        function updateDisplay() {{
            const searchTerm = searchBox.value.toLowerCase();
            let visible = 0;

            cards.forEach(card => {{
                const severity = card.dataset.severity;
                const title = card.querySelector('h3')?.textContent?.toLowerCase() || '';
                const summary = card.querySelector('.summary')?.textContent?.toLowerCase() || '';
                const matchesFilter = currentFilter === 'all' || severity === currentFilter;
                const matchesSearch = title.includes(searchTerm) || summary.includes(searchTerm);
                const show = matchesFilter && matchesSearch;

                card.classList.toggle('hidden', !show);
                if (show) visible++;
            }});

            counter.textContent = visible + ' items displayed';
        }}

        searchBox.addEventListener('input', updateDisplay);

        filterBtns.forEach(btn => {{
            btn.addEventListener('click', () => {{
                filterBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                currentFilter = btn.dataset.filter;
                updateDisplay();
            }});
        }});

        updateDisplay();
    </script>
</body>
</html>"""

        return html

    def _get_category_color(self, category: str) -> str:
        colors = {
            'Data Leaks': '#ff2a6d',
            'Exploits': '#ff6b00',
            'Nuclear': '#ff6b35',
            'Defense': '#e05c2a',
            'Cyber': '#00d4aa',
            'Ransomware': '#c0392b'
        }
        for key, color in colors.items():
            if key in category:
                return color
        return '#888888'

    def export_pdf(self, articles: List[IntelligenceArticle], analyzer: IntelligenceAnalyzer) -> str:
        path = self.config.get('export.paths.pdf', 'fulcrum_report.pdf')

        html_path = self.export_html(articles, analyzer)

        try:
            import pdfkit
            pdfkit.from_file(html_path, path)
            return path
        except ImportError:
            self.config.logger.warning("pdfkit not installed, skipping PDF export")
            return None

    def export_all(self, articles: List[IntelligenceArticle], analyzer: IntelligenceAnalyzer) -> Dict[str, str]:
        stats = analyzer.generate_full_stats()
        return {
            'json': self.export_json(articles, stats),
            'csv': self.export_csv(articles),
            'html': self.export_html(articles, analyzer),
            'pdf': self.export_pdf(articles, analyzer)
        }


# ──────────────────────────────────────────────────────────────────────────────
# ALERTING SYSTEM
# ──────────────────────────────────────────────────────────────────────────────

class AlertSystem:
    def __init__(self, config: Config):
        self.config = config
        self.console = Console() if RICH_AVAILABLE else None

    def send_alert(self, article: IntelligenceArticle):
        if self.config.get('alerts.critical_only', False) and article.severity not in ['FLASH', 'CRITICAL']:
            return

        message = self._format_alert(article)

        if self.console:
            self.console.print(Panel(
                message,
                title="🚨 ALERT",
                border_style="red"
            ))

        for webhook in self.config.get('alerts.webhooks', []):
            self._send_webhook(webhook, message)

        token = self.config.get('alerts.telegram_bot_token')
        chat_id = self.config.get('alerts.telegram_chat_id')
        if token and chat_id:
            self._send_telegram(token, chat_id, message)

        slack_webhook = self.config.get('alerts.slack_webhook')
        if slack_webhook:
            self._send_slack(slack_webhook, message)

        discord_webhook = self.config.get('alerts.discord_webhook')
        if discord_webhook:
            self._send_discord(discord_webhook, message)

    def _format_alert(self, article: IntelligenceArticle) -> str:
        score = article.risk_score + article.strat_score
        return f"""
╔═══════════════════════════════════════════════════════════════╗
║  [{article.severity}] {article.title[:60]}
╠═══════════════════════════════════════════════════════════════╣
║  Score: {score}/100  |  Source: {article.source}
║  Category: {article.category}
║  Link: {article.link}
╚═══════════════════════════════════════════════════════════════╝
"""

    def _send_webhook(self, url: str, message: str):
        try:
            requests.post(url, json={"text": message}, timeout=5)
        except:
            pass

    def _send_telegram(self, token: str, chat_id: str, message: str):
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=5)
        except:
            pass

    def _send_slack(self, webhook: str, message: str):
        try:
            requests.post(webhook, json={"text": message}, timeout=5)
        except:
            pass

    def _send_discord(self, webhook: str, message: str):
        try:
            requests.post(webhook, json={"content": message}, timeout=5)
        except:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# API SERVER (Flask)
# ──────────────────────────────────────────────────────────────────────────────

class APIServer:
    def __init__(self, config: Config, articles: List[IntelligenceArticle], analyzer: IntelligenceAnalyzer):
        self.config = config
        self.articles = articles
        self.analyzer = analyzer
        self.app = None

    def start(self, host: str = None, port: int = None):
        if not self.config.get('api.enabled', False):
            return

        try:
            from flask import Flask, jsonify, request
            from flask_cors import CORS

            host = host or self.config.get('api.host', '0.0.0.0')
            port = port or self.config.get('api.port', 5000)

            self.app = Flask(__name__)
            if self.config.get('api.cors', True):
                CORS(self.app)

            @self.app.route('/api/health', methods=['GET'])
            def health():
                return jsonify({
                    'status': 'operational',
                    'version': self.config.get('app.version', '3.0'),
                    'timestamp': datetime.now(timezone.utc).isoformat()
                })

            @self.app.route('/api/articles', methods=['GET'])
            def get_articles():
                limit = request.args.get('limit', 100, type=int)
                offset = request.args.get('offset', 0, type=int)
                severity = request.args.get('severity')
                category = request.args.get('category')

                articles = self.articles
                if severity:
                    articles = [a for a in articles if a.severity == severity.upper()]
                if category:
                    articles = [a for a in articles if category.lower() in a.category.lower()]

                paginated = articles[offset:offset+limit]

                return jsonify({
                    'total': len(articles),
                    'limit': limit,
                    'offset': offset,
                    'articles': [a.to_dict() for a in paginated]
                })

            @self.app.route('/api/stats', methods=['GET'])
            def get_stats():
                return jsonify(self.analyzer.generate_full_stats())

            @self.app.route('/api/critical', methods=['GET'])
            def get_critical():
                critical = self.analyzer.get_critical_alerts(85)
                return jsonify({
                    'count': len(critical),
                    'articles': [a.to_dict() for a in critical]
                })

            @self.app.route('/api/cves/top', methods=['GET'])
            def get_top_cves():
                stats = self.analyzer.generate_full_stats()
                return jsonify(stats.get('top_cves', []))

            print(f"🌐 API Server running on http://{host}:{port}")
            self.app.run(host=host, port=port, debug=False)

        except ImportError:
            self.config.logger.warning("Flask not installed, API server disabled")
        except Exception as e:
            self.config.logger.error(f"API server error: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ──────────────────────────────────────────────────────────────────────────────

class FULCRUM:
    def __init__(self, config_path: Optional[Path] = None):
        self.config = Config(config_path)
        self.console = Console() if RICH_AVAILABLE else None
        self.articles: List[IntelligenceArticle] = []
        self.analyzer: Optional[IntelligenceAnalyzer] = None
        self._store: Optional[Any] = None

    def run(self, mode: str = 'fusion', export_format: str = None,
            critical_only: bool = False, since: str = None,
            theatre: str = None, dashboard: bool = False, port: int = 8080,
            api: bool = False, api_port: int = 5000,
            watch: int = 0, report: str = None):

        self._print_banner()

        # ── Init SQLite persistence ────────────────────────────────────────
        self._store: Optional[Any] = None
        if SQLITE_STORE_AVAILABLE:
            try:
                db_path = self.config.get('persistence.db_path', 'fulcrum_intel.db')
                self._store = SQLiteStore(db_path=db_path)
                if self.console:
                    self.console.print(f"[dim]SQLite store: {db_path}[/dim]")
            except Exception as exc:
                if self.console:
                    self.console.print(f"[yellow]SQLite init failed: {exc}[/yellow]")

        # ── Watch/scheduler mode ───────────────────────────────────────────
        if watch > 0 and SCHEDULER_AVAILABLE:
            # 1. Effectuer une première collecte immédiate pour initialiser les données
            # Cela garantit que self.articles et self.analyzer ne sont pas None
            self._run_once(mode=mode, export_format=export_format,
                           critical_only=critical_only, since=since,
                           theatre=theatre, dashboard=False, port=port,
                           api=False, api_port=api_port, report=report)

            # 2. Configurer le scheduler pour les mises à jour périodiques en arrière-plan
            def _collect_fn():
                self._run_once(mode=mode, export_format=export_format,
                               critical_only=critical_only, since=since,
                               theatre=theatre, dashboard=False, port=port,
                               api=False, api_port=api_port, report=report)

            scheduler = FulcrumScheduler(
                config=self.config.data,
                collect_fn=_collect_fn,
                prune_fn=self._store.prune_old_articles if self._store else None,
                export_fn=None,
                config_reload_fn=None,
            )

            scheduler.start()
            self.console.print(f"[dim]Scheduler démarré en arrière-plan (intervalle: {watch}s)[/dim]")

            # 3. Lancer le dashboard avec les données déjà collectées
            if dashboard:
                self._start_dashboard(port)
            else:
                # Sinon, on maintient le thread principal en vie pour que le scheduler continue
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.console.print("\n[yellow]Arrêt du scheduler...[/yellow]")
                    scheduler.stop()
            return

        self._run_once(mode=mode, export_format=export_format,
                       critical_only=critical_only, since=since,
                       theatre=theatre, dashboard=dashboard, port=port,
                       api=api, api_port=api_port, report=report)

    def _run_once(self, mode: str = 'fusion', export_format: str = None,
                  critical_only: bool = False, since: str = None,
                  theatre: str = None, dashboard: bool = False, port: int = 8080,
                  api: bool = False, api_port: int = 5000, report: str = None):

        if self.console:
            self.console.print("[cyan]🔍 Starting intelligence collection...[/cyan]")
        collector = UnifiedCollector(self.config)
        self.articles = collector.collect_all(mode)

        if critical_only:
            self.articles = [a for a in self.articles if a.severity in ['FLASH', 'CRITICAL']]
            if self.console:
                self.console.print(f"[dim]Filter: critical-only → {len(self.articles)} items[/dim]")

        if since:
            days = {'24h': 1, '7d': 7, '30d': 30}.get(since, 0)
            if days:
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                before = len(self.articles)
                self.articles = [a for a in self.articles
                                 if datetime.fromisoformat(a.published.replace('Z', '+00:00')) >= cutoff]
                if self.console:
                    self.console.print(f"[dim]Filter: since {since} → {before} → {len(self.articles)} items[/dim]")

        if theatre:
            self.articles = [a for a in self.articles if theatre.lower() in a.theatres]
            if self.console:
                self.console.print(f"[dim]Filter: theatre {theatre} → {len(self.articles)} items[/dim]")

        self.analyzer = IntelligenceAnalyzer(self.articles, self.config)
        stats = self.analyzer.generate_full_stats()

        # ── Persist articles to SQLite ─────────────────────────────────────
        clusters: Dict = {}
        if self._store:
            try:
                new_count = 0
                for art in self.articles:
                    # CORRECTION : le simhash est déjà clampé à 63-bit dans IntelligenceArticle
                    is_new = self._store.upsert_article(art.to_dict())
                    if is_new:
                        new_count += 1
                        if art.iocs:
                            self._store.upsert_iocs(art.id, art.iocs)
                if self.console:
                    self.console.print(f"[dim]SQLite: {new_count} new articles persisted[/dim]")
                if CORRELATOR_AVAILABLE:
                    detector = ClusterDetector(window_hours=72)
                    clusters = detector.detect(self.articles)
                    for cluster_id, cluster_arts in clusters.items():
                        if len(cluster_arts) > 1:
                            self._store.save_cluster(
                                cluster_id=cluster_id,
                                article_ids=[a.id for a in cluster_arts],
                                actors=cluster_arts[0].actors if cluster_arts[0].actors else [],
                                theatre=cluster_arts[0].theatres[0] if cluster_arts[0].theatres else " ",
                            )
                risk_evo = self._store.get_risk_evolution(days=30)
                stats['risk_evolution'] = risk_evo
            except Exception as exc:
                if self.console:
                    self.console.print(f"[yellow]SQLite persistence error: {exc}[/yellow]")

        # ── Generate takeaways ─────────────────────────────────────────────
        takeaway: Dict = {}
        if TAKEAWAY_AVAILABLE:
            try:
                _articles_dicts = [a.to_dict() for a in self.articles]
                gen = TakeawayGenerator(_articles_dicts, stats, clusters)
                takeaway = gen.daily_brief()
            except Exception as exc:
                if self.console:
                    self.console.print(f"[yellow]TakeawayGenerator error: {exc}[/yellow]")

        self._print_summary(stats)

        critical = self.analyzer.get_critical_alerts(85)
        if critical and self.console:
            self.console.print()
            self.console.print(
                Panel(
                    "\n".join([f"[bold red]⚠ {a.title}[/bold red]" for a in critical[:5]]),
                    title="🚨 CRITICAL ALERTS",
                    border_style="red"
                )
            )

        if self.console:
            self.console.print()
            self.console.print(self.analyzer.generate_executive_summary())

        if export_format:
            exporter = Exporter(self.config)
            if export_format == 'json':
                path = exporter.export_json(self.articles, stats)
                if self.console:
                    self.console.print(f"[green]✓ JSON exported → {path}[/green]")
            elif export_format == 'csv':
                path = exporter.export_csv(self.articles)
                if self.console:
                    self.console.print(f"[green]✓ CSV exported → {path}[/green]")
            elif export_format == 'html':
                path = exporter.export_html(self.articles, self.analyzer, takeaway=takeaway)
                if self.console:
                    self.console.print(f"[green]✓ HTML dashboard → {path}[/green]")
            elif export_format == 'pdf':
                path = exporter.export_pdf(self.articles, self.analyzer)
                if path and self.console:
                    self.console.print(f"[green]✓ PDF report → {path}[/green]")
            elif export_format == 'all':
                paths = exporter.export_all(self.articles, self.analyzer)
                for fmt, path in paths.items():
                    if path and self.console:
                        self.console.print(f"[green]✓ {fmt.upper()} → {path}[/green]")

        # ── Jinja2 text report ─────────────────────────────────────────────
        if report and REPORT_GENERATOR_AVAILABLE and takeaway:
            try:
                reporter = ReportGenerator()
                rtype = report if report in ('daily_brief', 'weekly_strategic') else 'daily_brief'
                rdata = takeaway if rtype == 'daily_brief' else TakeawayGenerator(
                    [a.to_dict() for a in self.articles], stats, clusters).weekly_strategic()
                out_path = f"fulcrum_{rtype}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
                reporter.render_and_save(rtype, rdata, out_path)
                if self.console:
                    self.console.print(f"[green]✓ Report → {out_path}[/green]")
            except Exception as exc:
                if self.console:
                    self.console.print(f"[yellow]Report error: {exc}[/yellow]")

        if dashboard:
            self._start_dashboard(port)

        if api:
            api_server = APIServer(self.config, self.articles, self.analyzer)
            api_server.start(port=api_port)

        # ── Send alerts ────────────────────────────────────────────────────
        critical_alerts = self.analyzer.get_critical_alerts(85)[:10]
        if WEBHOOK_MANAGER_AVAILABLE and critical_alerts:
            try:
                wm = WebhookManager(
                    config=self.config.data,
                    critical_only=self.config.get('alerts.critical_only', False),
                    min_score=self.config.get('alerts.min_score', 0),
                )
                wm.send_batch([a.to_dict() for a in critical_alerts])
            except Exception as exc:
                if self.console:
                    self.console.print(f"[yellow]Webhook error: {exc}[/yellow]")
                # Fallback to legacy AlertSystem
                alert_system = AlertSystem(self.config)
                for art in critical_alerts:
                    alert_system.send_alert(art)
        elif critical_alerts:
            alert_system = AlertSystem(self.config)
            for art in critical_alerts:
                alert_system.send_alert(art)

        if self.console:
            self.console.print()
            self.console.print(
                Panel(
                    f"[bold green]✓ Collection complete[/bold green]\n"
                    f"Total: {len(self.articles)} | FLASH: {stats['flash_count']} | "
                    f"CRITICAL: {stats['critical_count']} | Leaks: {stats['leak_count']}",
                    border_style="green"
                )
            )

    def _print_banner(self):
        if not self.console:
            return

        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ███████╗██╗   ██╗██╗      ██████╗██████╗ ██╗   ██╗███╗   ███╗            ║
║   ██╔════╝██║   ██║██║     ██╔════╝██╔══██╗██║   ██║████╗ ████║            ║
║   █████╗  ██║   ██║██║     ██║     ██████╔╝██║   ██║██╔████╔██║            ║
║   ██╔══╝  ██║   ██║██║     ██║     ██╔══██╗██║   ██║██║╚██╔╝██║            ║
║   ██║     ╚██████╔╝███████╗╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║            ║
║   ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝            ║
║                                                                              ║
║                    FULL SPECTRUM INTELLIGENCE PLATFORM                       ║
║                              v3.0 · OPERATIONAL                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        self.console.print(banner, style="cyan")
        self.console.print(f"[dim]Configuration: {self.config.config_path}[/dim]")
        self.console.print(f"[dim]Mode: {self.config.get('app.theme', 'ops')} | Debug: {self.config.get('app.debug', False)}[/dim]\n")

    def _print_summary(self, stats: Dict):
        if not self.console:
            return

        table = Table(title="📊 INTELLIGENCE SUMMARY", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Domain", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Critical", justify="right", style="red")
        table.add_column("Flags", justify="right")

        domains = [
            ("Cyber", stats['by_domain'].get('cyber', 0), stats['exploit_count'], "⚡"),
            ("Strategic", stats['by_domain'].get('strategic', 0), stats['nuclear_count'], "☢"),
            ("Offensive", stats['by_domain'].get('offensive', 0), stats['leak_count'], "🔓"),
        ]

        for name, total, critical, flag in domains:
            table.add_row(f"{flag} {name}", str(total), str(critical), "")

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{stats['total']}[/bold]",
            f"[bold red]{stats['critical_count'] + stats['flash_count']}[/bold red]",
            f"[bold]{stats['iocs_total']} IOCs[/bold]"
        )

        self.console.print(table)

        if stats['by_theatre']:
            th_table = Table(title="🌍 ACTIVE THEATRES", box=box.SIMPLE)
            th_table.add_column("Theatre", style="cyan")
            th_table.add_column("Signals", justify="right")
            for theatre, count in sorted(stats['by_theatre'].items(), key=lambda x: -x[1])[:5]:
                th_table.add_row(theatre.upper(), str(count))
            self.console.print(th_table)

    def _start_dashboard(self, port: int):
        import http.server
        import socketserver
        import webbrowser

        exporter = Exporter(self.config)
        html_path = exporter.export_html(self.articles, self.analyzer)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(Path(html_path).parent), **kwargs)
            def log_message(self, *args): pass

        self.console.print(f"\n[bold green]🌐 Dashboard: http://localhost:{port}/{Path(html_path).name}[/bold green]")
        self.console.print("[dim]Ctrl+C to stop[/dim]")

        try:
            with socketserver.TCPServer(("", port), Handler) as httpd:
                webbrowser.open(f"http://localhost:{port}/{Path(html_path).name}")
                httpd.serve_forever()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Dashboard stopped.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="FULCRUM — Full Spectrum Intelligence Fusion Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔══════════════════════════════════════════════════════════════════════════════╗
║ EXAMPLES                                                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  # Full fusion mode with HTML dashboard                                      ║
║  python fulcrum.py --mode fusion --export html --dashboard                   ║
║                                                                              ║
║  # Cyber-only with JSON export                                               ║
║  python fulcrum.py --mode cyber --export json --max 30                       ║
║                                                                              ║
║  # Strategic mode with theatre filter                                        ║
║  python fulcrum.py --mode strat --theatre ukraine --export html              ║
║                                                                              ║
║  # Leak focus with critical alerts only                                      ║
║  python fulcrum.py --mode leak --critical-only --export all                  ║
║                                                                              ║
║  # API server mode                                                           ║
║  python fulcrum.py --api --api-port 5000 --mode fusion                       ║
║                                                                              ║
║  # Dashboard with custom port                                                ║
║  python fulcrum.py --dashboard --port 8082                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
    )

    parser.add_argument("--config", type=Path, help="Configuration file path")
    parser.add_argument("--mode", choices=["cyber", "strat", "leak", "fusion"],
                       default="fusion", help="Intelligence mode")
    parser.add_argument("--export", choices=["json", "csv", "html", "pdf", "all"],
                       help="Export format")
    parser.add_argument("--max", type=int, help="Max items per feed")
    parser.add_argument("--critical-only", action="store_true",
                       help="Show only FLASH/CRITICAL items")
    parser.add_argument("--since", choices=["24h", "7d", "30d"],
                       help="Time filter")
    parser.add_argument("--theatre", choices=["ukraine", "middle-east", "asia-pacific", "africa", "europe"],
                       help="Filter by theatre")
    parser.add_argument("--dashboard", action="store_true",
                       help="Start web dashboard")
    parser.add_argument("--port", type=int, default=8080,
                       help="Dashboard port")
    parser.add_argument("--api", action="store_true",
                       help="Start REST API server")
    parser.add_argument("--api-port", type=int, default=5000,
                       help="API server port")
    parser.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                       help="Watch mode: repeat collection every N seconds (0=disabled)")
    parser.add_argument("--report", choices=["daily_brief", "weekly_strategic"],
                       help="Generate Jinja2 text report after collection")

    args = parser.parse_args()

    if not FEEDPARSER_AVAILABLE:
        print("❌ feedparser not installed. Run: pip install feedparser")
        sys.exit(1)

    if not REQUESTS_AVAILABLE:
        print("❌ requests not installed. Run: pip install requests")
        sys.exit(1)

    fulcrum = FULCRUM(args.config)

    if args.max:
        fulcrum.config.data['collection']['max_items_per_feed'] = args.max

    fulcrum.run(
        mode=args.mode,
        export_format=args.export,
        critical_only=args.critical_only,
        since=args.since,
        theatre=args.theatre,
        dashboard=args.dashboard,
        port=args.port,
        api=args.api,
        api_port=args.api_port,
        watch=args.watch,
        report=args.report,
    )


if __name__ == "__main__":
    main()
