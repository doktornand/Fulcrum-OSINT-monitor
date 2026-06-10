"""
config_loader.py — FULCRUM Configuration Loader with Pydantic Validation

Charge et valide la configuration YAML selon des schémas stricts.
Supporte le hot-reload et la validation Pydantic v2.

Google-style docstrings throughout.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml

logger = logging.getLogger("FULCRUM.config")

# ---------------------------------------------------------------------------
# Pydantic optionnel — fallback dataclass si absent
# ---------------------------------------------------------------------------
try:
    from pydantic import BaseModel, Field, field_validator, model_validator
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    logger.warning("pydantic non disponible — validation minimale activée")

# ---------------------------------------------------------------------------
# Schémas Pydantic
# ---------------------------------------------------------------------------

if PYDANTIC_AVAILABLE:

    class AppConfig(BaseModel):
        """Configuration applicative globale."""

        name: str = "FULCRUM Intelligence Platform"
        version: str = "3.0"
        theme: str = "ops"
        timezone: str = "UTC"
        debug: bool = False
        user_agent: str = "FULCRUM/3.0"

    class CollectionConfig(BaseModel):
        """Paramètres de collecte RSS/API."""

        max_items_per_feed: int = Field(25, ge=1, le=200)
        request_timeout: int = Field(15, ge=1, le=120)
        retry_attempts: int = Field(3, ge=0, le=10)
        retry_backoff: float = Field(1.5, ge=1.0, le=10.0)
        concurrent_workers: int = Field(10, ge=1, le=50)
        rate_limit_per_host: int = Field(2, ge=1, le=20)
        user_agent_rotation: bool = True
        proxy_rotation: bool = False
        deduplicate: bool = True
        scraping_enabled: bool = True
        leak_focused_mode: bool = False

    class CacheConfig(BaseModel):
        """Configuration du cache."""

        enabled: bool = True
        type: str = "memory"
        redis_url: str = "redis://localhost:6379/0"
        ttl_seconds: int = Field(3600, ge=60)
        memory_max_items: int = Field(1000, ge=100)

        @field_validator("type")
        @classmethod
        def validate_type(cls, v: str) -> str:
            """Vérifie que le type de cache est supporté."""
            if v not in ("memory", "redis"):
                raise ValueError(f"type doit être 'memory' ou 'redis', reçu: {v}")
            return v

    class ScoringWeightsConfig(BaseModel):
        """Pondérations du scoring de risque."""

        risk_weights: Dict[str, int] = Field(
            default_factory=lambda: {
                "critical": 40, "exploit": 15, "kev": 15,
                "ransomware": 12, "apt": 10, "darkweb": 8,
            }
        )
        strat_weights: Dict[str, int] = Field(
            default_factory=lambda: {
                "nuclear": 25, "conflict": 15, "weapons": 10,
                "aerospace": 8, "sanctions": 7, "intel": 10,
            }
        )
        # Pondération par fiabilité de source (configurable)
        source_reliability: Dict[str, float] = Field(
            default_factory=lambda: {
                "CISA KEV Catalog": 1.0,
                "NVD National Vuln DB": 1.0,
                "ANSSI – Alertes": 1.0,
                "Krebs on Security": 0.95,
                "Cisco Talos": 0.95,
                "CrowdStrike Blog": 0.9,
                "Mandiant": 0.95,
                "Unit42": 0.9,
                "default": 0.7,
            }
        )
        # Bonus/malus temporel (fraîcheur)
        freshness_bonus_24h: int = 10
        freshness_bonus_72h: int = 5
        freshness_malus_7d: int = -5

    class ThresholdsConfig(BaseModel):
        """Seuils de classification de sévérité."""

        critical_score: int = Field(85, ge=0, le=100)
        high_score: int = Field(70, ge=0, le=100)
        medium_score: int = Field(50, ge=0, le=100)
        flash_threshold: int = Field(90, ge=0, le=100)
        # Seuil minimal pour qualifier CRITICAL (anti-inflation)
        critical_requires_exploit_or_actor: bool = True

    class IntelligenceConfig(BaseModel):
        """Configuration de l'analyse d'intelligence."""

        scoring: ScoringWeightsConfig = Field(default_factory=ScoringWeightsConfig)
        thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)

        # Blacklist anti-faux-positifs contextuels
        false_positive_blacklist: List[str] = Field(
            default_factory=lambda: [
                "nuclear family", "atomic clock", "nuclear power plant safety",
                "nuclear medicine", "bomb squad training", "critical thinking",
                "critical care", "critical hit", "nuclear pasta",
                "missile defense spending", "weapons of mass destruction museum",
            ]
        )

    class ExportConfig(BaseModel):
        """Configuration des exports."""

        default_format: str = "html"
        paths: Dict[str, str] = Field(
            default_factory=lambda: {
                "json": "fulcrum_export.json",
                "csv": "fulcrum_export.csv",
                "html": "fulcrum_dashboard.html",
                "pdf": "fulcrum_report.pdf",
            }
        )
        auto_generate: bool = True

    class AlertsConfig(BaseModel):
        """Configuration des alertes."""

        webhooks: List[str] = Field(default_factory=list)
        telegram_bot_token: Optional[str] = None
        telegram_chat_id: Optional[str] = None
        slack_webhook: Optional[str] = None
        discord_webhook: Optional[str] = None
        critical_only: bool = False

    class PersistenceConfig(BaseModel):
        """Configuration de la persistance SQLite."""

        enabled: bool = True
        db_path: str = "fulcrum.db"
        retention_days: int = Field(90, ge=1)
        archive_days: int = Field(365, ge=90)
        simhash_threshold: float = Field(0.85, ge=0.5, le=1.0)

    class FeedConfig(BaseModel):
        """Configuration d'un flux RSS/API individuel."""

        name: str
        url: str
        priority: Optional[str] = None
        confidence: int = Field(5, ge=0, le=10)
        max_items: Optional[int] = None
        tags: List[str] = Field(default_factory=list)

        @field_validator("priority")
        @classmethod
        def validate_priority(cls, v: Optional[str]) -> Optional[str]:
            """Vérifie les valeurs de priorité autorisées."""
            if v is not None and v not in ("critical", "high", "medium", "low"):
                raise ValueError(f"priority doit être critical/high/medium/low, reçu: {v}")
            return v

    class CategoryConfig(BaseModel):
        """Configuration d'une catégorie de sources."""

        name: str
        color: str = "#ffffff"
        priority: int = Field(2, ge=0, le=5)
        feeds: List[FeedConfig] = Field(default_factory=list)

    class FulcrumConfig(BaseModel):
        """Schéma racine de configuration FULCRUM."""

        app: AppConfig = Field(default_factory=AppConfig)
        collection: CollectionConfig = Field(default_factory=CollectionConfig)
        cache: CacheConfig = Field(default_factory=CacheConfig)
        intelligence: IntelligenceConfig = Field(default_factory=IntelligenceConfig)
        export: ExportConfig = Field(default_factory=ExportConfig)
        alerts: AlertsConfig = Field(default_factory=AlertsConfig)
        persistence: PersistenceConfig = Field(default_factory=PersistenceConfig)
        categories: List[CategoryConfig] = Field(default_factory=list)

        @model_validator(mode="after")
        def validate_thresholds_order(self) -> "FulcrumConfig":
            """Vérifie l'ordre cohérent des seuils de sévérité."""
            t = self.intelligence.thresholds
            if not (t.medium_score < t.high_score < t.critical_score):
                raise ValueError(
                    "Les seuils doivent respecter : medium < high < critical"
                )
            return self

        def get(self, key: str, default: Any = None) -> Any:
            """Accès par dot-notation (ex: 'collection.timeout')."""
            keys = key.split(".")
            obj: Any = self
            for k in keys:
                if isinstance(obj, dict):
                    obj = obj.get(k)
                elif hasattr(obj, k):
                    obj = getattr(obj, k)
                else:
                    return default
                if obj is None:
                    return default
            return obj

        def __getitem__(self, key: str) -> Any:
            return self.get(key)


# ---------------------------------------------------------------------------
# ConfigLoader : chargement + validation
# ---------------------------------------------------------------------------

class ConfigLoader:
    """Charge, valide et expose la configuration FULCRUM.

    Args:
        config_path: Chemin vers le fichier YAML/JSON de configuration.

    Attributes:
        config: Instance validée de FulcrumConfig (ou dict si Pydantic absent).
        raw: Dictionnaire brut chargé depuis le fichier.
    """

    DEFAULT_PATH = Path(__file__).parent / "fulcrum_config.yml"

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = Path(config_path) if config_path else self.DEFAULT_PATH
        self.raw: Dict[str, Any] = {}
        self.config = self._load_and_validate()

    # ------------------------------------------------------------------
    # Chargement
    # ------------------------------------------------------------------

    def _load_and_validate(self):
        """Charge le fichier de configuration et le valide.

        Returns:
            Instance FulcrumConfig validée, ou dict en fallback.

        Raises:
            RuntimeError: Si le fichier existe mais ne peut pas être parsé.
        """
        raw = self._read_file()
        self.raw = raw

        if PYDANTIC_AVAILABLE:
            try:
                return FulcrumConfig(**raw)
            except Exception as exc:
                logger.error(f"Erreur validation config Pydantic: {exc}")
                logger.warning("Utilisation de la config brute sans validation")
                return _DictConfig(raw)
        else:
            return _DictConfig(raw)

    def _read_file(self) -> Dict[str, Any]:
        """Lit et parse le fichier de configuration.

        Returns:
            Dictionnaire de configuration.
        """
        if not self.config_path.exists():
            logger.warning(f"Config {self.config_path} introuvable — valeurs par défaut")
            return {}

        suffix = self.config_path.suffix.lower()
        try:
            with open(self.config_path, encoding="utf-8") as f:
                if suffix in (".yml", ".yaml"):
                    return yaml.safe_load(f) or {}
                elif suffix == ".json":
                    return json.load(f)
                else:
                    raise ValueError(f"Format non supporté: {suffix}")
        except Exception as exc:
            raise RuntimeError(f"Impossible de lire {self.config_path}: {exc}") from exc

    # ------------------------------------------------------------------
    # Hot-reload
    # ------------------------------------------------------------------

    def reload(self) -> None:
        """Recharge la configuration depuis le disque (hot-reload)."""
        logger.info("Hot-reload de la configuration...")
        self.config = self._load_and_validate()
        logger.info("Configuration rechargée avec succès")


# ---------------------------------------------------------------------------
# Fallback _DictConfig quand Pydantic n'est pas disponible
# ---------------------------------------------------------------------------

class _DictConfig:
    """Config minimale par dict quand Pydantic est absent."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def get(self, key: str, default: Any = None) -> Any:
        """Accès par dot-notation."""
        keys = key.split(".")
        v = self._data
        for k in keys:
            if isinstance(v, dict):
                v = v.get(k)
            else:
                return default
            if v is None:
                return default
        return v

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    def __getattr__(self, key: str) -> Any:
        if key.startswith("_"):
            raise AttributeError(key)
        return self._data.get(key)
