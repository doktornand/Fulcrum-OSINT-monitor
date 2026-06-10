"""
analyzers/scoring_engine.py — Moteur de scoring FULCRUM (rule-based)

Améliorations vs fulcrum2e.py :
  - Pondération par fiabilité de source (configurable YAML)
  - Détection faux-positifs : blacklist mots contextuels
  - Réduction inflation CRITICAL : plafonnement aux vrais indicateurs
  - Scoring temporel : bonus/malus fraîcheur (24h/72h/7j)
  - Décomposition explicite du score pour l'affichage

Google-style docstrings. Aucune dépendance IA/LLM/NLP.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any

# ---------------------------------------------------------------------------
# Blacklist anti-faux-positifs contextuels
# ---------------------------------------------------------------------------

_DEFAULT_FALSE_POSITIVE_PHRASES = frozenset([
    "nuclear family",
    "atomic clock",
    "nuclear power plant safety",
    "nuclear medicine",
    "bomb squad training",
    "critical thinking",
    "critical care",
    "critical hit",
    "nuclear pasta",
    "missile defense spending",
    "weapons of mass destruction museum",
    "strategic planning",
    "crisis management course",
    "nuclear reactor safety",
    "defense budget",
    "ballistic performance",      # équipements sportifs
    "explosive growth",           # finance
    "nuclear option",             # politique parlementaire
    "cyber monday",
    "cyber hygiene tips",
    "zero-day sale",              # promotions commerciales
])


def _contains_false_positive(text: str, custom_blacklist: Optional[List[str]] = None) -> bool:
    """Vérifie si le texte contient une phrase de faux-positif connu.

    Args:
        text: Texte normalisé en minuscules.
        custom_blacklist: Liste supplémentaire de phrases à exclure.

    Returns:
        True si au moins une phrase blacklistée est trouvée.
    """
    blacklist = _DEFAULT_FALSE_POSITIVE_PHRASES
    if custom_blacklist:
        blacklist = blacklist | frozenset(p.lower() for p in custom_blacklist)

    text_lower = text.lower()
    return any(phrase in text_lower for phrase in blacklist)


# ---------------------------------------------------------------------------
# Pondération source
# ---------------------------------------------------------------------------

_DEFAULT_SOURCE_RELIABILITY: Dict[str, float] = {
    "CISA KEV Catalog": 1.0,
    "NVD National Vuln DB": 1.0,
    "ANSSI – Alertes": 1.0,
    "CERT-FR – Bulletins": 1.0,
    "Krebs on Security": 0.95,
    "Cisco Talos": 0.95,
    "CrowdStrike Blog": 0.90,
    "Mandiant": 0.95,
    "Mandiant APT Research": 0.95,
    "Unit42": 0.90,
    "Securelist": 0.88,
    "RAND Corporation": 0.90,
    "ISW — War Updates": 0.85,
    "ISW — Ukraine/Russia": 0.85,
    "Bellingcat OSINT": 0.85,
    "HaveIBeenPwned": 1.0,
    "ThreatFox IOCs": 0.88,
    "MalwareBazaar": 0.88,
    "Exploit-DB": 0.85,
    "Project Zero": 0.95,
    "AIEA — Actualités": 0.95,
    "NTI — Atomic Pulse": 0.90,
    "Bulletin of the Atomic Scientists": 0.90,
    "_default": 0.70,
}


def get_source_reliability(
    source_name: str,
    config_weights: Optional[Dict[str, float]] = None,
) -> float:
    """Retourne le coefficient de fiabilité d'une source.

    Args:
        source_name: Nom de la source tel que défini dans la config.
        config_weights: Pondérations personnalisées depuis le YAML.

    Returns:
        Coefficient entre 0.0 et 1.0.
    """
    weights = dict(_DEFAULT_SOURCE_RELIABILITY)
    if config_weights:
        weights.update(config_weights)

    return weights.get(source_name, weights["_default"])


# ---------------------------------------------------------------------------
# Scoring temporel
# ---------------------------------------------------------------------------

def compute_freshness_bonus(published_iso: str) -> int:
    """Calcule le bonus/malus de fraîcheur d'un article.

    Args:
        published_iso: Date de publication au format ISO 8601.

    Returns:
        Bonus (positif) ou malus (négatif) à ajouter au score.
    """
    try:
        pub = datetime.fromisoformat(published_iso.replace("Z", "+00:00"))
        age = datetime.now(timezone.utc) - pub
    except (ValueError, TypeError):
        return 0

    if age <= timedelta(hours=24):
        return 10
    elif age <= timedelta(hours=72):
        return 5
    elif age <= timedelta(days=7):
        return 0
    else:
        return -5


# ---------------------------------------------------------------------------
# Score explicable — décomposition
# ---------------------------------------------------------------------------

class ScoreBreakdown:
    """Décomposition explicable d'un score FULCRUM.

    Attributes:
        components: Liste des contributions (label, valeur).
        total: Score final.
    """

    def __init__(self) -> None:
        self.components: List[Tuple[str, int]] = []
        self.total: int = 0

    def add(self, label: str, value: int) -> "ScoreBreakdown":
        """Ajoute une composante au score.

        Args:
            label: Description de la composante.
            value: Points contributés (peut être négatif).

        Returns:
            Self pour chaînage.
        """
        if value != 0:
            self.components.append((label, value))
            self.total += value
        return self

    def cap(self, maximum: int = 100) -> "ScoreBreakdown":
        """Plafonne le score total.

        Args:
            maximum: Valeur maximale autorisée.

        Returns:
            Self pour chaînage.
        """
        self.total = min(self.total, maximum)
        return self

    def floor(self, minimum: int = 0) -> "ScoreBreakdown":
        """Plancher le score total.

        Args:
            minimum: Valeur minimale autorisée.

        Returns:
            Self pour chaînage.
        """
        self.total = max(self.total, minimum)
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Sérialise la décomposition.

        Returns:
            Dict avec 'total' et 'breakdown' (liste de [label, value]).
        """
        return {
            "total": self.total,
            "breakdown": [{"label": lbl, "value": val} for lbl, val in self.components],
        }

    def __str__(self) -> str:
        parts = " | ".join(f"{lbl}: {val:+d}" for lbl, val in self.components)
        return f"[Score {self.total}] {parts}"


# ---------------------------------------------------------------------------
# ScoringEngine principal
# ---------------------------------------------------------------------------

class ScoringEngine:
    """Moteur de scoring rule-based pour les articles FULCRUM.

    Calcule risk_score et strat_score avec décomposition explicite.
    Applique filtrage faux-positifs et pondération source.

    Args:
        source_weights: Pondérations source personnalisées (depuis config).
        false_positive_blacklist: Phrases à considérer comme faux-positifs.
        critical_requires_exploit_or_actor: Si True, CRITICAL exige un exploit
            OU un acteur étatique confirmé pour éviter l'inflation.

    Example:
        >>> engine = ScoringEngine()
        >>> score = engine.compute_risk_score(article)
        >>> print(score)
        [Score 72] base: +30 | exploit: +15 | freshness: +10 | source: +12
    """

    # Sévérités de base
    _SEVERITY_BASE: Dict[str, int] = {
        "FLASH": 55,
        "CRITICAL": 45,
        "HIGH": 30,
        "MEDIUM": 20,
        "WATCH": 10,
        "INFO": 5,
    }

    def __init__(
        self,
        source_weights: Optional[Dict[str, float]] = None,
        false_positive_blacklist: Optional[List[str]] = None,
        critical_requires_exploit_or_actor: bool = True,
    ) -> None:
        self.source_weights = source_weights or {}
        self.false_positive_blacklist = false_positive_blacklist or []
        self.critical_requires_exploit_or_actor = critical_requires_exploit_or_actor

    # ------------------------------------------------------------------
    # Sévérité
    # ------------------------------------------------------------------

    def compute_severity(self, title: str, summary: str, cvss_score: Optional[float]) -> str:
        """Détermine la sévérité d'un article.

        Applique la blacklist anti-faux-positifs avant toute classification.

        Args:
            title: Titre de l'article.
            summary: Résumé de l'article.
            cvss_score: Score CVSS si disponible.

        Returns:
            Sévérité en majuscules : FLASH, CRITICAL, HIGH, MEDIUM, WATCH, INFO.
        """
        full = f"{title} {summary}"
        full_upper = full.upper()

        # Vérification faux-positifs avant tout
        if _contains_false_positive(full, self.false_positive_blacklist):
            return "INFO"

        # FLASH : évènements à impact immédiat
        if any(x in full_upper for x in [
            "NUCLEAR LAUNCH", "BALLISTIC MISSILE LAUNCH", "DECLARATION OF WAR",
            "ACTIVE SHOOTER", "TERROR ATTACK", "STATE OF EMERGENCY",
        ]):
            return "FLASH"

        # CRITICAL : avec plafonnement anti-inflation si requis
        is_critical_candidate = any(x in full_upper for x in [
            "CRITICAL", "CVE-202", "RCE", "0DAY", "ZERO-DAY",
            "NUCLEAR TEST", "WARHEAD", "ICBM",
        ])
        if is_critical_candidate:
            if not self.critical_requires_exploit_or_actor:
                return "CRITICAL"
            # Anti-inflation : exiger exploit + contexte confirmé
            has_exploit_signal = any(x in full_upper for x in [
                "ACTIVELY EXPLOITED", "IN THE WILD", "EXPLOIT AVAILABLE",
                "METASPLOIT", "POC", "PROOF-OF-CONCEPT",
            ])
            has_state_actor = any(x in full_upper for x in [
                "APT", "NATION-STATE", "STATE-SPONSORED", "LAZARUS",
                "FANCY BEAR", "VOLT TYPHOON", "SANDWORM",
            ])
            if has_exploit_signal or has_state_actor:
                return "CRITICAL"
            # Dégrade à HIGH si pas de signal confirmé
            return "HIGH"

        if any(x in full_upper for x in [
            "HIGH SEVERITY", "URGENT", "ACTIVELY EXPLOITED", "ESCALATION",
            "INVASION", "AIRSTRIKE", "GROUND OFFENSIVE",
        ]):
            return "HIGH"

        if any(x in full_upper for x in [
            "MEDIUM", "MODERATE", "BREACH", "LEAK", "SANCTIONS",
            "MILITARY EXERCISE", "DEPLOYMENT", "CEASEFIRE",
        ]):
            return "MEDIUM"

        if any(x in full_upper for x in [
            "ANALYSIS", "REPORT", "ASSESSMENT", "STRATEGY",
            "MODERNIZATION", "PROCUREMENT", "REVIEW",
        ]):
            return "WATCH"

        # CVSS override
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return "CRITICAL"
            elif cvss_score >= 7.0:
                return "HIGH"
            elif cvss_score >= 4.0:
                return "MEDIUM"

        return "INFO"

    # ------------------------------------------------------------------
    # Risk Score
    # ------------------------------------------------------------------

    def compute_risk_score(
        self,
        severity: str,
        source_name: str,
        published_iso: str,
        exploit_available: bool = False,
        in_kev: bool = False,
        ransomware_related: bool = False,
        apt_related: bool = False,
        darkweb_related: bool = False,
        extortion_related: bool = False,
        leak_records: Optional[str] = None,
        cvss_score: Optional[float] = None,
        confidence: int = 5,
    ) -> ScoreBreakdown:
        """Calcule le score de risque cyber avec décomposition complète.

        Args:
            severity: Niveau de sévérité (FLASH, CRITICAL, HIGH…).
            source_name: Nom de la source.
            published_iso: Date de publication ISO 8601.
            exploit_available: Exploit public disponible.
            in_kev: Dans le catalogue KEV de la CISA.
            ransomware_related: Lié à du ransomware.
            apt_related: Lié à un APT/acteur étatique.
            darkweb_related: Mentionné sur le dark web.
            extortion_related: Implique de l'extorsion.
            leak_records: Nombre d'enregistrements exposés (ex: "5M records").
            cvss_score: Score CVSS numérique.
            confidence: Niveau de confiance de la source (0-10).

        Returns:
            ScoreBreakdown avec décomposition et total plafonné à 100.
        """
        bd = ScoreBreakdown()

        # Base sévérité
        bd.add(f"severity({severity})", self._SEVERITY_BASE.get(severity, 10))

        # Signaux de risque
        if exploit_available:
            bd.add("exploit_available", 12)
        if in_kev:
            bd.add("in_kev", 12)
        if ransomware_related:
            bd.add("ransomware", 10)
        if apt_related:
            bd.add("apt", 8)
        if darkweb_related:
            bd.add("darkweb", 7)
        if extortion_related:
            bd.add("extortion", 8)

        # Volume de fuite
        if leak_records:
            bd.add("leak_volume", self._score_leak_volume(leak_records))

        # CVSS
        if cvss_score is not None:
            bd.add("cvss", int(cvss_score * 2))

        # Pondération source
        reliability = get_source_reliability(source_name, self.source_weights)
        reliability_bonus = int((reliability - 0.70) * 20)  # max +6 pour source parfaite
        bd.add(f"source_reliability({reliability:.2f})", reliability_bonus)

        # Confiance source (0-10 → 0 à +4)
        confidence_bonus = int((confidence / 10) * 4)
        bd.add(f"confidence({confidence}/10)", confidence_bonus)

        # Fraîcheur temporelle
        freshness = compute_freshness_bonus(published_iso)
        bd.add("freshness", freshness)

        return bd.floor(0).cap(100)

    def _score_leak_volume(self, leak_records: str) -> int:
        """Traduit un volume de fuite en points.

        Args:
            leak_records: Ex: "5.2M records", "100K records".

        Returns:
            Points de score pour le volume.
        """
        try:
            if "B" in leak_records.upper() or "billion" in leak_records.lower():
                return 20
            if "M" in leak_records:
                num = float(leak_records.split("M")[0].strip())
                if num > 100:
                    return 15
                elif num > 10:
                    return 10
                return 5
            if "K" in leak_records:
                num = float(leak_records.split("K")[0].strip())
                if num > 500:
                    return 5
                return 2
        except (ValueError, AttributeError):
            pass
        return 3

    # ------------------------------------------------------------------
    # Strat Score
    # ------------------------------------------------------------------

    def compute_strat_score(
        self,
        severity: str,
        nuclear_related: bool = False,
        conflict_related: bool = False,
        weapons_related: bool = False,
        aerospace_related: bool = False,
        sanctions_related: bool = False,
        intel_related: bool = False,
        actors_count: int = 0,
        theatres_count: int = 0,
        source_name: str = "",
        published_iso: str = "",
    ) -> ScoreBreakdown:
        """Calcule le score de risque géostratégique.

        Args:
            severity: Niveau de sévérité.
            nuclear_related: Dimension nucléaire détectée.
            conflict_related: Dimension conflit armé.
            weapons_related: Systèmes d'armes mentionnés.
            aerospace_related: Dimension aérospatiale.
            sanctions_related: Sanctions économiques.
            intel_related: Dimension renseignement.
            actors_count: Nombre d'acteurs étatiques identifiés.
            theatres_count: Nombre de théâtres géographiques.
            source_name: Nom de la source.
            published_iso: Date de publication ISO 8601.

        Returns:
            ScoreBreakdown avec décomposition et total plafonné à 100.
        """
        bd = ScoreBreakdown()

        if nuclear_related:
            bd.add("nuclear", 25)
        if conflict_related:
            bd.add("conflict", 15)
        if weapons_related:
            bd.add("weapons", 10)
        if aerospace_related:
            bd.add("aerospace", 8)
        if sanctions_related:
            bd.add("sanctions", 7)
        if intel_related:
            bd.add("intel", 8)

        if actors_count >= 3:
            bd.add("multi_actor", 5)
        elif actors_count >= 1:
            bd.add("actor", 2)

        if theatres_count >= 2:
            bd.add("multi_theatre", 5)

        severity_boost = {
            "FLASH": 20, "CRITICAL": 15, "HIGH": 10,
            "MEDIUM": 5, "WATCH": 3, "INFO": 0,
        }
        bd.add(f"severity_boost({severity})", severity_boost.get(severity, 0))

        # Pondération source + fraîcheur
        reliability = get_source_reliability(source_name, self.source_weights)
        bd.add(f"source_reliability({reliability:.2f})", int((reliability - 0.70) * 15))

        freshness = compute_freshness_bonus(published_iso)
        bd.add("freshness", freshness // 2)  # fraîcheur moins pesante côté strat

        return bd.floor(0).cap(100)
