"""
analyzers/takeaway_generator.py — Générateur de Key Takeaways rule-based

Produit des synthèses textuelles structurées à partir des articles FULCRUM
sans aucune dépendance IA/LLM/NLP. Tout le raisonnement est basé sur :
  - Seuils numériques (scores, volumes, compteurs)
  - Motifs de règles explicites sur les champs structurés
  - Templates textuels paramétrés par contexte

Types de takeaways :
  - daily_brief    : résumé quotidien opérationnel
  - weekly_strat   : synthèse stratégique hebdomadaire
  - incident_flash : alerte flash pour un incident majeur

Google-style docstrings. Aucune dépendance IA/LLM/NLP.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constantes de seuil pour les règles
# ---------------------------------------------------------------------------

_CRITICAL_SCORE_THRESHOLD = 85
_HIGH_SCORE_THRESHOLD = 70
_CLUSTER_SIGNIFICANT = 3      # min articles pour un cluster notable
_CVE_MANY = 5                  # seuil "nombreux CVEs"
_RANSOMWARE_SURGE_THRESHOLD = 5
_LEAK_MAJOR_THRESHOLD_M = 1.0  # millions


# ---------------------------------------------------------------------------
# Règles de signalement
# ---------------------------------------------------------------------------

def _top_n(counter: Counter, n: int = 3) -> List[Tuple[str, int]]:
    """Retourne les N éléments les plus fréquents d'un Counter.

    Args:
        counter: Counter à analyser.
        n: Nombre d'éléments à retourner.

    Returns:
        Liste de (élément, compte).
    """
    return counter.most_common(n)


def _format_list(items: List[str], max_items: int = 5, separator: str = ", ") -> str:
    """Formate une liste en chaîne lisible.

    Args:
        items: Éléments à lister.
        max_items: Nombre maximum d'éléments affichés.
        separator: Séparateur entre les éléments.

    Returns:
        Chaîne formatée, ex: "Ukraine, Russie, Iran (+2)".
    """
    if not items:
        return "N/A"
    shown = items[:max_items]
    rest = len(items) - max_items
    result = separator.join(shown)
    if rest > 0:
        result += f" (+{rest})"
    return result


# ---------------------------------------------------------------------------
# TakeawayGenerator
# ---------------------------------------------------------------------------

class TakeawayGenerator:
    """Génère des synthèses textuelles rule-based depuis les données FULCRUM.

    Aucun LLM n'est utilisé. Chaque takeaway est le résultat de l'application
    de règles explicites sur des champs structurés (scores, compteurs, listes).

    Args:
        articles: Liste de dicts articles FULCRUM.
        stats: Statistiques globales (depuis IntelligenceAnalyzer).
        clusters: Clusters d'incidents (depuis ClusterDetector).

    Example:
        >>> gen = TakeawayGenerator(articles, stats, clusters)
        >>> brief = gen.daily_brief()
        >>> print(brief["headline"])
        "Niveau de menace ÉLEVÉ — 12 alertes critiques, 3 incidents actifs"
    """

    def __init__(
        self,
        articles: List[Dict[str, Any]],
        stats: Optional[Dict[str, Any]] = None,
        clusters: Optional[Dict[str, list]] = None,
    ) -> None:
        self.articles = articles
        self.stats = stats or {}
        self.clusters = clusters or {}
        self._now = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Daily Brief
    # ------------------------------------------------------------------

    def daily_brief(self) -> Dict[str, Any]:
        """Génère un brief quotidien opérationnel.

        Synthétise la situation des dernières 24h :
        niveau de menace, alertes critiques, incidents actifs,
        principaux acteurs, CVEs prioritaires, IOCs notables.

        Returns:
            Dict avec clés : headline, threat_level, sections (list de dicts).
        """
        recent = self._filter_recent_hours(24)
        threat_level = self._compute_threat_level(recent)

        sections = []

        # Résumé chiffré
        sections.append({
            "title": "SITUATION 24H",
            "items": self._situation_24h(recent),
        })

        # Alertes critiques
        criticals = [a for a in recent if a.get("severity") in ("FLASH", "CRITICAL")]
        if criticals:
            sections.append({
                "title": "ALERTES CRITIQUES",
                "items": [
                    f"[{a.get('severity')}] {a.get('title', '')[:80]} — {a.get('source', '')}"
                    for a in criticals[:5]
                ],
            })

        # CVEs exploités
        cves_items = self._extract_active_cves(recent)
        if cves_items:
            sections.append({"title": "CVEs EXPLOITÉS", "items": cves_items})

        # Ransomware
        ransom = [a for a in recent if a.get("ransomware_related")]
        if ransom:
            groups = Counter()
            for a in ransom:
                for tag in a.get("tags", []):
                    if tag.startswith("group:"):
                        groups[tag.replace("group:", "").upper()] += 1
            items = [f"{len(ransom)} nouvelles victimes ransomware"]
            if groups:
                items.append(f"Groupes actifs : {_format_list(list(groups.keys()))}")
            sections.append({"title": "RANSOMWARE", "items": items})

        # Théâtres actifs
        theatre_items = self._theatre_summary(recent)
        if theatre_items:
            sections.append({"title": "THÉÂTRES ACTIFS", "items": theatre_items})

        # Clusters d'incidents
        cluster_items = self._cluster_summary()
        if cluster_items:
            sections.append({"title": "INCIDENTS CORRÉLÉS", "items": cluster_items})

        return {
            "type": "daily_brief",
            "generated_at": self._now.isoformat(),
            "period": "24h",
            "headline": self._daily_headline(threat_level, len(criticals), recent),
            "threat_level": threat_level,
            "sections": sections,
        }

    # ------------------------------------------------------------------
    # Weekly Strategic
    # ------------------------------------------------------------------

    def weekly_strategic(self) -> Dict[str, Any]:
        """Génère une synthèse stratégique hebdomadaire.

        Analyse les tendances sur 7 jours : évolution des volumes,
        acteurs émergents, théâtres en escalade, risques persistants.

        Returns:
            Dict avec analyse stratégique structurée.
        """
        week = self._filter_recent_hours(168)  # 7j
        sections = []

        # Tendances volumétriques
        sections.append({
            "title": "TENDANCES 7J",
            "items": self._volume_trends(week),
        })

        # Acteurs les plus actifs
        actor_counts = Counter()
        for a in week:
            for actor in a.get("actors", []):
                actor_counts[actor] += 1
        if actor_counts:
            top_actors = _top_n(actor_counts, 5)
            sections.append({
                "title": "ACTEURS DOMINANTS",
                "items": [f"{actor} — {count} signaux" for actor, count in top_actors],
            })

        # Théâtres en escalade
        escalade = self._detect_escalation(week)
        if escalade:
            sections.append({"title": "THÉÂTRES EN ESCALADE", "items": escalade})

        # APTs actifs
        apts = [a for a in week if a.get("apt_related")]
        if apts:
            apt_actors = Counter()
            for a in apts:
                for actor in a.get("actors", []):
                    if actor.startswith("Apt") or "Bear" in actor or "Typhoon" in actor:
                        apt_actors[actor] += 1
            items = [f"{len(apts)} incidents APT/nation-state détectés cette semaine"]
            if apt_actors:
                items.extend([f"• {a}: {c} incidents" for a, c in apt_actors.most_common(3)])
            sections.append({"title": "ACTIVITÉ APT", "items": items})

        # Fuites de données majeures
        leaks = [a for a in week if a.get("leak_related")]
        if leaks:
            sections.append({
                "title": "FUITES DE DONNÉES",
                "items": self._leak_summary(leaks),
            })

        # Risques nucléaires/stratégiques
        nuclear = [a for a in week if a.get("nuclear_related")]
        if nuclear:
            theatres = Counter()
            for a in nuclear:
                for t in a.get("theatres", []):
                    theatres[t] += 1
            sections.append({
                "title": "SIGNAUX NUCLÉAIRES/STRATÉGIQUES",
                "items": [
                    f"{len(nuclear)} signaux nucléaires ou de prolifération",
                    f"Zones d'intérêt : {_format_list(list(theatres.keys()))}",
                ],
            })

        return {
            "type": "weekly_strategic",
            "generated_at": self._now.isoformat(),
            "period": "7j",
            "headline": self._weekly_headline(week),
            "sections": sections,
        }

    # ------------------------------------------------------------------
    # Incident Flash
    # ------------------------------------------------------------------

    def incident_flash(self, article: Dict[str, Any]) -> Dict[str, Any]:
        """Génère une alerte flash pour un incident majeur spécifique.

        Produit une fiche structurée synthétisant l'incident :
        classification, acteurs, théâtres, IOCs, score, contexte.

        Args:
            article: Dict de l'article déclenchant l'alerte.

        Returns:
            Dict structuré pour une alerte flash.
        """
        severity = article.get("severity", "HIGH")
        risk = article.get("risk_score", 0)
        strat = article.get("strat_score", 0)
        score = risk + strat

        # Classification de l'incident
        incident_type = self._classify_incident(article)

        # Contexte historique (articles liés des 72h précédentes)
        related = self._find_related(article)

        # Évaluation de la menace
        assessment = self._threat_assessment(article)

        # IOCs clés
        iocs = article.get("iocs", {})
        ioc_summary = []
        for ioc_type, values in iocs.items():
            if values:
                ioc_summary.append(f"{ioc_type.upper()}: {_format_list(values, max_items=3)}")

        return {
            "type": "incident_flash",
            "generated_at": self._now.isoformat(),
            "classification": "FLASH" if severity == "FLASH" else "PRIORITY",
            "incident": {
                "title": article.get("title", ""),
                "type": incident_type,
                "source": article.get("source", ""),
                "severity": severity,
                "composite_score": score,
                "risk_score": risk,
                "strat_score": strat,
                "published": article.get("published", ""),
                "link": article.get("link", ""),
            },
            "actors": article.get("actors", []),
            "theatres": article.get("theatres", []),
            "cves": article.get("cves", []),
            "iocs": ioc_summary,
            "assessment": assessment,
            "related_incidents": len(related),
            "recommended_actions": self._recommend_actions(article),
        }

    # ------------------------------------------------------------------
    # Méthodes privées utilitaires
    # ------------------------------------------------------------------

    def _filter_recent_hours(self, hours: int) -> List[Dict[str, Any]]:
        """Filtre les articles publiés dans les dernières N heures.

        Args:
            hours: Fenêtre temporelle en heures.

        Returns:
            Liste d'articles récents.
        """
        cutoff = self._now - timedelta(hours=hours)
        result = []
        for a in self.articles:
            pub_str = a.get("published", "")
            try:
                pub = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                if pub >= cutoff:
                    result.append(a)
            except (ValueError, TypeError):
                pass
        return result

    def _compute_threat_level(self, articles: List[Dict[str, Any]]) -> str:
        """Évalue le niveau de menace global d'une liste d'articles.

        Règles :
          - CRITIQUE : ≥1 FLASH ou ≥3 CRITICAL
          - ÉLEVÉ : ≥1 CRITICAL ou score moyen ≥70
          - MODÉRÉ : score moyen ≥50
          - FAIBLE : sinon

        Args:
            articles: Articles à analyser.

        Returns:
            Niveau de menace : CRITIQUE, ÉLEVÉ, MODÉRÉ, FAIBLE.
        """
        if not articles:
            return "FAIBLE"

        flash = sum(1 for a in articles if a.get("severity") == "FLASH")
        critical = sum(1 for a in articles if a.get("severity") == "CRITICAL")
        avg_score = sum(a.get("risk_score", 0) for a in articles) / len(articles)

        if flash >= 1 or critical >= 3:
            return "CRITIQUE"
        elif critical >= 1 or avg_score >= 70:
            return "ÉLEVÉ"
        elif avg_score >= 50:
            return "MODÉRÉ"
        return "FAIBLE"

    def _daily_headline(
        self, threat_level: str, critical_count: int, articles: List[Dict[str, Any]]
    ) -> str:
        """Génère le titre du brief quotidien.

        Args:
            threat_level: Niveau de menace calculé.
            critical_count: Nombre d'alertes critiques.
            articles: Articles des 24h.

        Returns:
            Titre synthétique en une phrase.
        """
        clusters = len([c for c in self.clusters.values() if len(c) >= _CLUSTER_SIGNIFICANT])
        total = len(articles)

        parts = [f"Niveau de menace {threat_level}"]
        if critical_count:
            parts.append(f"{critical_count} alerte{'s' if critical_count > 1 else ''} critique{'s' if critical_count > 1 else ''}")
        if clusters:
            parts.append(f"{clusters} incident{'s' if clusters > 1 else ''} corrélé{'s' if clusters > 1 else ''}")
        parts.append(f"{total} signaux collectés")

        return " — ".join(parts)

    def _weekly_headline(self, articles: List[Dict[str, Any]]) -> str:
        """Génère le titre de la synthèse hebdomadaire.

        Args:
            articles: Articles de la semaine.

        Returns:
            Titre de synthèse.
        """
        ransomware = sum(1 for a in articles if a.get("ransomware_related"))
        nuclear = sum(1 for a in articles if a.get("nuclear_related"))
        apt = sum(1 for a in articles if a.get("apt_related"))

        dominant = []
        if ransomware > _RANSOMWARE_SURGE_THRESHOLD:
            dominant.append(f"ransomware en hausse ({ransomware} incidents)")
        if apt > 3:
            dominant.append(f"activité APT soutenue ({apt} détections)")
        if nuclear > 2:
            dominant.append(f"signaux nucléaires actifs ({nuclear})")

        if dominant:
            return f"Semaine marquée par : {_format_list(dominant, separator=' | ')}"
        return f"Semaine nominale — {len(articles)} signaux traités"

    def _situation_24h(self, articles: List[Dict[str, Any]]) -> List[str]:
        """Génère les chiffres clés des 24 dernières heures.

        Args:
            articles: Articles des 24h.

        Returns:
            Liste de chaînes descriptives.
        """
        total = len(articles)
        exploits = sum(1 for a in articles if a.get("exploit_available"))
        ransomware = sum(1 for a in articles if a.get("ransomware_related"))
        leaks = sum(1 for a in articles if a.get("leak_related"))
        nuclear = sum(1 for a in articles if a.get("nuclear_related"))
        conflict = sum(1 for a in articles if a.get("conflict_related"))

        items = [f"Total signaux : {total}"]
        if exploits:
            items.append(f"Exploits actifs : {exploits}")
        if ransomware:
            items.append(f"Incidents ransomware : {ransomware}")
        if leaks:
            items.append(f"Fuites de données : {leaks}")
        if nuclear:
            items.append(f"Signaux nucléaires : {nuclear}")
        if conflict:
            items.append(f"Incidents de conflit : {conflict}")

        return items

    def _extract_active_cves(self, articles: List[Dict[str, Any]]) -> List[str]:
        """Extrait les CVEs prioritaires avec contexte d'exploitation.

        Args:
            articles: Articles à analyser.

        Returns:
            Liste de descriptions CVE.
        """
        cve_data: Dict[str, Dict[str, Any]] = {}

        for a in articles:
            for cve in a.get("cves", []):
                if cve not in cve_data:
                    cve_data[cve] = {
                        "exploited": False,
                        "in_kev": False,
                        "sources": [],
                        "score": a.get("risk_score", 0),
                    }
                if a.get("exploit_available"):
                    cve_data[cve]["exploited"] = True
                if a.get("in_kev"):
                    cve_data[cve]["in_kev"] = True
                cve_data[cve]["sources"].append(a.get("source", ""))

        items = []
        # Prioriser exploités + KEV
        for cve, data in sorted(cve_data.items(), key=lambda x: (
            x[1]["in_kev"], x[1]["exploited"], x[1]["score"]
        ), reverse=True)[:5]:
            flags = []
            if data["in_kev"]:
                flags.append("KEV")
            if data["exploited"]:
                flags.append("EXPLOITÉ")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            items.append(f"{cve}{flag_str} — {_format_list(data['sources'], max_items=2)}")

        return items

    def _theatre_summary(self, articles: List[Dict[str, Any]]) -> List[str]:
        """Résume l'activité par théâtre géographique.

        Args:
            articles: Articles à analyser.

        Returns:
            Liste de résumés par théâtre.
        """
        theatres: Counter = Counter()
        for a in articles:
            for t in a.get("theatres", []):
                theatres[t] += 1

        items = []
        for theatre, count in theatres.most_common(5):
            # Score moyen pour ce théâtre
            theatre_arts = [a for a in articles if theatre in a.get("theatres", [])]
            avg_risk = (
                sum(a.get("risk_score", 0) for a in theatre_arts) / len(theatre_arts)
                if theatre_arts else 0
            )
            items.append(
                f"{theatre.upper()} — {count} signaux, score moyen {avg_risk:.0f}/100"
            )

        return items

    def _cluster_summary(self) -> List[str]:
        """Résume les clusters d'incidents détectés.

        Returns:
            Liste de descriptions de clusters.
        """
        items = []
        significant = {k: v for k, v in self.clusters.items() if len(v) >= _CLUSTER_SIGNIFICANT}

        for cluster_id, arts in sorted(
            significant.items(), key=lambda x: len(x[1]), reverse=True
        )[:3]:
            parts = cluster_id.split("|")
            actor = parts[0].title() if parts else "?"
            theatre = parts[1].upper() if len(parts) > 1 else "?"
            items.append(
                f"Cluster {theatre}/{actor} — {len(arts)} articles liés"
            )

        return items

    def _volume_trends(self, articles: List[Dict[str, Any]]) -> List[str]:
        """Calcule les tendances volumétriques sur 7j.

        Découpe la semaine en deux périodes de 3.5j et compare.

        Args:
            articles: Articles de la semaine.

        Returns:
            Liste de tendances chiffrées.
        """
        mid = self._now - timedelta(hours=84)  # 3.5j
        first_half = [a for a in articles if self._pub_date(a) and self._pub_date(a) < mid]
        second_half = [a for a in articles if self._pub_date(a) and self._pub_date(a) >= mid]

        total = len(articles)
        critical_week = sum(1 for a in articles if a.get("severity") in ("FLASH", "CRITICAL"))
        avg_risk = sum(a.get("risk_score", 0) for a in articles) / total if total else 0

        items = [
            f"Volume total : {total} signaux",
            f"Alertes critiques : {critical_week}",
            f"Score moyen : {avg_risk:.1f}/100",
        ]

        if first_half and second_half:
            trend = len(second_half) - len(first_half)
            direction = "↑" if trend > 0 else "↓" if trend < 0 else "→"
            items.append(
                f"Tendance volumétrique : {direction} "
                f"({len(first_half)} → {len(second_half)} signaux par demi-semaine)"
            )

        return items

    def _detect_escalation(self, articles: List[Dict[str, Any]]) -> List[str]:
        """Détecte les théâtres en escalade sur la semaine.

        Un théâtre est en escalade si son volume augmente dans
        la deuxième moitié de la semaine.

        Args:
            articles: Articles de la semaine.

        Returns:
            Liste de théâtres en escalade avec description.
        """
        mid = self._now - timedelta(hours=84)
        items = []

        # Comptage par théâtre et demi-période
        theatres = set()
        for a in articles:
            theatres.update(a.get("theatres", []))

        for theatre in theatres:
            first = sum(
                1 for a in articles
                if theatre in a.get("theatres", []) and
                self._pub_date(a) and self._pub_date(a) < mid
            )
            second = sum(
                1 for a in articles
                if theatre in a.get("theatres", []) and
                self._pub_date(a) and self._pub_date(a) >= mid
            )
            if second > first * 1.5 and second >= 2:  # +50% et au moins 2 signaux
                items.append(
                    f"{theatre.upper()} : escalade détectée ({first} → {second} signaux)"
                )

        return items

    def _leak_summary(self, leaks: List[Dict[str, Any]]) -> List[str]:
        """Génère un résumé des fuites de données.

        Args:
            leaks: Articles liés à des fuites.

        Returns:
            Liste de descriptions.
        """
        major = [a for a in leaks if a.get("leak_records") and "M" in a.get("leak_records", "")]
        items = [f"{len(leaks)} fuites de données détectées cette semaine"]
        if major:
            items.append(f"Fuites majeures (>1M) : {len(major)}")
            for a in major[:3]:
                items.append(f"• {a.get('title', '')[:60]} — {a.get('leak_records', '?')}")
        return items

    def _classify_incident(self, article: Dict[str, Any]) -> str:
        """Classifie le type d'incident d'un article.

        Args:
            article: Article à classifier.

        Returns:
            Type d'incident en texte.
        """
        if article.get("nuclear_related"):
            return "Signalement nucléaire / prolifération"
        if article.get("exploit_available") and article.get("in_kev"):
            return "Exploitation active (KEV + exploit confirmé)"
        if article.get("exploit_available"):
            return "Exploitation active (CVE / 0-day)"
        if article.get("ransomware_related"):
            return "Attaque ransomware / extorsion"
        if article.get("leak_related"):
            return "Fuite / violation de données"
        if article.get("apt_related"):
            return "Activité APT / acteur étatique"
        if article.get("conflict_related"):
            return "Incident de conflit armé"
        if article.get("aerospace_related"):
            return "Incident aérospatial / missile"
        return "Incident de sécurité (générique)"

    def _threat_assessment(self, article: Dict[str, Any]) -> str:
        """Génère une évaluation de la menace pour un article.

        Règles strictement basées sur les champs structurés.

        Args:
            article: Article à évaluer.

        Returns:
            Phrase d'évaluation.
        """
        risk = article.get("risk_score", 0)
        strat = article.get("strat_score", 0)
        actors = article.get("actors", [])
        theatres = article.get("theatres", [])

        parts = []

        if risk >= 80:
            parts.append("Menace cyber immédiate et critique")
        elif risk >= 60:
            parts.append("Menace cyber significative")
        else:
            parts.append("Menace cyber modérée")

        if strat >= 60:
            parts.append("impact géostratégique majeur")
        elif strat >= 30:
            parts.append("implications stratégiques notables")

        if actors:
            parts.append(f"acteurs identifiés : {_format_list(actors, max_items=3)}")
        if theatres:
            parts.append(f"zones affectées : {_format_list(theatres, max_items=3)}")

        return " | ".join(parts)

    def _recommend_actions(self, article: Dict[str, Any]) -> List[str]:
        """Génère des recommandations d'actions basées sur le type d'incident.

        Les recommandations sont dérivées de règles par type d'incident,
        sans aucune génération IA.

        Args:
            article: Article source de l'incident.

        Returns:
            Liste de recommandations concrètes.
        """
        actions = []

        if article.get("exploit_available") or article.get("in_kev"):
            actions.append("Appliquer les correctifs disponibles en urgence (SLA 24-72h)")
            actions.append("Vérifier exposition dans les systèmes exposés")

        if article.get("cves"):
            cves = ", ".join(article["cves"][:3])
            actions.append(f"Scanner l'infrastructure pour {cves}")

        if article.get("ransomware_related"):
            actions.append("Vérifier les sauvegardes et leur isolation réseau")
            actions.append("Surveiller les indicateurs d'exfiltration dans les logs")

        if article.get("iocs", {}).get("ipv4"):
            actions.append("Bloquer les IPs malveillantes dans les firewalls")

        if article.get("iocs", {}).get("domain"):
            actions.append("Ajouter les domaines malveillants au DNS sinkhoring")

        if article.get("nuclear_related") or article.get("conflict_related"):
            actions.append("Escalader vers l'équipe stratégique/géopolitique")
            actions.append("Mettre à jour la carte de menace du théâtre concerné")

        if article.get("apt_related"):
            actions.append("Comparer les TTPs aux campagnes APT connues (MITRE ATT&CK)")
            actions.append("Effectuer une chasse aux menaces ciblée")

        if not actions:
            actions.append("Maintenir la surveillance et documenter dans la base d'incidents")

        return actions

    def _find_related(
        self, article: Dict[str, Any], max_hours: int = 72
    ) -> List[Dict[str, Any]]:
        """Trouve les articles liés dans une fenêtre temporelle.

        Args:
            article: Article de référence.
            max_hours: Fenêtre en heures.

        Returns:
            Articles liés (mêmes acteurs OU mêmes théâtres).
        """
        pub = self._pub_date(article)
        if not pub:
            return []

        cutoff = pub - timedelta(hours=max_hours)
        art_actors = set(article.get("actors", []))
        art_theatres = set(article.get("theatres", []))

        related = []
        for a in self.articles:
            if a.get("id") == article.get("id"):
                continue
            a_pub = self._pub_date(a)
            if not a_pub or a_pub < cutoff:
                continue
            a_actors = set(a.get("actors", []))
            a_theatres = set(a.get("theatres", []))
            if (art_actors & a_actors) or (art_theatres & a_theatres):
                related.append(a)

        return related

    @staticmethod
    def _pub_date(article: Dict[str, Any]) -> Optional[datetime]:
        """Parse la date de publication d'un article.

        Args:
            article: Article à parser.

        Returns:
            Datetime ou None.
        """
        pub_str = article.get("published", "")
        if not pub_str:
            return None
        try:
            return datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
