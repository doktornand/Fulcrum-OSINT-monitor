# FULCRUM — Quick Catch-Up

**Date :** 2026-03-24 · **Tests :** 97/97 ✓ · **Contrainte :** zéro IA/LLM/NLP

---

## État actuel

Monolithe `fulcrum2e.py` refactorisé en architecture modulaire complète. Tous les modules sont branchés sur l'orchestrateur avec fallback gracieux si dépendance absente.

```
collectors/   rss_collector.py · api_collector.py (CISA KEV, ACLED)
analyzers/    scoring_engine.py · ioc_extractor.py · correlator.py · takeaway_generator.py
persistence/  sqlite_store.py (WAL, pruning 90j)
alerts/       webhook_manager.py (Slack · Discord · Telegram)
exporters/    html_dashboard.py · json_exporter.py · report_generator.py
orchestration/ scheduler.py (APScheduler + circuit breaker)
templates/    daily_brief.j2 · weekly_strategic.j2 · incident_flash.j2
```

---

## Lancement

```bash
# Dépendances minimales
pip install feedparser requests pyyaml rich

# Dépendances complètes (recommandé)
pip install feedparser requests pyyaml rich beautifulsoup4 lxml jinja2 apscheduler

# Collecte fusion + dashboard HTML
python fulcrum2e.py --mode fusion --export html

# Avec rapport texte quotidien
python fulcrum2e.py --export html --report daily_brief

# Mode watch (relance toutes les 5 min)
python fulcrum2e.py --watch 300 --export html

# Cyber uniquement, 24h, alertes critiques
python fulcrum2e.py --mode cyber --since 24h --critical-only --export json

# Lancer les tests
python -m pytest tests/ -q
```

---

## Prochaines étapes

| Priorité | Item | Fichier cible |
|---|---|---|
| **haute** | Charts Plotly inline (histogramme, timeline 7j, répartition théâtres) | `exporters/html_dashboard.py` |
| **haute** | Carte Leaflet géolocalisée par théâtre (coordonnées statiques) | `exporters/html_dashboard.py` |
| **moyenne** | Export PDF via weasyprint | `exporters/pdf_exporter.py` (à créer) |
| **basse** | Telegram monitoring (Telethon, canaux OSINT publics) | `collectors/telegram_collector.py` (à créer) |

---

## Points d'attention

- **Config :** `fulcrum_config.yml` — sections `intelligence.scoring.source_reliability`, `persistence.db_path`, `alerts.*`
- **SQLite :** base créée automatiquement à `fulcrum_intel.db` au premier lancement
- **Anti-inflation CRITICAL :** activé par défaut — un article « CRITICAL » sans exploit confirmé ni acteur étatique est dégradé en HIGH
- **SimHash :** déduplication fuzzy seuil 0.85 — les agrégateurs qui republient le même article sont filtrés
- **Breakdowns de score :** champs `risk_score_breakdown` / `strat_score_breakdown` exportés en JSON pour le dashboard drill-down
