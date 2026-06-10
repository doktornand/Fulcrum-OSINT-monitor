# FULCRUM — Architecture Technique v3.1

## Vue d'ensemble

FULCRUM est une plateforme d'intelligence multi-spectre (cyber, géostratégique, offensif)
basée sur une architecture **rule-based** sans dépendance IA/LLM/NLP.

```
┌─────────────────────────────────────────────────────────────────┐
│                    FULCRUM v3.1 Architecture                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────┐  │
│  │  collectors/ │  │  analyzers/  │  │    persistence/     │  │
│  │              │  │              │  │                     │  │
│  │ rss_          │  │ scoring_     │  │ sqlite_store.py    │  │
│  │ collector.py │  │ engine.py    │  │ cache_manager.py   │  │
│  │              │  │              │  │                     │  │
│  │ api_          │  │ ioc_         │  └─────────────────────┘  │
│  │ collector.py │  │ extractor.py │                            │
│  │  (CISA KEV,  │  │              │  ┌─────────────────────┐  │
│  │   ACLED,     │  │ correlator.py│  │     exporters/      │  │
│  │   Ransomware)│  │  (SimHash,   │  │                     │  │
│  │              │  │   clusters)  │  │ html_dashboard.py  │  │
│  └──────────────┘  └──────────────┘  │ json_exporter.py   │  │
│                                       │ pdf_exporter.py    │  │
│  ┌──────────────┐                    └─────────────────────┘  │
│  │   alerts/    │                                              │
│  │              │  ┌─────────────────────────────────────┐   │
│  │ webhook_     │  │         config_loader.py            │   │
│  │ manager.py   │  │    (Pydantic v2 + YAML validation)  │   │
│  │ telegram_    │  └─────────────────────────────────────┘   │
│  │ alerts.py    │                                              │
│  └──────────────┘  ┌─────────────────────────────────────┐   │
│                     │         fulcrum2e.py                 │   │
│                     │     (orchestrateur monolithe)        │   │
│                     └─────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Structure des fichiers

```
Monitoring/
├── fulcrum2e.py              # Monolithe original (orchestrateur)
├── fulcrum_config.yml        # Configuration principale
├── config_loader.py          # Chargement + validation Pydantic
├── ARCHITECTURE.md           # Ce document
│
├── collectors/
│   ├── __init__.py
│   ├── rss_collector.py      # Collecte RSS/Atom (feedparser)
│   └── api_collector.py      # APIs REST : CISA KEV, ACLED, Ransomware.live
│
├── analyzers/
│   ├── __init__.py
│   ├── scoring_engine.py     # Scoring rule-based + décomposition explicite
│   ├── ioc_extractor.py      # Extraction IOC avec filtrage RFC 1918
│   └── correlator.py         # SimHash, clusters 72h, timeline, last-run
│
├── exporters/
│   ├── __init__.py
│   └── json_exporter.py      # Export JSON structuré (schéma v3.1)
│
├── persistence/
│   ├── __init__.py
│   └── sqlite_store.py       # Persistance SQLite (90j + archivage)
│
├── alerts/
│   ├── __init__.py
│   └── webhook_manager.py    # Slack, Discord, Telegram, webhooks génériques
│
└── tests/
    ├── __init__.py
    ├── test_ioc_extractor.py
    ├── test_scoring_engine.py
    ├── test_correlator.py
    └── test_sqlite_store.py
```

## Flux de données

```
Sources RSS/API
      │
      ▼
collectors/ ──► dicts bruts
      │
      ▼
analyzers/scoring_engine.py  ──► severity, risk_score (décomposé), strat_score
analyzers/ioc_extractor.py   ──► IOCs filtrés (sans RFC 1918, avec contexte hashes)
analyzers/correlator.py      ──► SimHash → dédup fuzzy → clusters 72h
      │
      ▼
persistence/sqlite_store.py  ──► articles, iocs, clusters, source_stats
      │
      ├──► exporters/ ──► HTML / JSON / PDF
      └──► alerts/    ──► Slack / Discord / Telegram / Webhook
```

## Schéma SQLite

### Table `articles`
| Colonne | Type | Description |
|---------|------|-------------|
| id | TEXT PK | Hash MD5 identifiant unique |
| simhash | INTEGER | SimHash 64-bit pour dédup fuzzy |
| title | TEXT | Titre de l'article |
| source | TEXT | Nom de la source |
| published | TEXT | Date ISO 8601 |
| severity | TEXT | FLASH/CRITICAL/HIGH/MEDIUM/WATCH/INFO |
| risk_score | INTEGER | Score de risque 0-100 |
| strat_score | INTEGER | Score stratégique 0-100 |
| risk_breakdown | TEXT | JSON décomposition du score |
| theatres | TEXT | JSON liste des théâtres |
| actors | TEXT | JSON liste des acteurs |

### Table `iocs_extracted`
IOCs par article avec référence FK pour cascade delete.

### Table `correlations_detected`
Clusters d'incidents corrélés (acteur + théâtre + 72h).

### Table `source_stats`
Statistiques de fiabilité historique par source.

## Modules en détail

### `config_loader.py`
- Validation Pydantic v2 avec schémas stricts
- Dot-notation pour l'accès (`config.get("collection.timeout")`)
- Fallback `_DictConfig` si Pydantic absent
- Support hot-reload via `ConfigLoader.reload()`

### `analyzers/scoring_engine.py`
- **Pondération source** : coefficient multiplicateur par source (YAML)
- **Anti-faux-positifs** : blacklist de 20+ phrases contextuelles
- **Anti-inflation CRITICAL** : exige exploit actif OU acteur étatique confirmé
- **Scoring temporel** : +10 pts (<24h), +5 pts (<72h), -5 pts (>7j)
- **ScoreBreakdown** : décomposition exportable de chaque contribution

### `analyzers/ioc_extractor.py`
- **Filtrage RFC 1918** : 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 + loopback + link-local
- **Hash contextualisation** : accepte MD5/SHA uniquement avec préfixe (`hash:`, `md5:`, `sha256:`) ou dans un bloc IOC explicite
- **Validation CIDR** : rejette les sous-réseaux privés

### `analyzers/correlator.py`
- **SimHash 64-bit** : n-grams 3 caractères sur titre+résumé, sans ML
- **Seuil configurable** : 0.85 par défaut (YAML: `persistence.simhash_threshold`)
- **Clusters** : même acteur + même théâtre + fenêtre 72h
- **Mode `--since last-run`** : `.fulcrum_last_run` timestamp file

### `persistence/sqlite_store.py`
- **WAL mode** pour performances concurrentes
- **Pruning auto** : DELETE articles > 90j, configurable
- **Requêtes** : `query_articles(theatre, actor, severity, days)`
- **Risk evolution** : comparaison stats 7j vs 30j
- **Source stats** : suivi fiabilité historique

### `collectors/api_collector.py`
- **CISA KEV** : API publique JSON, pas de clé requise
- **ACLED** : nécessite clé API + email (gratuit recherche)
- **Ransomware.live** : API publique JSON

### `alerts/webhook_manager.py`
- Filtrage par sévérité (`critical_only`) et score minimum
- Payloads natifs Slack Block Kit, Discord Embed, Telegram HTML
- Rate limiting intégré (`delay` entre envois)

## Contraintes architecturales

- ❌ Aucune dépendance IA/LLM/NLP (Ollama, transformers, embeddings, classification ML)
- ✅ Tout le raisonnement est rule-based et algorithmique
- ✅ SimHash : locality-sensitive hashing déterministe, pas de ML
- ✅ Scoring : somme pondérée de règles explicites
- ✅ IOC contextualisation : regex + marqueurs syntaxiques

## Dépendances Python

### Obligatoires
```
feedparser
requests
pyyaml
```

### Optionnelles (dégradation gracieuse)
```
pydantic>=2.0      # Validation config (fallback dict)
rich               # Interface CLI colorée
beautifulsoup4     # Scraping HTML
lxml               # Parser HTML/XML
pandas             # Exports CSV/analytics
plotly             # Charts dashboard
redis              # Cache distribué (fallback mémoire)
```

### Nouvelles (v3.1)
```
pydantic>=2.0      # config_loader.py
# sqlite3          # stdlib — pas d'installation requise
```

## Migration depuis fulcrum2e.py (monolithe)

1. Installer les nouvelles dépendances : `pip install pydantic>=2.0`
2. Les nouveaux modules sont **opt-in** : `fulcrum2e.py` fonctionne tel quel
3. Pour utiliser le scoring amélioré :
   ```python
   from analyzers.scoring_engine import ScoringEngine
   engine = ScoringEngine(source_weights=config.get("intelligence.scoring.source_reliability"))
   ```
4. Pour la déduplication SimHash :
   ```python
   from analyzers.correlator import FuzzyDeduplicator
   dedup = FuzzyDeduplicator(threshold=0.85)
   unique = dedup.deduplicate(articles)
   ```
5. Pour la persistance SQLite :
   ```python
   from persistence.sqlite_store import SQLiteStore
   store = SQLiteStore("fulcrum.db")
   store.upsert_article(article.to_dict())
   ```
