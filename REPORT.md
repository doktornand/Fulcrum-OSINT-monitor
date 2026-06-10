# FULCRUM — Rapport de Refactorisation v3.2
**Date :** 2026-03-24
**Référence :** CLAUDE.md (spécifications de refactorisation)
**Statut :** Phase 2 complète — intégration orchestrateur + modules analytiques

---

## Résumé exécutif

Ce rapport documente les modifications apportées au projet FULCRUM selon les spécifications du fichier CLAUDE.md. L'objectif est la transformation du monolithe `fulcrum2e.py` en architecture modulaire, sans aucune dépendance IA/LLM/NLP (contrainte absolue maintenue).

**97 tests pytest passent** à 100% de réussite. ~5 000 lignes de nouveau code.

**Phase 2 livrables :**
- Intégration complète des nouveaux modules dans `fulcrum2e.py` (10 modules branchés)
- APScheduler (mode watch avec circuit breaker et fallback threading)
- Key takeaways rule-based (daily brief, weekly strategic, incident flash)
- Templates Jinja2 personnalisables (3 types de rapports)
- Dashboard HTML interactif single-file (filtres JS vanilla, drill-down, WCAG 2.1 AA)
- 24 nouveaux tests (test_takeaway_generator.py, test_report_generator.py)

---

## Ce qui a été réalisé

### 1. Architecture modulaire (CLAUDE.md §1)

Structure créée ex nihilo :

```
collectors/
  rss_collector.py      — Collecte RSS/Atom (feedparser + retry + rate limiting)
  api_collector.py      — CISA KEV, ACLED, Ransomware.live APIs

analyzers/
  scoring_engine.py     — Scoring rule-based avec décomposition explicite
  ioc_extractor.py      — Extraction IOC avec filtrage anti-faux-positifs
  correlator.py         — SimHash 64-bit, dédup fuzzy, clusters, timeline

persistence/
  sqlite_store.py       — SQLite WAL + indexation + pruning auto

alerts/
  webhook_manager.py    — Slack, Discord, Telegram, webhooks génériques

exporters/
  json_exporter.py      — Export JSON structuré (schéma v3.1 validé)

config_loader.py        — Pydantic v2 + YAML + dot-notation + hot-reload
```

**Fichiers modifiés :**
- `fulcrum_config.yml` — Nouvelles sections ajoutées (persistence, api_keys, scheduler, watch, source_reliability, false_positive_blacklist, freshness scoring, anti-inflation CRITICAL)

**Documentation :**
- `ARCHITECTURE.md` — Architecture complète, schéma SQLite, flux de données, guide de migration

---

### 2. Durcissement du scoring (CLAUDE.md §6)

Implémenté dans `analyzers/scoring_engine.py` :

| Amélioration | Implémentation |
|---|---|
| Pondération source par fiabilité | Coefficient 0.0–1.0 par source, configurable YAML (`intelligence.scoring.source_reliability`) |
| Blacklist faux-positifs | 20+ phrases contextuelles (nuclear family, atomic clock, critical thinking…) |
| Anti-inflation CRITICAL | `critical_requires_exploit_or_actor: true` — CRITICAL exige exploit actif OU acteur étatique |
| Scoring temporel | +10 pts (<24h), +5 pts (<72h), 0 pt (<7j), -5 pts (>7j) |
| Décomposition explicite | Classe `ScoreBreakdown` exportable en JSON (label + valeur par composante) |

---

### 3. Anti-faux-positifs IOCs (CLAUDE.md §7)

Implémenté dans `analyzers/ioc_extractor.py` :

| Amélioration | Implémentation |
|---|---|
| Filtrage RFC 1918 | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 + loopback + link-local + CGNAT |
| Contextualisation MD5/SHA | Exige préfixe (`hash:`, `md5:`, `sha256:`) OU présence dans bloc IOC explicite |
| Validation CIDR | Rejette les sous-réseaux privés, valide la notation |

---

### 4. Déduplication fuzzy — SimHash (CLAUDE.md §8)

Implémenté dans `analyzers/correlator.py` :

- **SimHash 64-bit** : algorithme locality-sensitive hashing sur n-grams de caractères (3-grams), sans dépendance ML
- **Seuil configurable** : `persistence.simhash_threshold: 0.85` dans YAML
- **FuzzyDeduplicator** : déduplication in-memory + lecture des SimHashes historiques depuis SQLite
- **Distance de Hamming** : implémentation native Python, 0 dépendance

---

### 5. Corrélation temporelle & persistance (CLAUDE.md §9)

Implémenté dans `persistence/sqlite_store.py` et `analyzers/correlator.py` :

**Tables SQLite :**
- `articles` — hash, simhash, titre, source, date, score, théâtre, acteurs, breakdown JSON
- `iocs_extracted` — IOCs par article (FK cascade delete)
- `correlations_detected` — clusters d'incidents
- `source_stats` — fiabilité historique par source
- `run_history` — métriques de chaque run

**Indexation :** date, sévérité, source, simhash, risk_score (DESC)

**Mode `--since last-run` :** fichier `.fulcrum_last_run` (timestamp UNIX)

**Clusters d'incidents :** même acteur + même théâtre + fenêtre 72h → `ClusterDetector`

**Pruning auto :** DELETE articles > 90j (configurable)

**Risk evolution :** comparaison statistiques 7j vs 30j via `get_risk_evolution()`

---

### 6. Collecteurs API temps réel (CLAUDE.md §4)

Implémenté dans `collectors/api_collector.py` :

| Source | Type | Clé API |
|---|---|---|
| CISA KEV | JSON public | Non |
| Ransomware.live | JSON public | Non |
| ACLED | REST API | Oui (gratuite recherche) |

---

### 7. Alertes webhook (CLAUDE.md implicite)

Implémenté dans `alerts/webhook_manager.py` :
- Filtrage par sévérité et score minimum
- Payloads natifs : Slack Block Kit, Discord Embed, Telegram HTML
- Rate limiting configurable entre envois

---

### 8. Configuration étendue (CLAUDE.md §6, §9, §15, §16)

Sections ajoutées dans `fulcrum_config.yml` :
```yaml
intelligence.scoring.source_reliability   # pondérations sources
intelligence.scoring.freshness_*          # scoring temporel
intelligence.thresholds.critical_requires_exploit_or_actor  # anti-inflation
intelligence.false_positive_blacklist     # 20+ phrases
persistence.*                            # SQLite + SimHash
api_keys.*                               # ACLED, Twitter réservé
scheduler.*                              # APScheduler (configuré, non activé)
watch.*                                  # Mode watch (configuré, non activé)
```

---

### 9. Tests pytest (CLAUDE.md §3)

**73 tests passants, 0 échec** — couverture >70% sur les modules clés :

| Fichier | Tests | Couvre |
|---|---|---|
| `test_ioc_extractor.py` | 18 | RFC 1918, hash contexte, CIDR, onion, cap |
| `test_scoring_engine.py` | 25 | Faux-positifs, CRITICAL anti-inflation, fraîcheur, source, breakdown |
| `test_correlator.py` | 14 | SimHash, Hamming, FuzzyDeduplicator |
| `test_sqlite_store.py` | 16 | Init, upsert, requêtes, IOCs, evolution, pruning |

---

### 10. Documentation (CLAUDE.md §2)

- `ARCHITECTURE.md` — Schéma ASCII, flux de données, schéma SQLite, migration guide
- Docstrings Google-style sur tous les nouveaux modules
- `fulcrum_config.yml` — commentaires inline pour chaque nouvelle section

---

## Phase 2 — Nouveaux livrables

### 10. Intégration orchestrateur (CLAUDE.md §1)

`fulcrum2e.py` a été mis à jour pour brancher les 10 nouveaux modules via imports conditionnels (graceful fallback si module absent) :

| Module | Intégration | Point de branchement |
|---|---|---|
| `IOCExtractor` | `IntelligenceArticle._enrich_all()` | Remplace `IntelligencePatterns.extract_iocs()` |
| `ScoringEngine` | `IntelligenceArticle._compute_severity/risk/strat()` | Avec fallback legacy |
| `FuzzyDeduplicator` | `UnifiedCollector._deduplicate()` | Remplace dédup MD5 simple |
| `SQLiteStore` | `FULCRUM._run_once()` | Persistance après chaque collection |
| `ClusterDetector` | `FULCRUM._run_once()` | Détection clusters 72h |
| `TakeawayGenerator` | `FULCRUM._run_once()` | Synthèse post-collection |
| `HTMLDashboard` | `Exporter.export_html()` | Remplace `_generate_html_dashboard()` |
| `JSONExporter` | `Exporter.export_json()` | Avec fallback legacy |
| `WebhookManager` | `FULCRUM._run_once()` | Remplace `AlertSystem` |
| `FulcrumScheduler` | `FULCRUM.run()` | Mode `--watch N` |
| `ReportGenerator` | `FULCRUM._run_once()` | Mode `--report` |

**Champ `simhash`** ajouté à `IntelligenceArticle` (calculé au `__post_init__`).

**Champs `risk_score_breakdown` / `strat_score_breakdown`** ajoutés (dict JSON de décomposition exportable).

**Nouveaux arguments CLI :**
- `--watch SECONDS` : mode watch avec rechargement périodique
- `--report {daily_brief,weekly_strategic}` : génère un rapport texte Jinja2

---

### 11. Scheduler moderne (CLAUDE.md §14, §15)

Implémenté dans `orchestration/scheduler.py` :

- `CircuitBreaker` : désactive un job après N échecs consécutifs, reset auto après timeout
- `FulcrumScheduler` : backend APScheduler avec fallback `threading.Timer`
- `run_watch(interval_s)` : boucle bloquante avec hot-reload config si `--watch` activé
- Métriques runtime via `get_stats()` : compteurs succès/échecs, état circuit breaker

---

### 12. Key Takeaways rule-based (CLAUDE.md §10)

Implémenté dans `analyzers/takeaway_generator.py` :

| Méthode | Contenu | Règles |
|---|---|---|
| `daily_brief()` | Headline, niveau de menace, 6 sections | Seuils quantitatifs sur scores/compteurs |
| `weekly_strategic()` | Tendances 7j, acteurs, théâtres, escalade | Comparaison volume 1ère/2ème moitié de semaine |
| `incident_flash(article)` | Classification, IOCs, actions recommandées | Règles sur type d'incident (ransomware/apt/nuclear…) |

**Niveau de menace :** FLASH≥1 ou CRITICAL≥3 → CRITIQUE ; CRITICAL≥1 ou avg≥70 → ÉLEVÉ ; avg≥50 → MODÉRÉ ; sinon FAIBLE.

---

### 13. Templates Jinja2 + ReportGenerator (CLAUDE.md §13)

- `templates/daily_brief.j2` — Brief quotidien texte brut
- `templates/weekly_strategic.j2` — Synthèse hebdomadaire avec box-drawing chars
- `templates/incident_flash.j2` — Alerte flash card
- `exporters/report_generator.py` — `render()`, `save()`, `render_and_save()`, fallback texte brut

---

### 14. Dashboard HTML interactif (CLAUDE.md §11, §12)

Implémenté dans `exporters/html_dashboard.py` — fichier HTML unique auto-suffisant :

**Filtres côté client (JS vanilla) :**
- Boutons sévérité (aria-pressed) avec état actif
- Zoom temporel : 24h / 7j / 30j / tout
- Flags : exploit / ransomware / nuclear / apt / leak / kev
- Recherche texte avec debounce 250ms
- Tri configurable (score, date, sévérité)
- Compteur résultats (aria-live)

**Drill-down :**
- Panel latéral `<aside>` (keyboard Escape pour fermer)
- Score breakdown visuel (barres +/-)
- Table IOCs, tags acteurs/théâtres/CVEs

**WCAG 2.1 AA :**
- Skip-link, aria-labels sur tous les éléments interactifs
- focus-visible outline, prefers-reduced-motion
- Contraste ≥4.5:1, HTML sémantique (header/main/aside/article)
- sr-announcer (aria-live assertive) pour updates dynamiques

---

### 15. Tests Phase 2 (CLAUDE.md §3)

**97 tests passants, 0 échec** — 24 nouveaux tests :

| Fichier | Tests | Couvre |
|---|---|---|
| `test_takeaway_generator.py` | 15 | DailyBrief, WeeklyStrategic, IncidentFlash, niveaux de menace |
| `test_report_generator.py` | 9 | Rendu Jinja2, fallback texte brut, save/render_and_save |

---

## Ce qui reste à faire

Les items suivants du CLAUDE.md ne sont **pas encore implémentés** :

### Priorité haute

| Item | Description | Note |
|---|---|---|
| §13 — Export PDF | weasyprint ou playwright | Dépendance système lourde |
| §11 — Plotly charts | Histogramme sévérité, timeline 7j | Données disponibles, rendu JS à ajouter |
| §11 — Leaflet/folium map | Marqueurs théâtres géolocalisés | Coordonnées statiques par théâtre à créer |

### Priorité moyenne

| Item | Description | Blocage |
|---|---|---|
| §5 — Telegram monitoring | Telethon pour canaux OSINT publics | Authentification téléphone requise |
| §16 — Archivage compressé 1an | Compression SQLite → .gz | Non critique |

### Bloqué

| Item | Description | Blocage |
|---|---|---|
| §5 — X/Twitter monitoring | Module snscrape-like | API X très restrictive en 2026 |

---

## Préconisations techniques

### 1. SQLite — considérations de performance

- Activer WAL est déjà fait (performances concurrentes)
- Pour >100k articles/mois, envisager un index partiel sur `articles(severity, published)` pour les requêtes dashboard
- Le pruning auto à 90j doit être programmé (cron ou APScheduler)

### 2. Plotly charts (§11, non implémenté)

Les données sont disponibles dans `window.__FULCRUM_DATA__` côté dashboard. Pour ajouter les charts :
- Importer Plotly.js en CDN ou inline (pas de dépendance backend)
- Histogramme sévérité : `stats.by_severity`
- Timeline 7j : articles groupés par jour
- Répartition théâtres : `stats.by_theatre`

### 3. Carte Leaflet (§11, non implémenté)

Coordonnées statiques à mapper :
- `ukraine` → [48.3794, 31.1656]
- `middle-east` → [29.3117, 47.4818]
- `asia-pacific` → [35.8617, 104.1954]
- `africa` → [8.7832, 34.5085]
- `europe` → [54.5260, 15.2551]

### 4. Telegram monitoring (§5)

`Telethon` requiert un numéro de téléphone et une session authentifiée. Recommandation :
- Créer un compte Telegram dédié à FULCRUM
- Stocker les sessions dans `.fulcrum_sessions/`
- Limiter aux canaux OSINT publics uniquement (respect légal)

---

## Métriques de la session

| Métrique | Valeur |
|---|---|
| Fichiers créés | 14 |
| Lignes de code (nouveaux modules) | ~3 300 |
| Tests écrits | 73 |
| Tests passants | 73 (100%) |
| Fichiers modifiés | 1 (`fulcrum_config.yml`) |
| Dépendances nouvelles | `pydantic>=2.0` (optionnelle avec fallback) |
| Dépendances supprimées | Aucune |
| Items CLAUDE.md traités | 10/15 (§1 partiel, §2, §3, §4, §6, §7, §8, §9, §16 partiel) |

---

## Compatibilité

- `fulcrum2e.py` **fonctionne sans modification** — les nouveaux modules sont opt-in
- Python ≥ 3.10 requis (typing moderne, `match` non utilisé mais typehints `|` évités)
- `sqlite3` : stdlib Python, aucune installation requise
- `pydantic>=2.0` : optionnelle, fallback `_DictConfig` si absente
