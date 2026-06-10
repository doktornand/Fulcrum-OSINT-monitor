Tu es un ingénieur senior en architecture logicielle et veille géostratégique. 
Tu dois améliorer le code FULCRUM (fourni ci-après) selon les spécifications suivantes.

=== CONTRAINTE ABSOLUE ===
❌ INTERDICTION TOTALE d'ajouter des dépendances IA/LLM/NLP (pas d'Ollama, pas de transformers, 
pas d'embeddings, pas de classification ML). Toute amélioration doit être règle-based, 
algorithmique, ou basée sur des heuristiques explicites.

=== ARCHITECTURE & CODE QUALITÉ ===
1. MODULARISATION : Refactoriser le monolithe en modules séparés :
   - config_loader.py (YAML validation + schémas Pydantic)
   - collectors/ (rss_collector.py, api_collector.py, telegram_collector.py, x_collector.py)
   - analyzers/ (scoring_engine.py, ioc_extractor.py, correlator.py)
   - exporters/ (html_dashboard.py, pdf_exporter.py, json_exporter.py)
   - persistence/ (sqlite_store.py, cache_manager.py)
   - alerts/ (webhook_manager.py, telegram_alerts.py)

2. DOCUMENTATION : Ajouter docstrings Google-style + README technique + ARCHITECTURE.md

3. TESTS : Implémenter pytest avec fixtures, tests unitaires par module, tests d'intégration 
   sur flux RSS réduits, mock des dépendances externes

=== SOURCES & COLLECTE ===
4. APIs TEMPS RÉEL : Ajouter collecte API (pas seulement RSS) pour sources clés :
   - CISA KEV API
   - ACLED API
   - Twitter/X API v2 (basique, sans LLM)
   - Telegram monitoring (telethon) pour canaux OSINT publics

5. TELEGRAM/X MONITORING : Module basique telethon pour canaux OSINT + snscrape-like 
   pour X (rate limiting strict, rotation User-Agent)

=== SCORING & QUALITÉ DES SIGNAUX ===
6. DURCISSEMENT SCORING : 
   - Pondération source par fiabilité historique (configurable YAML)
   - Détection faux-positifs : blacklist mots contextuels ("nuclear family", "atomic clock")
   - Réduction inflation criticité : plafonnement CRITICAL aux vrais indicateurs 
     (CVE exploitable + acteur étatique confirmé + théâtre actif)
   - Scoring temporel : bonus/malus fraîcheur (24h/72h/7j)

7. ANTI-FAUX-POSITIFS IOCs :
   - Filtrer plages IP privées RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
   - Contextualisation MD5/SHA : exiger préfixe "hash:", "md5:", "sha256:" ou 
     présence dans bloc IOC explicite
   - Validation format CIDR pour IPs

=== DÉDUPLICATION & CORRÉLATION ===
8. FUZZY MATCHING : Remplacer hash simple par SimHash/MinHash sur titre + résumé 
   (seuil similarité 0.85)

9. CORRÉLATION TEMPORELLE :
   - SQLite persistance : stocker articles vus (30j), scores historiques, tendances
   - Détection clusters : articles même acteur + même théâtre + fenêtre 72h = incident unique
   - Timeline événements : vue chronologique par théâtre/acteur
   - Mode --since last-run : timestamp fichier .fulcrum_last_run

10. STRUCTURATION ANALYTIQUE :
    - Regroupement par campagne/théâtre (Ukraine, Middle East, Indo-Pacifique)
    - Explicabilité score : afficher décomposition (source: X, mots-clés: Y, fraîcheur: Z)
    - Key takeaways générés par templates règle-based (pas de LLM)
    - Risk evolution : comparaison volume/sevérité sur 7j/30j

=== DASHBOARD & UX ===
11. DASHBOARD INTERACTIF :
    - Filtres dynamiques côté client (JS vanilla) : par date, théâtre, acteur, sévérité
    - Zoom temporel : vue 24h/7j/30j/custom
    - Drill-down : clic article → détail complet + articles liés + contexte historique
    - Charts Plotly (déjà en dépendances) : histogramme sévérité, timeline 7j, 
      répartition théâtres, top acteurs
    - Carte interactive folium/leaflet : marqueurs théâtres géolocalisés, 
      clustering proximité, liens vers Oryx/ACLED

12. ACCESSIBILITÉ : Conformité WCAG 2.1 AA (contraste 4.5:1, taille police adaptable, 
    navigation clavier, aria-labels)

=== EXPORT & RAPPORTS ===
13. RAPPORTS AUTOMATISÉS :
    - Templates personnalisables (Jinja2) : daily brief, weekly strategic, incident flash
    - Export PDF : remplacer pdfkit par weasyprint ou playwright (meux support CSS)
    - Export JSON structuré : schéma validé, métadonnées enrichies

=== ORCHESTRATION ===
14. SCHEDULER MODERNE : Remplacer threading/asyncio spaghetti par APScheduler 
    (jobs périodiques, retry exponentiel, circuit breaker)

15. MODE WATCH : Rechargement périodique auto (--watch 300s) avec hot-reload config

=== PERSISTANCE ===
16. SQLITE STORE :
    - Tables : articles (hash, titre, source, date, score, théâtre, acteurs, raw_content),
      iocs_extracted, correlations_detected, source_reliability_history
    - Index : date, théâtre, acteur, hash_simhash
    - Pruning auto : conservation 90j, archivage compressé 1an

=== LIVRABLES ATTENDUS ===
- Code refactorisé modulaire (structure répertoire claire)
- Tests pytest passants (couverture &gt;70%)
- Documentation technique complète
- Dashboard HTML amélioré (fichier unique ou templates Jinja2)
- Migration guide depuis fulcrum2e.py monolithe