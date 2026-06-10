"""
exporters/html_dashboard.py — Dashboard HTML interactif FULCRUM

Génère un fichier HTML autonome (single-file) avec :
  - Filtres dynamiques JS vanilla (date, théâtre, acteur, sévérité)
  - Zoom temporel : 24h / 7j / 30j / tout
  - Drill-down : clic article → détail complet + score breakdown + IOCs
  - WCAG 2.1 AA : contraste 4.5:1, aria-labels, navigation clavier, tailles adaptables
  - Score breakdown visible par article
  - Résumé des takeaways intégré

Aucune dépendance CDN externe — tout est inline (CSS + JS vanilla).

Google-style docstrings.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("FULCRUM.html_dashboard")

# ---------------------------------------------------------------------------
# Couleurs sévérité (WCAG 4.5:1 sur fond #0a0c12)
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "FLASH":    "#FF0040",
    "CRITICAL": "#FF2A6D",
    "HIGH":     "#FF8C42",
    "MEDIUM":   "#FFD166",
    "WATCH":    "#06D6A0",
    "INFO":     "#78909C",
}


def _sev_color(severity: str) -> str:
    return _SEVERITY_COLORS.get(severity, "#78909C")


# ---------------------------------------------------------------------------
# Sérialisation articles pour window.__FULCRUM_DATA__
# ---------------------------------------------------------------------------

def _serialize_articles(articles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sérialise les articles pour l'injection JSON dans le HTML.

    Args:
        articles: Liste de dicts articles FULCRUM.

    Returns:
        Liste allégée des champs nécessaires au dashboard.
    """
    out = []
    for a in articles:
        # Breakdown texte lisible
        breakdown = a.get("risk_breakdown", {})
        bd_parts = []
        if isinstance(breakdown, dict) and "breakdown" in breakdown:
            bd_parts = [
                f"{b['label']}: {b['value']:+d}"
                for b in breakdown["breakdown"]
                if b.get("value", 0) != 0
            ]

        pub = a.get("published", "")[:10]  # YYYY-MM-DD

        out.append({
            "id":          a.get("id", ""),
            "title":       a.get("title", "")[:200],
            "source":      a.get("source", ""),
            "category":    a.get("category", ""),
            "published":   a.get("published", ""),
            "pub_date":    pub,
            "link":        a.get("link", ""),
            "severity":    a.get("severity", "INFO"),
            "risk_score":  a.get("risk_score", 0),
            "strat_score": a.get("strat_score", 0),
            "score":       a.get("risk_score", 0) + a.get("strat_score", 0),
            "theatres":    a.get("theatres", []),
            "actors":      a.get("actors", []),
            "cves":        a.get("cves", [])[:5],
            "tags":        a.get("tags", []),
            "summary":     a.get("summary", "")[:400],
            "iocs":        {k: v[:5] for k, v in a.get("iocs", {}).items()},
            "breakdown":   bd_parts,
            # Flags booléens
            "exploit":     bool(a.get("exploit_available")),
            "ransomware":  bool(a.get("ransomware_related")),
            "apt":         bool(a.get("apt_related")),
            "nuclear":     bool(a.get("nuclear_related")),
            "leak":        bool(a.get("leak_related")),
            "in_kev":      bool(a.get("in_kev")),
        })

    return out


# ---------------------------------------------------------------------------
# HTML Generator
# ---------------------------------------------------------------------------

class HTMLDashboard:
    """Génère un dashboard HTML interactif FULCRUM (single-file).

    Args:
        output_path: Chemin du fichier HTML de sortie.
        max_articles: Nombre maximum d'articles inclus (défaut 300).

    Example:
        >>> dashboard = HTMLDashboard("fulcrum_dashboard.html")
        >>> dashboard.generate(articles, stats, takeaway)
    """

    def __init__(
        self,
        output_path: str = "fulcrum_dashboard.html",
        max_articles: int = 300,
    ) -> None:
        self.output_path = Path(output_path)
        self.max_articles = max_articles

    def generate(
        self,
        articles: List[Dict[str, Any]],
        stats: Optional[Dict[str, Any]] = None,
        takeaway: Optional[Dict[str, Any]] = None,
    ) -> Path:
        """Génère le fichier HTML dashboard.

        Args:
            articles: Liste de dicts articles FULCRUM.
            stats: Statistiques globales.
            takeaway: Daily brief issu de TakeawayGenerator.

        Returns:
            Chemin du fichier généré.
        """
        serialized = _serialize_articles(articles[:self.max_articles])
        stats = stats or {}
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        html = self._build_html(serialized, stats, takeaway, now)

        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(html, encoding="utf-8")
        logger.info(f"Dashboard HTML généré : {self.output_path} ({len(articles)} articles)")
        return self.output_path

    # ------------------------------------------------------------------
    # Construction HTML
    # ------------------------------------------------------------------

    def _build_html(
        self,
        articles_json: List[Dict[str, Any]],
        stats: Dict[str, Any],
        takeaway: Optional[Dict[str, Any]],
        now: str,
    ) -> str:
        """Construit le document HTML complet.

        Args:
            articles_json: Articles sérialisés pour le JS.
            stats: Statistiques.
            takeaway: Données du brief quotidien.
            now: Timestamp de génération.

        Returns:
            HTML complet en string.
        """
        data_json = json.dumps(articles_json, ensure_ascii=False)
        total = len(articles_json)
        critical_count = sum(1 for a in articles_json if a["severity"] in ("FLASH", "CRITICAL"))
        high_count     = sum(1 for a in articles_json if a["severity"] == "HIGH")
        avg_score      = (sum(a["score"] for a in articles_json) / total) if total else 0

        # Headline du brief
        brief_headline = ""
        brief_threat   = ""
        brief_sections = []
        if takeaway:
            brief_headline = takeaway.get("headline", "")
            brief_threat   = takeaway.get("threat_level", "")
            brief_sections = takeaway.get("sections", [])

        threat_color = {
            "CRITIQUE": "#FF2A6D", "ÉLEVÉ": "#FF8C42",
            "MODÉRÉ": "#FFD166", "FAIBLE": "#06D6A0",
        }.get(brief_threat, "#78909C")

        # Sections du brief en HTML
        sections_html = ""
        for sec in brief_sections[:6]:
            items_html = "".join(
                f'<li>{item}</li>' for item in sec.get("items", [])[:6]
            )
            sections_html += f"""
            <div class="brief-section">
                <h4 class="brief-section-title">{sec.get("title", "")}</h4>
                <ul class="brief-items">{items_html}</ul>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FULCRUM — Intelligence Operations Center</title>
    <meta name="description" content="FULCRUM Intelligence Platform — Dashboard opérationnel">
    <style>
{self._css()}
    </style>
</head>
<body>

<!-- Skip-link WCAG -->
<a href="#main-content" class="skip-link">Aller au contenu principal</a>

<!-- HEADER -->
<header class="header" role="banner">
    <div class="header-inner">
        <h1 class="header-title" aria-label="FULCRUM Intelligence Operations Center">
            ⬡ FULCRUM
            <span class="header-sub">INTELLIGENCE OPERATIONS CENTER</span>
        </h1>
        <div class="header-meta" aria-live="polite">
            <span class="led" aria-hidden="true"></span>
            <span>OPERATIONAL</span>
            <span class="sep">|</span>
            <time datetime="{now[:16]}">{now}</time>
            <span class="sep">|</span>
            <span>{total} signaux</span>
        </div>
    </div>
</header>

<!-- KPI STRIP -->
<section class="kpi-strip" aria-label="Indicateurs clés">
    <div class="kpi" style="--accent:#FF2A6D">
        <span class="kpi-value" aria-label="{critical_count} alertes critiques">{critical_count}</span>
        <span class="kpi-label">CRITIQUES</span>
    </div>
    <div class="kpi" style="--accent:#FF8C42">
        <span class="kpi-value" aria-label="{high_count} alertes haute sévérité">{high_count}</span>
        <span class="kpi-label">HIGH</span>
    </div>
    <div class="kpi" style="--accent:#06D6A0">
        <span class="kpi-value" aria-label="Score moyen {avg_score:.0f}">{avg_score:.0f}</span>
        <span class="kpi-label">SCORE MOY.</span>
    </div>
    <div class="kpi" style="--accent:#78909C">
        <span class="kpi-value">{total}</span>
        <span class="kpi-label">TOTAL</span>
    </div>
</section>

<!-- BRIEF QUOTIDIEN -->
{f'''<section class="brief-panel" aria-label="Brief quotidien" aria-expanded="true">
    <details open>
        <summary class="brief-summary">
            <span class="brief-threat" style="color:{threat_color}">
                [{brief_threat}]
            </span>
            DAILY BRIEF — {brief_headline}
        </summary>
        <div class="brief-body">
            {sections_html}
        </div>
    </details>
</section>''' if brief_headline else ''}

<!-- TOOLBAR / FILTRES -->
<div class="toolbar" role="toolbar" aria-label="Filtres et tri">

    <div class="filter-group" role="group" aria-label="Filtres de sévérité">
        <span class="filter-label" id="sev-label">Sévérité :</span>
        <button class="filter-btn active" data-filter="all"
                aria-pressed="true" aria-describedby="sev-label">Tout</button>
        <button class="filter-btn" data-filter="FLASH"
                aria-pressed="false" style="--btn-color:#FF0040">FLASH</button>
        <button class="filter-btn" data-filter="CRITICAL"
                aria-pressed="false" style="--btn-color:#FF2A6D">CRITICAL</button>
        <button class="filter-btn" data-filter="HIGH"
                aria-pressed="false" style="--btn-color:#FF8C42">HIGH</button>
        <button class="filter-btn" data-filter="MEDIUM"
                aria-pressed="false" style="--btn-color:#FFD166">MEDIUM</button>
    </div>

    <div class="filter-group" role="group" aria-label="Zoom temporel">
        <span class="filter-label" id="time-label">Période :</span>
        <button class="time-btn active" data-days="0"
                aria-pressed="true" aria-describedby="time-label">Tout</button>
        <button class="time-btn" data-days="1"  aria-pressed="false">24h</button>
        <button class="time-btn" data-days="7"  aria-pressed="false">7j</button>
        <button class="time-btn" data-days="30" aria-pressed="false">30j</button>
    </div>

    <div class="filter-group" role="group" aria-label="Filtres thématiques">
        <span class="filter-label" id="flag-label">Filtres :</span>
        <button class="flag-btn" data-flag="exploit"
                aria-pressed="false" aria-describedby="flag-label">⚡ Exploit</button>
        <button class="flag-btn" data-flag="ransomware"
                aria-pressed="false">💀 Ransom</button>
        <button class="flag-btn" data-flag="nuclear"
                aria-pressed="false">☢ Nucléaire</button>
        <button class="flag-btn" data-flag="apt"
                aria-pressed="false">🎯 APT</button>
        <button class="flag-btn" data-flag="leak"
                aria-pressed="false">🔓 Leak</button>
        <button class="flag-btn" data-flag="in_kev"
                aria-pressed="false">🛡 KEV</button>
    </div>

    <div class="filter-group search-group">
        <label for="search-input" class="filter-label">Recherche :</label>
        <input type="search" id="search-input"
               class="search-input"
               placeholder="titre, source, CVE, acteur…"
               aria-label="Rechercher dans les articles"
               autocomplete="off">
    </div>

    <div class="filter-group" role="group" aria-label="Tri">
        <label for="sort-select" class="filter-label">Tri :</label>
        <select id="sort-select" class="sort-select" aria-label="Critère de tri">
            <option value="score">Score (déc.)</option>
            <option value="date">Date (récent)</option>
            <option value="severity">Sévérité</option>
        </select>
    </div>

    <div class="result-count" aria-live="polite" aria-atomic="true">
        <span id="result-count">{total}</span> articles affichés
    </div>
</div>

<!-- MAIN CONTENT -->
<main id="main-content" class="main-grid">

    <!-- GRILLE D'ARTICLES -->
    <section class="articles-panel" aria-label="Articles d'intelligence">
        <div id="cards-container" class="cards-grid" role="feed" aria-label="Articles filtrés">
            <!-- Injecté par JS -->
        </div>
    </section>

    <!-- PANNEAU DÉTAIL (DRILL-DOWN) -->
    <aside id="detail-panel" class="detail-panel" aria-label="Détail de l'article" hidden>
        <button id="close-detail" class="close-btn"
                aria-label="Fermer le panneau de détail">✕</button>
        <div id="detail-content" class="detail-content"></div>
    </aside>

</main>

<!-- MODAL ACCESSIBILITÉ (annonces) -->
<div id="sr-announcer" aria-live="assertive" aria-atomic="true"
     class="visually-hidden" role="status"></div>

<!-- DONNÉES INJECTÉES -->
<script>
/* Données articles — générées côté serveur */
window.__FULCRUM_DATA__ = {data_json};
</script>

<script>
{self._js()}
</script>

</body>
</html>"""

    # ------------------------------------------------------------------
    # CSS (WCAG 2.1 AA)
    # ------------------------------------------------------------------

    def _css(self) -> str:
        return """
        /* ── Reset & Variables ─────────────────────────────────────────── */
        :root {
            --bg:       #0a0c12;
            --bg2:      #111318;
            --bg3:      #1a1d24;
            --border:   #2a2e3a;
            --text:     #eef2ff;   /* contrast >7:1 sur --bg */
            --text2:    #b0b8cc;   /* contrast ~4.7:1 */
            --accent:   #00d4aa;
            --fs-base:  1rem;
            --fs-sm:    0.875rem;
            --fs-lg:    1.125rem;
            --radius:   6px;
            --shadow:   0 2px 12px rgba(0,0,0,0.5);
            --font: 'JetBrains Mono', 'Courier New', monospace;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        html { font-size: 16px; scroll-behavior: smooth; }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--font);
            font-size: var(--fs-base);
            line-height: 1.6;
            min-height: 100vh;
        }

        /* ── Accessibilité ─────────────────────────────────────────────── */
        .skip-link {
            position: absolute; top: -100%; left: 1rem;
            background: var(--accent); color: #000;
            padding: 0.5rem 1rem; border-radius: var(--radius);
            font-weight: bold; z-index: 9999; text-decoration: none;
        }
        .skip-link:focus { top: 1rem; }

        .visually-hidden {
            position: absolute; width: 1px; height: 1px;
            margin: -1px; overflow: hidden; clip: rect(0,0,0,0);
            white-space: nowrap; border: 0;
        }

        :focus-visible {
            outline: 3px solid var(--accent);
            outline-offset: 2px;
        }

        /* ── Header ────────────────────────────────────────────────────── */
        .header {
            background: linear-gradient(135deg, var(--bg), var(--bg2));
            border-bottom: 2px solid var(--accent);
            padding: 1rem 1.5rem;
            position: sticky; top: 0; z-index: 100;
        }
        .header-inner { display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
        .header-title {
            font-size: clamp(1.2rem, 3vw, 1.8rem);
            font-weight: 900; letter-spacing: -1px;
            background: linear-gradient(135deg, #00d4aa, #ff2a6d, #ff6b35);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .header-sub { display: block; font-size: var(--fs-sm); color: var(--text2); }
        .header-meta {
            margin-left: auto; display: flex; align-items: center; gap: 0.5rem;
            font-size: var(--fs-sm); color: var(--text2);
        }
        .sep { opacity: 0.4; }
        .led {
            display: inline-block; width: 8px; height: 8px; border-radius: 50%;
            background: #06d6a0; box-shadow: 0 0 6px #06d6a0;
            animation: blink 2s infinite;
        }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.4} }

        /* ── KPI Strip ─────────────────────────────────────────────────── */
        .kpi-strip {
            display: flex; gap: 1px;
            background: var(--border);
            border-bottom: 1px solid var(--border);
        }
        .kpi {
            flex: 1; background: var(--bg2);
            padding: 0.75rem 1rem; text-align: center;
            border-left: 3px solid var(--accent);
        }
        .kpi-value {
            display: block; font-size: clamp(1.4rem, 3vw, 2rem);
            font-weight: 900; color: var(--accent);
        }
        .kpi-label {
            font-size: 0.65rem; color: var(--text2);
            letter-spacing: 1px; text-transform: uppercase;
        }

        /* ── Brief Panel ───────────────────────────────────────────────── */
        .brief-panel {
            background: var(--bg2); border-bottom: 1px solid var(--border);
            padding: 0 1.5rem;
        }
        .brief-panel details { padding: 0.5rem 0; }
        .brief-summary {
            cursor: pointer; padding: 0.6rem 0;
            font-size: var(--fs-sm); color: var(--text2);
            user-select: none; list-style: none;
        }
        .brief-summary::-webkit-details-marker { display: none; }
        .brief-threat { font-weight: bold; margin-right: 0.5rem; }
        .brief-body {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
            gap: 1rem; padding: 1rem 0;
        }
        .brief-section { background: var(--bg3); border-radius: var(--radius); padding: 0.75rem; }
        .brief-section-title {
            font-size: var(--fs-sm); color: var(--accent);
            margin-bottom: 0.5rem; text-transform: uppercase;
        }
        .brief-items { padding-left: 1rem; font-size: 0.8rem; color: var(--text2); }
        .brief-items li { margin-bottom: 0.2rem; }

        /* ── Toolbar ───────────────────────────────────────────────────── */
        .toolbar {
            position: sticky; top: 56px; z-index: 90;
            background: var(--bg2); border-bottom: 1px solid var(--border);
            padding: 0.6rem 1.5rem;
            display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem;
        }
        .filter-group { display: flex; align-items: center; gap: 0.35rem; flex-wrap: wrap; }
        .filter-label { font-size: 0.75rem; color: var(--text2); white-space: nowrap; }

        .filter-btn, .time-btn, .flag-btn {
            background: var(--bg3); border: 1px solid var(--border);
            color: var(--text2); padding: 0.25rem 0.6rem;
            border-radius: var(--radius); font-size: 0.75rem;
            cursor: pointer; transition: all 0.15s;
            font-family: var(--font);
        }
        .filter-btn:hover, .time-btn:hover, .flag-btn:hover {
            border-color: var(--accent); color: var(--text);
        }
        .filter-btn.active, .time-btn.active, .flag-btn.active {
            background: var(--btn-color, var(--accent));
            border-color: var(--btn-color, var(--accent));
            color: #000; font-weight: bold;
        }

        .search-input {
            background: var(--bg3); border: 1px solid var(--border);
            color: var(--text); padding: 0.25rem 0.6rem;
            border-radius: var(--radius); font-size: 0.8rem;
            font-family: var(--font); width: clamp(150px, 20vw, 280px);
        }
        .search-input::placeholder { color: var(--text2); }
        .search-input:focus { border-color: var(--accent); }

        .sort-select {
            background: var(--bg3); border: 1px solid var(--border);
            color: var(--text); padding: 0.25rem 0.5rem;
            border-radius: var(--radius); font-size: 0.75rem;
            font-family: var(--font); cursor: pointer;
        }

        .result-count {
            margin-left: auto; font-size: 0.75rem; color: var(--text2);
            white-space: nowrap;
        }
        #result-count { font-weight: bold; color: var(--accent); }

        /* ── Main Grid ─────────────────────────────────────────────────── */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr;
            min-height: calc(100vh - 160px);
        }
        .main-grid.detail-open {
            grid-template-columns: 1fr 420px;
        }

        /* ── Cards ─────────────────────────────────────────────────────── */
        .articles-panel { padding: 1rem 1.5rem; overflow-y: auto; }
        .cards-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 0.75rem;
        }

        .card {
            background: var(--bg2); border: 1px solid var(--border);
            border-radius: var(--radius); padding: 0.9rem;
            cursor: pointer; transition: border-color 0.15s, transform 0.1s;
            border-left: 3px solid var(--sev-color, var(--border));
        }
        .card:hover {
            border-color: var(--accent);
            transform: translateY(-1px);
            box-shadow: var(--shadow);
        }
        .card:focus-visible { outline: 3px solid var(--accent); }

        .card-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem; margin-bottom: 0.5rem; }
        .card-source { font-size: 0.7rem; color: var(--text2); }
        .sev-badge {
            font-size: 0.65rem; font-weight: bold; padding: 0.15rem 0.4rem;
            border-radius: 3px; white-space: nowrap;
            background: var(--sev-color, #444); color: #000;
        }

        .card-title {
            font-size: 0.85rem; font-weight: 600; color: var(--text);
            margin-bottom: 0.5rem; line-height: 1.4;
            display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .score-bar {
            height: 4px; background: var(--bg3); border-radius: 2px;
            margin-bottom: 0.5rem; position: relative;
        }
        .score-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }

        .card-flags { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-bottom: 0.4rem; }
        .flag {
            font-size: 0.65rem; padding: 0.1rem 0.35rem;
            border-radius: 3px; background: rgba(255,255,255,0.08);
            color: var(--text2); border: 1px solid var(--border);
        }
        .flag.exploit { border-color: #FF8C42; color: #FF8C42; }
        .flag.ransom  { border-color: #FF2A6D; color: #FF2A6D; }
        .flag.nuclear { border-color: #FF6B35; color: #FF6B35; }
        .flag.apt     { border-color: #7C5CBF; color: #9B7FD4; }
        .flag.leak    { border-color: #FFD166; color: #FFD166; }
        .flag.kev     { border-color: #06D6A0; color: #06D6A0; }

        .card-meta {
            display: flex; justify-content: space-between;
            font-size: 0.7rem; color: var(--text2); margin-top: 0.4rem;
        }

        /* ── Detail Panel (Drill-down) ──────────────────────────────────── */
        .detail-panel {
            background: var(--bg2); border-left: 1px solid var(--border);
            overflow-y: auto; position: relative;
        }
        .detail-panel[hidden] { display: none; }

        .close-btn {
            position: sticky; top: 0; float: right;
            background: var(--bg3); border: 1px solid var(--border);
            color: var(--text); width: 32px; height: 32px;
            border-radius: var(--radius); cursor: pointer; font-size: 1rem;
            margin: 0.75rem; z-index: 10;
        }
        .close-btn:hover { background: var(--accent); color: #000; }

        .detail-content { padding: 1rem 1.25rem; clear: both; }
        .detail-sev {
            font-size: 0.75rem; font-weight: bold; padding: 0.2rem 0.5rem;
            border-radius: 3px; display: inline-block; margin-bottom: 0.75rem;
        }
        .detail-title {
            font-size: 1rem; font-weight: 700; color: var(--text);
            margin-bottom: 0.5rem; line-height: 1.4;
        }
        .detail-source { font-size: 0.75rem; color: var(--text2); margin-bottom: 1rem; }
        .detail-link {
            display: inline-block; margin-bottom: 1rem;
            font-size: 0.8rem; color: var(--accent); text-decoration: none;
        }
        .detail-link:hover { text-decoration: underline; }

        .detail-section { margin-bottom: 1rem; }
        .detail-section h3 {
            font-size: 0.7rem; text-transform: uppercase; letter-spacing: 1px;
            color: var(--text2); border-bottom: 1px solid var(--border);
            padding-bottom: 0.3rem; margin-bottom: 0.5rem;
        }
        .detail-summary { font-size: 0.82rem; color: var(--text2); line-height: 1.5; }

        .scores-row { display: flex; gap: 1rem; margin-bottom: 0.5rem; }
        .score-box {
            background: var(--bg3); border-radius: var(--radius);
            padding: 0.5rem 0.75rem; text-align: center; flex: 1;
        }
        .score-box-val { font-size: 1.4rem; font-weight: 900; }
        .score-box-lbl { font-size: 0.65rem; color: var(--text2); text-transform: uppercase; }

        .breakdown-list { font-size: 0.75rem; color: var(--text2); }
        .breakdown-list li { padding: 0.15rem 0; display: flex; justify-content: space-between; }
        .breakdown-list .bd-val { font-weight: bold; }
        .bd-pos { color: #06D6A0; }
        .bd-neg { color: #FF2A6D; }

        .tag-list { display: flex; flex-wrap: wrap; gap: 0.3rem; }
        .tag {
            font-size: 0.7rem; padding: 0.1rem 0.4rem;
            background: var(--bg3); border: 1px solid var(--border);
            border-radius: 3px; color: var(--text2);
        }

        .ioc-table { width: 100%; font-size: 0.72rem; border-collapse: collapse; }
        .ioc-table td { padding: 0.2rem 0.4rem; border-bottom: 1px solid var(--border); }
        .ioc-type { color: var(--accent); white-space: nowrap; }
        .ioc-value { color: var(--text2); word-break: break-all; }

        /* ── Responsive ────────────────────────────────────────────────── */
        @media (max-width: 768px) {
            .main-grid.detail-open { grid-template-columns: 1fr; }
            .detail-panel { position: fixed; inset: 60px 0 0; z-index: 200; }
            .cards-grid { grid-template-columns: 1fr; }
            .kpi-strip { overflow-x: auto; }
        }

        @media (prefers-reduced-motion: reduce) {
            .led, .card { animation: none; transition: none; }
        }
"""

    # ------------------------------------------------------------------
    # JavaScript (vanilla, aucune dépendance)
    # ------------------------------------------------------------------

    def _js(self) -> str:
        return r"""
'use strict';

/* ── État de l'application ─────────────────────────────────────────────── */
const state = {
    severity: 'all',
    days: 0,
    flags: new Set(),
    search: '',
    sort: 'score',
    selected: null,
};

const articles = window.__FULCRUM_DATA__ || [];

/* ── Couleurs sévérité ──────────────────────────────────────────────────── */
const SEV_COLORS = {
    FLASH: '#FF0040', CRITICAL: '#FF2A6D', HIGH: '#FF8C42',
    MEDIUM: '#FFD166', WATCH: '#06D6A0', INFO: '#78909C',
};
const sevColor = sev => SEV_COLORS[sev] || '#78909C';

/* ── Filtrage ───────────────────────────────────────────────────────────── */
function applyFilters() {
    const now = Date.now();
    let filtered = articles.filter(a => {
        /* Sévérité */
        if (state.severity !== 'all' && a.severity !== state.severity) return false;

        /* Zoom temporel */
        if (state.days > 0) {
            const pub = new Date(a.published).getTime();
            if (now - pub > state.days * 86400000) return false;
        }

        /* Flags thématiques (ET logique) */
        for (const flag of state.flags) {
            if (!a[flag]) return false;
        }

        /* Recherche texte (OR sur titre, source, CVEs, acteurs) */
        if (state.search) {
            const q = state.search.toLowerCase();
            const haystack = [
                a.title, a.source, a.summary,
                ...(a.cves || []), ...(a.actors || []), ...(a.theatres || []),
            ].join(' ').toLowerCase();
            if (!haystack.includes(q)) return false;
        }

        return true;
    });

    /* Tri */
    const SEV_ORDER = { FLASH: 0, CRITICAL: 1, HIGH: 2, MEDIUM: 3, WATCH: 4, INFO: 5 };
    if (state.sort === 'score')    filtered.sort((a, b) => b.score - a.score);
    if (state.sort === 'date')     filtered.sort((a, b) => b.published.localeCompare(a.published));
    if (state.sort === 'severity') filtered.sort((a, b) => (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));

    return filtered;
}

/* ── Rendu des cards ────────────────────────────────────────────────────── */
function renderCard(a) {
    const color = sevColor(a.severity);
    const flags = [];
    if (a.exploit)    flags.push('<span class="flag exploit" aria-label="Exploit disponible">⚡ EXPLOIT</span>');
    if (a.ransomware) flags.push('<span class="flag ransom"  aria-label="Ransomware">💀 RANSOM</span>');
    if (a.nuclear)    flags.push('<span class="flag nuclear" aria-label="Nucléaire">☢ NUCL</span>');
    if (a.apt)        flags.push('<span class="flag apt"     aria-label="APT nation-state">🎯 APT</span>');
    if (a.leak)       flags.push('<span class="flag leak"    aria-label="Fuite de données">🔓 LEAK</span>');
    if (a.in_kev)     flags.push('<span class="flag kev"     aria-label="Dans KEV CISA">🛡 KEV</span>');

    const cves = a.cves?.slice(0, 3).map(c => `<code style="font-size:0.65rem;color:#06D6A0">${c}</code>`).join(' ') || '';
    const date = a.published?.slice(0, 10) || '';
    const scoreBar = `<div class="score-fill" style="width:${Math.min(a.score,100)}%;background:${color}"></div>`;

    return `
    <article class="card" tabindex="0"
             style="--sev-color:${color}"
             data-id="${a.id}"
             aria-label="${a.severity}: ${a.title.slice(0,80)}"
             role="article">
        <div class="card-top">
            <span class="card-source">${escHtml(a.source)}</span>
            <span class="sev-badge" style="background:${color}">${a.severity}</span>
        </div>
        <div class="score-bar" aria-label="Score ${a.score}/100" role="progressbar"
             aria-valuenow="${a.score}" aria-valuemin="0" aria-valuemax="100">
            ${scoreBar}
        </div>
        <h2 class="card-title">${escHtml(a.title)}</h2>
        ${flags.length ? `<div class="card-flags">${flags.join('')}</div>` : ''}
        ${cves ? `<div style="margin-bottom:0.4rem">${cves}</div>` : ''}
        <div class="card-meta">
            <span>🕐 ${date}</span>
            <span>🔥 ${a.risk_score} | 🌍 ${a.strat_score}</span>
        </div>
    </article>`;
}

/* ── Rendu du panneau détail ────────────────────────────────────────────── */
function renderDetail(a) {
    const color = sevColor(a.severity);

    /* Breakdown */
    const bdItems = (a.breakdown || []).map(bd => {
        const [label, valStr] = bd.split(':').map(s => s.trim());
        const val = parseInt(valStr, 10);
        const cls = val >= 0 ? 'bd-pos' : 'bd-neg';
        return `<li><span>${escHtml(label)}</span><span class="bd-val ${cls}">${val >= 0 ? '+' : ''}${val}</span></li>`;
    }).join('');

    /* IOCs */
    let iocsHtml = '';
    if (a.iocs && Object.keys(a.iocs).length) {
        const rows = Object.entries(a.iocs).flatMap(([type, vals]) =>
            vals.map(v => `<tr><td class="ioc-type">${type}</td><td class="ioc-value">${escHtml(v)}</td></tr>`)
        ).join('');
        iocsHtml = `
        <div class="detail-section">
            <h3>IOCs</h3>
            <table class="ioc-table" aria-label="Indicateurs de compromission"><tbody>${rows}</tbody></table>
        </div>`;
    }

    /* Acteurs / théâtres / CVEs / tags */
    const actors   = a.actors?.length  ? `<div class="tag-list">${a.actors.map(t=>`<span class="tag">🎭 ${escHtml(t)}</span>`).join('')}</div>` : '';
    const theatres = a.theatres?.length ? `<div class="tag-list">${a.theatres.map(t=>`<span class="tag">🌍 ${escHtml(t)}</span>`).join('')}</div>` : '';
    const cves     = a.cves?.length     ? `<div class="tag-list">${a.cves.map(c=>`<span class="tag" style="color:#06D6A0;border-color:#06D6A0">${escHtml(c)}</span>`).join('')}</div>` : '';

    return `
    <span class="detail-sev" style="background:${color};color:#000">${a.severity}</span>
    <h2 class="detail-title">${escHtml(a.title)}</h2>
    <div class="detail-source">${escHtml(a.source)} — ${a.category || ''}</div>
    ${a.link ? `<a href="${escAttr(a.link)}" class="detail-link" target="_blank" rel="noopener noreferrer">→ Lire l'article ↗</a>` : ''}

    <div class="detail-section">
        <h3>Scores</h3>
        <div class="scores-row">
            <div class="score-box">
                <div class="score-box-val" style="color:${color}">${a.risk_score}</div>
                <div class="score-box-lbl">Risk Score</div>
            </div>
            <div class="score-box">
                <div class="score-box-val" style="color:#FF6B35">${a.strat_score}</div>
                <div class="score-box-lbl">Strat Score</div>
            </div>
            <div class="score-box">
                <div class="score-box-val">${a.score}</div>
                <div class="score-box-lbl">Composite</div>
            </div>
        </div>
        ${bdItems ? `<ul class="breakdown-list" aria-label="Décomposition du score">${bdItems}</ul>` : ''}
    </div>

    ${a.summary ? `
    <div class="detail-section">
        <h3>Résumé</h3>
        <p class="detail-summary">${escHtml(a.summary)}</p>
    </div>` : ''}

    ${actors || theatres || cves ? `
    <div class="detail-section">
        <h3>Contexte</h3>
        ${actors}${theatres}${cves}
    </div>` : ''}

    ${iocsHtml}

    <div class="detail-section">
        <h3>Publication</h3>
        <time class="detail-source" datetime="${escAttr(a.published)}">${a.published?.slice(0,19).replace('T',' ')} UTC</time>
    </div>`;
}

/* ── Mise à jour de l'affichage ─────────────────────────────────────────── */
function updateDisplay() {
    const filtered = applyFilters();
    const container = document.getElementById('cards-container');
    const countEl = document.getElementById('result-count');

    container.innerHTML = filtered.map(renderCard).join('');
    countEl.textContent = filtered.length;

    /* Événements click / keyboard sur les cards */
    container.querySelectorAll('.card').forEach(card => {
        const open = () => openDetail(card.dataset.id);
        card.addEventListener('click', open);
        card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
    });

    announce(`${filtered.length} articles affichés`);
}

/* ── Panneau de détail ──────────────────────────────────────────────────── */
function openDetail(id) {
    const a = articles.find(x => x.id === id);
    if (!a) return;
    state.selected = id;

    const panel = document.getElementById('detail-panel');
    const content = document.getElementById('detail-content');
    const grid = document.querySelector('.main-grid');

    content.innerHTML = renderDetail(a);
    panel.removeAttribute('hidden');
    grid.classList.add('detail-open');
    panel.focus();
}

function closeDetail() {
    const panel = document.getElementById('detail-panel');
    const grid = document.querySelector('.main-grid');
    panel.setAttribute('hidden', '');
    grid.classList.remove('detail-open');
    state.selected = null;
}

/* ── Utilitaires ─────────────────────────────────────────────────────────── */
function escHtml(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(s) {
    return String(s ?? '').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function announce(msg) {
    const el = document.getElementById('sr-announcer');
    el.textContent = '';
    setTimeout(() => { el.textContent = msg; }, 50);
}

/* ── Initialisation des contrôles ───────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
    /* Sévérité */
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => {
                b.classList.remove('active'); b.setAttribute('aria-pressed', 'false');
            });
            btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true');
            state.severity = btn.dataset.filter;
            updateDisplay();
        });
    });

    /* Zoom temporel */
    document.querySelectorAll('.time-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.time-btn').forEach(b => {
                b.classList.remove('active'); b.setAttribute('aria-pressed', 'false');
            });
            btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true');
            state.days = parseInt(btn.dataset.days, 10);
            updateDisplay();
        });
    });

    /* Flags */
    document.querySelectorAll('.flag-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const flag = btn.dataset.flag;
            if (state.flags.has(flag)) {
                state.flags.delete(flag);
                btn.classList.remove('active'); btn.setAttribute('aria-pressed', 'false');
            } else {
                state.flags.add(flag);
                btn.classList.add('active'); btn.setAttribute('aria-pressed', 'true');
            }
            updateDisplay();
        });
    });

    /* Recherche (debounce 250ms) */
    let searchTimer;
    document.getElementById('search-input').addEventListener('input', e => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            state.search = e.target.value.trim();
            updateDisplay();
        }, 250);
    });

    /* Tri */
    document.getElementById('sort-select').addEventListener('change', e => {
        state.sort = e.target.value;
        updateDisplay();
    });

    /* Fermeture détail */
    document.getElementById('close-detail').addEventListener('click', closeDetail);
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') closeDetail();
    });

    /* Rendu initial */
    updateDisplay();
});
"""
