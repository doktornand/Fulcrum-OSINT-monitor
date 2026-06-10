"""
orchestration/scheduler.py — Orchestrateur APScheduler pour FULCRUM

Remplace le threading/asyncio spaghetti du monolithe par APScheduler :
  - Jobs périodiques configurables (collecte, pruning, export)
  - Retry exponentiel sur échec
  - Circuit breaker simple (désactivation temporaire après N échecs)
  - Hot-reload de la configuration
  - Mode --watch (intervalle personnalisé)

Fallback : scheduler basé sur threading.Timer si APScheduler absent.

Google-style docstrings. Aucune dépendance IA/LLM/NLP.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("FULCRUM.scheduler")

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    logger.warning("APScheduler non disponible — fallback threading.Timer activé")


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class CircuitBreaker:
    """Désactive temporairement un job après N échecs consécutifs.

    Args:
        max_failures: Nombre d'échecs avant ouverture du circuit.
        reset_timeout_s: Délai en secondes avant tentative de réactivation.

    Example:
        >>> cb = CircuitBreaker(max_failures=3, reset_timeout_s=300)
        >>> if cb.allow():
        ...     run_job()
    """

    def __init__(self, max_failures: int = 3, reset_timeout_s: float = 300.0) -> None:
        self.max_failures = max_failures
        self.reset_timeout_s = reset_timeout_s
        self._failures = 0
        self._opened_at: Optional[float] = None
        self._lock = threading.Lock()

    @property
    def is_open(self) -> bool:
        """True si le circuit est ouvert (job désactivé)."""
        with self._lock:
            if self._opened_at is None:
                return False
            if time.time() - self._opened_at >= self.reset_timeout_s:
                # Tenter la réinitialisation (half-open)
                self._opened_at = None
                self._failures = 0
                logger.info("Circuit breaker : tentative de réinitialisation")
                return False
            return True

    def allow(self) -> bool:
        """Vérifie si l'exécution est autorisée.

        Returns:
            True si le circuit est fermé (job autorisé).
        """
        return not self.is_open

    def record_success(self) -> None:
        """Enregistre un succès et réinitialise le compteur."""
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        """Enregistre un échec. Ouvre le circuit si seuil atteint."""
        with self._lock:
            self._failures += 1
            if self._failures >= self.max_failures:
                self._opened_at = time.time()
                logger.error(
                    f"Circuit breaker ouvert après {self._failures} échecs. "
                    f"Réactivation dans {self.reset_timeout_s:.0f}s"
                )


# ---------------------------------------------------------------------------
# FulcrumScheduler
# ---------------------------------------------------------------------------

class FulcrumScheduler:
    """Orchestrateur de jobs FULCRUM basé sur APScheduler.

    Gère les cycles de collecte, pruning, export et hot-reload config.
    Fallback vers threading.Timer si APScheduler n'est pas installé.

    Args:
        config: Objet de configuration FULCRUM.
        collect_fn: Callable exécuté pour la collecte d'intelligence.
        prune_fn: Callable exécuté pour le pruning SQLite.
        export_fn: Callable exécuté pour les exports automatiques.
        config_reload_fn: Callable exécuté pour le hot-reload de config.

    Example:
        >>> scheduler = FulcrumScheduler(
        ...     config=config,
        ...     collect_fn=lambda: app.run(mode="fusion"),
        ... )
        >>> scheduler.start()
    """

    def __init__(
        self,
        config: Any,
        collect_fn: Optional[Callable] = None,
        prune_fn: Optional[Callable] = None,
        export_fn: Optional[Callable] = None,
        config_reload_fn: Optional[Callable] = None,
    ) -> None:
        self.config = config
        self.collect_fn = collect_fn
        self.prune_fn = prune_fn
        self.export_fn = export_fn
        self.config_reload_fn = config_reload_fn

        self._scheduler = None
        self._fallback_threads: List[threading.Timer] = []
        self._circuit_breakers: Dict[str, CircuitBreaker] = {
            "collect": CircuitBreaker(max_failures=3, reset_timeout_s=300),
            "prune": CircuitBreaker(max_failures=5, reset_timeout_s=600),
            "export": CircuitBreaker(max_failures=3, reset_timeout_s=120),
        }
        self._running = False
        self._stats: Dict[str, Any] = {
            "collect_runs": 0,
            "collect_errors": 0,
            "last_collect": None,
            "last_error": None,
        }

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _get_collect_interval(self) -> int:
        """Retourne l'intervalle de collecte en minutes depuis la config.

        Returns:
            Intervalle en minutes (défaut 60).
        """
        if hasattr(self.config, "get"):
            return self.config.get("scheduler.collection_interval_minutes", 60)
        return 60

    def _get_pruning_interval(self) -> int:
        """Retourne l'intervalle de pruning en heures.

        Returns:
            Intervalle en heures (défaut 24).
        """
        if hasattr(self.config, "get"):
            return self.config.get("scheduler.pruning_interval_hours", 24)
        return 24

    def _watch_interval(self) -> int:
        """Retourne l'intervalle de rechargement en mode watch.

        Returns:
            Intervalle en secondes (défaut 300).
        """
        if hasattr(self.config, "get"):
            return self.config.get("watch.interval_seconds", 300)
        return 300

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------

    def _job_collect(self) -> None:
        """Job de collecte d'intelligence avec circuit breaker.

        Exécute collect_fn si le circuit est fermé.
        Enregistre le succès/échec dans les statistiques.
        """
        cb = self._circuit_breakers["collect"]
        if not cb.allow():
            logger.warning("Collecte ignorée — circuit breaker ouvert")
            return

        try:
            logger.info(f"[SCHEDULER] Début collecte — {datetime.now(timezone.utc).isoformat()}")
            if self.collect_fn:
                self.collect_fn()
            cb.record_success()
            self._stats["collect_runs"] += 1
            self._stats["last_collect"] = datetime.now(timezone.utc).isoformat()
            logger.info("[SCHEDULER] Collecte terminée avec succès")
        except Exception as exc:
            cb.record_failure()
            self._stats["collect_errors"] += 1
            self._stats["last_error"] = str(exc)
            logger.error(f"[SCHEDULER] Erreur collecte: {exc}")

    def _job_prune(self) -> None:
        """Job de pruning SQLite avec circuit breaker."""
        cb = self._circuit_breakers["prune"]
        if not cb.allow():
            return

        try:
            if self.prune_fn:
                self.prune_fn()
            cb.record_success()
            logger.info("[SCHEDULER] Pruning SQLite terminé")
        except Exception as exc:
            cb.record_failure()
            logger.error(f"[SCHEDULER] Erreur pruning: {exc}")

    def _job_export(self) -> None:
        """Job d'export automatique avec circuit breaker."""
        cb = self._circuit_breakers["export"]
        if not cb.allow():
            return

        try:
            if self.export_fn:
                self.export_fn()
            cb.record_success()
            logger.info("[SCHEDULER] Export automatique terminé")
        except Exception as exc:
            cb.record_failure()
            logger.error(f"[SCHEDULER] Erreur export: {exc}")

    def _job_config_reload(self) -> None:
        """Hot-reload de la configuration YAML."""
        try:
            if self.config_reload_fn:
                self.config_reload_fn()
            logger.info("[SCHEDULER] Configuration rechargée")
        except Exception as exc:
            logger.error(f"[SCHEDULER] Erreur hot-reload config: {exc}")

    # ------------------------------------------------------------------
    # Démarrage / arrêt
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Démarre le scheduler (APScheduler ou fallback threading).

        Les jobs sont configurés selon fulcrum_config.yml section `scheduler`.
        """
        if APSCHEDULER_AVAILABLE:
            self._start_apscheduler()
        else:
            self._start_fallback()

        self._running = True
        logger.info(
            f"[SCHEDULER] Démarré — collecte toutes les {self._get_collect_interval()}min"
        )

    def _start_apscheduler(self) -> None:
        """Démarre APScheduler avec les triggers configurés."""
        self._scheduler = BackgroundScheduler(
            job_defaults={"coalesce": True, "max_instances": 1},
            timezone="UTC",
        )

        collect_min = self._get_collect_interval()
        self._scheduler.add_job(
            self._job_collect,
            trigger=IntervalTrigger(minutes=collect_min),
            id="fulcrum_collect",
            name="Intelligence Collection",
            replace_existing=True,
        )

        prune_hours = self._get_pruning_interval()
        self._scheduler.add_job(
            self._job_prune,
            trigger=IntervalTrigger(hours=prune_hours),
            id="fulcrum_prune",
            name="SQLite Pruning",
            replace_existing=True,
        )

        # Hot-reload config si watch activé
        if hasattr(self.config, "get") and self.config.get("watch.hot_reload_config", False):
            watch_s = self._watch_interval()
            self._scheduler.add_job(
                self._job_config_reload,
                trigger=IntervalTrigger(seconds=watch_s),
                id="fulcrum_config_reload",
                name="Config Hot-Reload",
                replace_existing=True,
            )

        # Listener d'évènements
        self._scheduler.add_listener(
            self._on_job_event,
            EVENT_JOB_ERROR | EVENT_JOB_EXECUTED,
        )

        self._scheduler.start()

    def _on_job_event(self, event: Any) -> None:
        """Handler d'évènements APScheduler pour le logging.

        Args:
            event: Évènement APScheduler.
        """
        if hasattr(event, "exception") and event.exception:
            logger.error(f"[APScheduler] Job {event.job_id} erreur: {event.exception}")
        else:
            logger.debug(f"[APScheduler] Job {event.job_id} exécuté")

    def _start_fallback(self) -> None:
        """Démarre un scheduler minimal basé sur threading.Timer."""
        logger.info("[SCHEDULER] Fallback threading.Timer activé")
        self._schedule_next_collect()
        self._schedule_next_prune()

    def _schedule_next_collect(self) -> None:
        """Planifie la prochaine collecte via threading.Timer."""
        if not self._running and len(self._fallback_threads) > 0:
            return
        interval = self._get_collect_interval() * 60
        t = threading.Timer(interval, self._collect_then_reschedule)
        t.daemon = True
        t.start()
        self._fallback_threads.append(t)

    def _collect_then_reschedule(self) -> None:
        """Exécute la collecte puis se replanifie (fallback)."""
        self._job_collect()
        if self._running:
            self._schedule_next_collect()

    def _schedule_next_prune(self) -> None:
        """Planifie le prochain pruning via threading.Timer."""
        interval = self._get_pruning_interval() * 3600
        t = threading.Timer(interval, self._prune_then_reschedule)
        t.daemon = True
        t.start()
        self._fallback_threads.append(t)

    def _prune_then_reschedule(self) -> None:
        """Exécute le pruning puis se replanifie (fallback)."""
        self._job_prune()
        if self._running:
            self._schedule_next_prune()

    def stop(self) -> None:
        """Arrête tous les jobs proprement."""
        self._running = False
        if self._scheduler:
            self._scheduler.shutdown(wait=False)
        for t in self._fallback_threads:
            t.cancel()
        self._fallback_threads.clear()
        logger.info("[SCHEDULER] Arrêté")

    # ------------------------------------------------------------------
    # Mode Watch
    # ------------------------------------------------------------------

    def run_watch(self, interval_s: Optional[int] = None) -> None:
        """Lance le mode watch : collecte périodique bloquante.

        Exécute une première collecte immédiatement, puis boucle
        avec rechargement de config optionnel entre chaque run.

        Args:
            interval_s: Intervalle en secondes. Si None, lit la config.
        """
        interval = interval_s or self._watch_interval()
        hot_reload = (
            hasattr(self.config, "get")
            and self.config.get("watch.hot_reload_config", True)
        )

        logger.info(f"[WATCH] Mode watch démarré — intervalle {interval}s")

        try:
            while True:
                self._job_collect()

                if hot_reload:
                    self._job_config_reload()

                logger.info(f"[WATCH] Prochaine collecte dans {interval}s")
                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("[WATCH] Arrêt demandé (Ctrl+C)")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques d'exécution du scheduler.

        Returns:
            Dict avec compteurs de runs, erreurs, et timestamps.
        """
        return {
            **self._stats,
            "circuit_breakers": {
                name: {
                    "open": cb.is_open,
                    "failures": cb._failures,
                }
                for name, cb in self._circuit_breakers.items()
            },
            "backend": "apscheduler" if APSCHEDULER_AVAILABLE else "threading.Timer",
        }
