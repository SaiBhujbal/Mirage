"""
Scheduler for the guarded MLOps cycle — closes the "runner is one-shot, you schedule it"
limitation.

`ml/mlops_runner.py` performs ONE guarded cycle (capture -> poison guard -> accumulation
check -> maybe retrain -> gate -> canary). Something has to invoke it on a cadence. This is
that something, with the properties an unattended retrain loop actually needs:

  - **It cannot stampede.** A file lock means two schedulers (or a stray manual run) never
    execute a cycle concurrently — concurrent retrains racing on the model registry is a
    corruption path, not a speedup.
  - **It fails soft.** A cycle that raises is logged and the loop continues; one bad cycle
    must not kill the scheduler and silently stop all future retraining.
  - **It backs off.** Consecutive failures increase the sleep (capped), so a persistently
    broken dependency doesn't spin hot.
  - **It is observable.** Every cycle appends a JSON line to data/corpus/mlops_cycles.jsonl
    (start, end, outcome, error) so you can prove the loop ran, and when.
  - **It respects the accumulation gate.** Most cycles will report HELD - accumulating and
    do nothing. That is correct: the store releases a batch only when it is large, balanced,
    diverse, multi-source and aged.

The safety chain is unchanged — this only decides WHEN a cycle runs, never whether a model
is promoted. Human review, poison guard, promotion gate and canary all still apply.

Usage:
    python -m ml.mlops_scheduler                     # loop forever, default 6h interval
    python -m ml.mlops_scheduler --interval 3600     # every hour
    python -m ml.mlops_scheduler --once              # single cycle (cron/systemd mode)
    MLOPS_INTERVAL_S=21600 python -m ml.mlops_scheduler

Deployment options:
    docker compose up mlops        # the bundled service runs this
    cron:    0 */6 * * *  cd /app && python -m ml.mlops_scheduler --once
    systemd: a .timer calling  python -m ml.mlops_scheduler --once
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s [mlops-scheduler] %(message)s")
log = logging.getLogger("mlops.scheduler")

_ROOT = Path(__file__).resolve().parent.parent
_LOCK = _ROOT / "data" / "corpus" / ".mlops_cycle.lock"
_JOURNAL = _ROOT / "data" / "corpus" / "mlops_cycles.jsonl"

DEFAULT_INTERVAL_S = 6 * 60 * 60      # 6h: retrain cadence, not a polling loop
MAX_BACKOFF_S = 60 * 60               # cap the failure backoff at 1h
LOCK_STALE_S = 6 * 60 * 60            # a lock older than this is treated as abandoned


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _journal(record: dict) -> None:
    """Append one cycle record. Never raises — observability must not break the loop."""
    try:
        _JOURNAL.parent.mkdir(parents=True, exist_ok=True)
        with _JOURNAL.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception as e:                                    # pragma: no cover
        log.warning("could not write cycle journal: %s", e)


def _acquire_lock() -> bool:
    """
    Exclusive-create a lock file. Returns False if another cycle holds it.

    A stale lock (older than LOCK_STALE_S, i.e. the holder died) is reclaimed, otherwise a
    crashed cycle would wedge the loop permanently.
    """
    try:
        _LOCK.parent.mkdir(parents=True, exist_ok=True)
        if _LOCK.exists():
            age = time.time() - _LOCK.stat().st_mtime
            if age < LOCK_STALE_S:
                return False
            log.warning("reclaiming stale lock (age %.0fs) — previous cycle likely died", age)
            _LOCK.unlink(missing_ok=True)
        # O_EXCL: atomic, so two schedulers cannot both believe they won.
        fd = os.open(str(_LOCK), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"pid": os.getpid(), "started": _now()}))
        return True
    except FileExistsError:
        return False
    except Exception as e:
        log.error("lock error (%s) — skipping this cycle rather than risking a concurrent run", e)
        return False


def _release_lock() -> None:
    try:
        _LOCK.unlink(missing_ok=True)
    except Exception as e:                                    # pragma: no cover
        log.warning("could not release lock: %s", e)


def run_cycle() -> dict:
    """
    Run exactly one guarded MLOps cycle. Returns a result record; never raises.

    Import is deferred to call time so a broken ML dependency surfaces as a failed CYCLE
    (logged, retried next tick) rather than a scheduler that will not start at all.
    """
    started = _now()
    t0 = time.perf_counter()
    if not _acquire_lock():
        log.info("another cycle is in progress — skipping")
        return {"started": started, "outcome": "skipped_locked"}

    try:
        from ml.mlops_runner import run_cycle as runner_cycle  # noqa: PLC0415 (deferred on purpose)
        report = runner_cycle() or {}
        # The runner returns its report dict; surface the decision so the journal shows
        # WHY a cycle did nothing (almost always: the accumulation gate held the batch).
        outcome = "ok"
        summary = {k: report[k] for k in ("released", "ready", "promoted", "canary", "seconds")
                   if isinstance(report, dict) and k in report}
        log.info("cycle finished: %s %s (%.1fs)", outcome, summary or "", time.perf_counter() - t0)
        return {"started": started, "ended": _now(),
                "seconds": round(time.perf_counter() - t0, 2),
                "outcome": outcome, "summary": summary}
    except Exception as e:
        log.exception("cycle FAILED — loop continues, will retry next interval")
        return {"started": started, "ended": _now(),
                "seconds": round(time.perf_counter() - t0, 2),
                "outcome": "error", "error": f"{type(e).__name__}: {e}"[:500]}
    finally:
        _release_lock()


def loop(interval_s: int) -> int:
    log.info("scheduler started — cycle every %ss (journal: %s)", interval_s, _JOURNAL)
    consecutive_failures = 0
    while True:
        record = run_cycle()
        _journal(record)

        if record.get("outcome") == "error":
            consecutive_failures += 1
            # Exponential backoff so a persistent breakage doesn't spin hot.
            delay = min(interval_s * (2 ** (consecutive_failures - 1)), MAX_BACKOFF_S)
            log.warning("failure #%d — backing off %ss", consecutive_failures, delay)
        else:
            consecutive_failures = 0
            delay = interval_s

        try:
            time.sleep(delay)
        except KeyboardInterrupt:
            log.info("interrupted — shutting down cleanly")
            return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scheduler for the guarded MLOps retrain cycle")
    ap.add_argument("--interval", type=int,
                    default=int(os.environ.get("MLOPS_INTERVAL_S", DEFAULT_INTERVAL_S)),
                    help="seconds between cycles (default 21600 = 6h)")
    ap.add_argument("--once", action="store_true",
                    help="run a single cycle and exit (for cron / systemd timers)")
    args = ap.parse_args(argv)

    if args.once:
        record = run_cycle()
        _journal(record)
        return 0 if record.get("outcome") in ("ok", "skipped_locked") else 1

    if args.interval < 60:
        log.error("interval must be >= 60s (retraining is not a polling loop)")
        return 2
    return loop(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
