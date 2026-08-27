# Mirage WAF — Go-Live Runbook

A staged path from install to full enforcement. The governing principle, learned the hard way:
**a passing harness proves the WAF blocks known attacks with zero FP *on a 21-sample corpus*; it
does NOT prove a low false-positive rate on YOUR traffic.** Every serious FP this project found
(a blocked "select an option", a blocked `id=`/`pwd=` parameter) sailed through a green harness.
So enforcement is earned by measuring shadow behavior on real traffic — never assumed.

## Phase 0 — Secrets & config (before anything is exposed)
- [ ] `cp .env.example .env`, then generate every secret the file documents (admin key hash, Redis
      password, session/audit signing keys). Do NOT ship the placeholder values.
- [ ] **Rotate the Tavily API key** if one was ever shared in plaintext. It lives only in the
      gitignored `.env`; `.env.example` must stay a blank placeholder. Unset = threat-intel is
      disabled and offline-safe.
- [ ] Set `EXPECTED_HOSTS` to the hostnames you actually serve (enables host-header/cache-poisoning
      detection; unset turns that check off).
- [ ] Set `REDIS_URL` for multi-replica rate limiting (without it the limit is per-process).
- [ ] Confirm `demo/` is not deployed — `demo/secret_config.txt` is a path-traversal *honeypot*
      with fake secrets, intended only for the demo app.

## Phase 1 — Signatures enforce, ML shadow (safe default; ship here first)
This is the default posture and the recommended day-one production state.
```
WAF_ML_MODEL=gcid          # distribution-free injection detector
WAF_ML_ENFORCE=false       # ML observes + logs, does not block
WAF_GCID_ENFORCE=false     # GCID observes + logs, does not block
WAF_SHADOW_ROUTES=         # (fill in Phase 2)
```
The signature/scanner tier enforces (it passes the harness hard gates: recall 1.0, 0 FP on corpus,
ReDoS-safe, fail-closed on truncation). ML runs in shadow. **Watch `LayeredWAF.stats()`** (exposed
via the metrics endpoint): the ratio `counters.shadow_would_block / counters.total` is your ML
would-block rate on live traffic. This is the number that decides Phase 3.

## Phase 2 — Scope the content-type boundary
Injection signatures + GCID cannot know that a field is *supposed* to contain code. Any endpoint
that legitimately carries SQL/shell/markup (admin query console, paste/snippet service, GraphQL or
other DSL) will be false-positived.
- [ ] Enumerate those routes and set `WAF_SHADOW_ROUTES=/admin/query,/paste,/api/graphql`.
      On these prefixes the WAF still scans and logs (visibility preserved) but does not 403.
- [ ] Re-check `stats()` after: the blocked-count on those paths should drop to shadow-only.

## Phase 3 — Turn on ML enforcement (only after the number is good)
Gate: the Phase-1 shadow would-block rate on **real benign traffic** is within your tolerance
(e.g. < 0.1%), and spot-checking the shadow_would_block log entries shows they are real attacks,
not legitimate users.
```
WAF_GCID_ENFORCE=true          # GCID now blocks, with its conformal false-alarm bound
WAF_GCID_ENFORCE_ALPHA=0.002   # tighten/loosen the guarantee
```
Roll out to a **canary** slice first (a fraction of replicas/traffic), watch block-rate and any
support signal for a bake period, then widen. `ml/canary_deploy.py` + `metrics/false_positive_monitor.py`
support staged model promotion with FP/recall gates and automatic rollback.

## Rollback
Instant, no redeploy: set `WAF_GCID_ENFORCE=false` (and/or `WAF_ML_ENFORCE=false`) and restart —
the WAF drops to signatures-enforce + ML-shadow, the Phase-1 known-good state.

## Known residual risks (documented, not hidden)
- **Regex/grammar WAF, not a tokenizer.** It stops known classes; a determined adversary iterating
  on encodings and alternate SQL dialects will keep probing. Keep signatures updated.
- **Bare space-delimited DML** (`id=1 SELECT name`, no punctuation) is an accepted residual: it is
  not a valid inline injection, and forcing a digit-context rule reintroduces prose FPs. The
  dangerous forms (stacked `;`, boolean, `UNION`, `EXEC <proc>`) ARE caught.
- **Business logic is out of scope** for GCID and the signatures (IDOR, mass-assignment, auth
  bypass have no injection syntax). Cover these at the application layer.
- **GCID enforcement readiness = clears our regression floor**, not a safety proof on your traffic.
  Phases 1–3 exist precisely to close that gap with measurement.

## Test/CI note
CI runs a curated quality-gate suite (green). The full `pytest tests/` shows SKIPs for legacy/demo
modules whose optional deps (pandas/fastapi/orjson/pydantic_settings) aren't installed, plus a
numpy/sklearn/xgboost ABI mismatch on Python 3.14 that corrupts numpy mid-process for a few legacy
ML tests. Neither is a WAF code defect; the GCID + signature tests pass in isolation and in CI.
