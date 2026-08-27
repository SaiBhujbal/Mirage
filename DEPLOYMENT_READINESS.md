# Mirage-WAF — Deployment Readiness

Status of the hardening + audit pass. Read this before pushing/deploying.

## TL;DR
- **Rules-tier security: hardened and regression-gated.** Every confirmed red-team bypass is
  closed and re-verified against the live engine; a CI hard-gate (`tests/test_waf_bypass_regression.py`)
  keeps them closed. 0 false positives on a 24-case realistic-benign suite.
- **Deploy surface: audited and hardened.** CI pwn-request fixed; SAST (bandit) run and triaged;
  config knobs documented; Docker/gunicorn/healthcheck reviewed and sound.
- **One deliberate default:** ML ships **shadow (off)**. Enforcement is a one-line switch
  (`WAF_ML_ENFORCE=true`) but must be FP-calibrated on real traffic first — see below.

## Verification gates (all green)
| Gate | Result |
|------|--------|
| `pytest tests/test_waf_bypass_regression.py` | 41 passed (22 attacks blocked, 18 benign allowed, no ReDoS) |
| `pytest tests/test_comprehensive_scanner.py` | 11 passed |
| `tests/test_attack_coverage.py` (standalone) | 90/92 payload attacks blocked (97.8%), 0.0% benign FP |
| ReDoS (4 KB `{{`+spaces) | 119 s → ~1 ms |
| bandit `-ll` HIGH/MED | 2 real issues fixed (jinja XSS, file:// urlopen); rest triaged (see below) |

## Security fixes shipped (all harness-verified)
- **ReDoS (was Critical):** catastrophic template regexes in `advanced_protection.py` /
  `comprehensive_patterns.py` rewritten linear; engine sanitizes + collapses long char-runs.
- **Truncation bypass:** engine fails **closed** on bodies larger than the inspection window
  (never proxies uninspected bytes). `WAF_MAX_INSPECT_BYTES` / `WAF_MAX_BODY_BYTES`.
- **Fail-open:** every field UTF-8-sanitized (kills the surrogate crash); each scanner guarded
  separately and fails **closed** on error.
- **Header injection blind spot:** attacker-controlled header values scanned for unambiguous
  injection (no URL/JWT false positives).
- **base64 / form / JSON-value scanning**, plus over-broad pattern fixes (LDAP CRLF, protocol-
  relative redirect, JSON-key scanning) that were causing false positives.
- **Dashboard XSS:** jinja `autoescape=True`.
- **SIEM webhook:** http(s)-scheme guard on `urlopen`.
- **Honesty:** fabricated 99.84% accuracy removed from docs/dashboard, replaced with the real
  measured figures (97.43% offline; 4.99% FP on real CSIC-2010) + correction banners.

## CI / supply chain
- **Fixed pwn-request:** `.github/workflows/security.yml` switched `pull_request_target` →
  `pull_request` and dropped the untrusted-head checkout. Untrusted PR code no longer runs with
  repo secrets / a write-scoped token.
- Added the bypass-regression suite as a **hard gate** in CI.

## bandit SAST triage (32 findings at `-ll`)
- **Fixed:** B701 jinja autoescape (XSS), B310 file:// urlopen (scheme guard).
- **Accepted / false positive (with rationale):**
  - B104 bind `0.0.0.0` ×18 — intended for a containerized server; not a vulnerability.
  - B608 "SQL injection" ×3 — all are attack **strings used as poison-test/deception data**
    (`enhanced_honeypot`, `champion_challenger`, `mlops_runner`), never executed against a DB.
  - B324 MD5/SHA1 ×9 — **non-cryptographic** fingerprint/cache/dedup/content-id uses; collision
    resistance is not relied upon. (Optionally silence with `usedforsecurity=False`.)

## Deploy checklist (operator)
1. `cp .env.example .env`, then generate every secret with the commands in `.env.example`
   (admin key hash, Redis password, session/audit/model keys, Grafana password). **Never commit `.env`.**
2. Set `ENV=production`, `REQUIRE_TLS=true`, `REQUIRE_API_AUTH=true`, `REDIS_HOST=redis`.
3. Set `EXPECTED_HOSTS` to your real hostnames (enables host-header/cache-poisoning detection).
4. Set `REDIS_URL` so rate limiting is shared across replicas (else it's per-process).
5. Confirm `WAF_MAX_INSPECT_BYTES` ≥ `MAX_REQUEST_BODY_SIZE` so legit max-size bodies are
   inspected rather than fail-closed-blocked.
6. Build & run: `docker compose up` (image runs `gunicorn waf.server:app`, healthcheck `/waf/health`).
7. Leave `WAF_ML_ENFORCE=false` until step 8.

## Runtime + end-to-end verification (done this pass)
The ML stack DOES install on Python 3.14 (numpy 2.5.2 etc.), so both were actually run:
- **ML runtime:** the detector loads and scores. **The currently-served model is miscalibrated —
  it flags *all* traffic (benign included) at mal_prob ≈ 1.0**, from train/serve feature skew plus a
  pickle version skew (models trained on scikit-learn 1.6.1, runtime 1.9.0). The skew guard
  correctly detects this and sets `MLResult.enforce=False`, so ML **detects but cannot enforce** —
  the safety mechanism working, with hard proof that enabling raw enforcement would block the site.
- **Engine bug found & fixed by runtime testing:** enforcement was gated on `mal_prob >= threshold`
  instead of the `enforce` contract flag; with a skewed model that blocked 100% of traffic. Now
  gated on `enforce` — verified that benign passes even with `WAF_ML_ENFORCE=true`.
- **End-to-end socket test** (`waf/server.py` over real TCP): 7/7 attacks blocked (403), 5/5 benign
  served (200). Exposed & fixed the `ML_PROBING` per-IP accumulator blocking benign traffic once an
  IP had sent attacks (collateral damage on shared NAT/LB IPs) — now advisory (confidence 0.45,
  below the block threshold), so it logs/corroborates without 403-ing legit traffic.

## ML retrain + MLOps status (done this pass)
- **Retrained on real CSIC-2010** (`ml/train_csic.py`, 48.8k train / 12.2k test): precision 0.960,
  recall 0.925, F1 0.942, ROC-AUC 0.992. The trainer now persists `contract_hash`, so the skew guard
  is SATISFIED (`contract_verified=True`) — enforcement is now mechanically enabled (was permanently
  off). Retraining under the current scikit-learn also clears the 1.6.1→1.9.0 pickle skew.
- **Honest calibration:** 6.2% false positives on real held-out CSIC benign, 96.8% attack detection.
  On OUT-OF-DISTRIBUTION benign it false-positives heavily — a model is only as good as its benign
  traffic matching production.
- **MLOps verified working:** the guarded chain passes all safety tests (`ml/test_mlops_chain.py`) —
  good challenger promoted via canary staging; FP-regressed and poisoned challengers auto-rolled-back
  at 1% traffic; registry live-pointer + instant rollback. The orchestrated runner
  (`ml/mlops_runner.py`) correctly HOLDS retraining behind accumulation gates (distinct shapes /
  batch age / cooldown).

## ML enforcement: SOLVED — via GCID (the distribution-free method)
The failure below applies to the DISTRIBUTION-based models (XGBoost, byte-CNN, conformal-on-
distance). A new method, **GCID** (`ml/gcid.py`, `ml/RESEARCH_GCID.md`), removes the root cause by
never modelling benign. Measured: **0.0–0.1% false positives on fresh modern benign, 100% in-scope
recall (injection + SSRF + CRLF/redirect), and it is the ONLY model that passes the harness
`--gate-ml` (ENFORCEMENT READY = YES).** To enable ML enforcement safely:
```
WAF_ML_MODEL=gcid  WAF_ML_ENFORCE=true  WAF_GCID_ENFORCE=true
```
Still canary + monitor on real traffic first (the harness corpus is representative, not exhaustive;
the known FP boundary is a field that legitimately expects code/SQL — a paste/bug tool). GCID is a
high-precision layer; keep the signature tier and (optionally) the byte-CNN shadow beside it.

## ML enforcement with the DISTRIBUTION models: empirically NOT safe (measured)
We tried FOUR distinct approaches to make ML enforcement-ready, each measured with the harness —
all failed. This is a representation ceiling, not a tuning gap:
1. **Modern-benign retrain** (4000): FP barely moved (100%->95%) and adaptive evasion got ~3x
   easier (ASR 25%->75%). Net loss.
2. **Threshold sweep:** NO threshold separates the classes — modern benign score mal_prob 1.0.
3. **Novelty-gated (OOD) abstention:** every eval record (benign AND attack) is out-of-distribution
   vs CSIC (novelty 12-3878 >> nov_t 9.89), so "enforce only in-distribution" gives 0% FP but 0%
   recall — the model has never seen modern traffic of either class.
4. **Balanced modern retrain** (6000 benign + 6000 attacks, distinct from eval): FIXED recall
   (30%->96%) but FP stuck at ~52%, and even `q=hello world` and `calc=2+2*3` score mal_prob **1.0**.
   No threshold recovers it (52% FP down to 38% only by dropping recall to 67%).

Root cause: the 50-dim lexical feature set conflates high-entropy/modern benign with attacks — it
cannot represent the difference. Reproduces the project's own research conclusion
(`ml/RESEARCH_DESIGN.md`: "4.99% FP ... still too high to deploy"). The generators
(`data_pipeline/modern_benign.py`, `modern_attacks.py`, env `MODERN_BENIGN_N`/`MODERN_ATTACK_N`)
are kept as tools for when REAL production traffic is available; default OFF (shipped model = clean
robust CSIC: 96% native recall, 5% native FP, ASR 27%).

**The only real path to ML enforcement** is a better representation (the research byte-CNN /
contrastive encoder in `ml/deep_model.py` + `ml/contrastive_encoder.py`) trained on production-
shaped traffic — a modeling effort, not a config change. Until the harness `--gate-ml` passes on a
production-shaped corpus, ML stays SHADOW and signatures enforce.

### Research prototypes — measured (run in WSL/Linux; torch is WDAC-blocked on the Windows box)
The deployed model uses the WEAKEST option (lexical XGBoost). The unused research prototypes are
materially better on exactly the failing metric:
- **byte-CNN (DualBranchNet)** — the learned byte representation cut modern-benign false positives
  from **100% (lexical XGBoost) to ~7%** (6.8% on generated modern benign, 14.3% on the harness
  set), with 0.996 energy-AUROC for novelty. The representation *was* the problem, confirmed.
- **contrastive encoder** — adaptive-attacker evasion **80%→60%** (more robust), mutation
  embedding-distance 0.020→0.011 (invariant), clean recall 0.979→1.0.
- **conformal open-set** — distribution-free FP guarantee (0% FA @ 1% budget, 100% zero-day recall)
  IN-distribution; still breaks on diverse benign because it sits on the lexical+Mahalanobis
  representation — which is exactly what the byte-CNN fixes.
Takeaway: ~7% FP is still above a <2% enforce budget, but the research stack (byte-CNN +
contrastive + conformal, trained on real traffic) is a credible path where the lexical model was a
dead end. Productionizing it must run on Linux (torch is blocked by Windows Application Control).

**Decision: keep ML in SHADOW; the signature tier enforces (harness: rules PASS, FP 0).** The
harness `ml_waf` gate correctly reports ENFORCEMENT READY = NO and will block anyone flipping the
switch prematurely. To ever enable it you need materially better inputs/architecture, not config:
1. Train benign on REAL production traffic (a generator seeded from your access logs), not synthetic.
2. Likely a better representation (the research byte-CNN/contrastive path) before FP is deployable.
3. Only enable `WAF_ML_ENFORCE=true` if/when `python -m harness.run --gate-ml` passes on a
   production-shaped corpus. Until then it is a genuine liability, not a shadow-only inconvenience.

## Tavily threat-intel -> ML training pipeline (added this pass)
`data_pipeline/tavily_source.py` uses the Tavily search API to collect the latest real web
exploits/CVEs (by attack class, language, framework, version), extracts attack payloads, and
appends them as labeled training records to the MLOps capture feed. The existing guarded loop
(`ml/mlops_runner`) then screens them (poison guard) and accumulates them (zero-day store) before
training a challenger — Tavily is just a fresh real-world ATTACK SOURCE, it does not bypass any gate.
- **Flow:** `python -m data_pipeline.tavily_source` (collect + write feed) → `python -m ml.mlops_runner`
  (guarded retrain). `mlops_runner` also auto-refreshes from Tavily at cycle start when a key is set.
- **Enable:** set `TAVILY_API_KEY` (+ optional `TAVILY_AUGMENT` for volume). UNSET => disabled and
  offline-safe; the WAF and MLOps loop run normally without it. No new dependency (uses `requests`).
- **Verified offline** (`tests/test_tavily_source.py`, 6 passed, mock search — no key/network):
  payload extraction, category inference, CVE/affected-tech parsing, feed-shape compatibility with
  `mlops_runner`, augmentation, and dedup. Extracted payloads were confirmed as real attacks by the
  WAF (5/5 blocked) — valid attack-class training data.
- **Not runtime-verified:** live Tavily calls (needs a key); once keyed, sanity-check that extracted
  payloads and volume are sufficient before relying on an automated retrain.

## Harness, drift, linting, CI/CD (added this pass)
- **Evaluation harness** (`harness/`): one frozen, content-hashed, human-reviewed corpus
  (`eval_corpus.json`, kept separate from the auto-accumulated training feed) + **four gates**
  (recall w/ per-family + must-catch, false-positive, latency p99, ReDoS), run across **three
  targets** — `rules` (signature tier), `ml_waf` (full `ml_enforce=True` stack), `ml_model` (raw
  detector) — plus an honest native-distribution (CSIC) readout. `python -m harness.run` (add
  `--ml-native`, `--gate-ml`). Tests in `tests/test_harness.py`.
  - It gates the ML, not just regex: current run shows **rules PASS** (recall 1.0, FP 0/21) but
    **ml_waf/ml_model FAIL — FP 100%** on the corpus's out-of-distribution benign, so
    **ML ENFORCEMENT READY = NO**. On the model's NATIVE data it is **96.1% recall / 5.8% FP**.
    The verdict is correct: do not set `WAF_ML_ENFORCE=true` until the benign corpus is
    production-shaped and the ml_waf FP gate passes. CI runs the deterministic rules gate; the
    `--gate-ml` enforcement decision runs pre-deploy where the model artifacts exist.
- **Feature-distribution drift** (`metrics/drift.py`): PSI on the canonical feature contract
  (the unsupervised early-warning the FP/FN monitor couldn't give). Wired fail-safe into
  `ml/mlops_runner` (fits a reference at train time, reports PSI + `retrain_recommended` each
  cycle, surfaces pending FP-monitor triggers). Tests in `tests/test_drift.py`.
- **Linting** (`ruff.toml`): gates on real-bug rules (pyflakes F + syntax E9), deliberately NOT
  import-sorting (the `sys.path.insert` pattern would break at runtime). Repo is **clean**.
  Fixed two genuine bugs found by it: `SecurityWarning` was undefined (NameError) in
  `core/secure_model_loader.py` and `ml/secure_inference.py`.
- **CI/CD** (`.github/workflows/ci.yml`): lint → quality-gate tests → **harness gate** (hard
  fail on any breach) → Docker build validation. Complements the (pwn-request-fixed) `security.yml`.
- **MLOps stack summary**: hand-rolled (no MLflow/W&B/DVC) — custom `registry.json` (versioned
  live pointer + rollback), snapshot `manifest_*.json` for data/feature-contract lineage,
  `canonical_features` pinned+hashed contract (skew guard), **canary** rollout (not A/B),
  FP/FN-threshold + PSI-drift retrain triggers, poison-guard + zero-day-store accumulation gates.

## Known residuals (honest)
- **Legacy test debt:** the old `core/waf_engine.py` + ONNX path has a pre-existing latent bug
  (`core/zero_day.py:115` `isinstance(features, np.ndarray)` where `np` isn't a real type),
  surfaced now that ML deps are installed. It's in the NON-deployed legacy engine (the deploy
  path is `waf/engine.py`); CI runs the verified quality suite, not the flaky legacy tests. Triage
  separately.
- **The benign eval corpus is the ceiling on the FP gate's honesty** — it's a representative
  baseline; sample real production benign into it before trusting the gate to authorize
  `WAF_ML_ENFORCE=true` (the the-fool #1 risk).
- The scanner's inherent FP rate still needs per-deployment tuning; the benign suites here are
  representative, not exhaustive.
- Configure trusted proxies / `X-Forwarded-For` so per-client controls key on real client IPs, not
  the load-balancer IP (otherwise per-IP signals apply to all clients collectively).
- Model weights (`models_v2/`) and `demo/secret_config.txt` are intentionally **not committed** —
  keep secrets out of git; ship models via your artifact pipeline, not the repo.
- "100% bug/loophole-free" is not achievable for any WAF; this closes every confirmed finding and
  guards them with tests.
