"""
detector_v2 — the serving side of the fixed ML pipeline.

Imports the SAME ml.canonical_features used by ml/train_v2.py, loads the scaler +
classifier + isolation-forest + calibrated thresholds from models_v2/, and returns a
decision. Because the feature code is shared and the scaler is loaded and applied,
training/serving skew is structurally impossible here (unlike the old paths).

Two detection routes, mirroring the research design:
  - closed-set: gradient-boosted classifier -> P(malicious) = 1 - P(benign)
  - open-set  : Mahalanobis novelty (energy-style OOD) escalates rare anomalies
                the classifier under-scores -> this is the zero-day route.

The two routes are ORed and the novelty route is INDEPENDENT of the classifier score:
a safety net that the thing it backstops can switch off is not a safety net (an
adversary who drives P(malicious) down would otherwise blind both routes at once).

Enforcement contract (what the engine may act on):
  - `MLResult.is_malicious` -> detection. Always safe to log/shadow.
  - `MLResult.enforce`      -> "confident enough to BLOCK". True only when
                               (a) the train/serve feature contract is VERIFIED, and
                               (b) the verdict clears a high-confidence threshold
                                   (`enforce_threshold`, default 0.90 for the
                                   classifier; `novelty_enforce_threshold` for the
                                   open-set route).
  An enforcing engine must gate blocking on `enforce`, not on `is_malicious`, and
  shadow-log everything else. `enforce` is False whenever the contract hash of the
  served model is unknown or unverifiable — skewed features never enforce.
"""
from __future__ import annotations
import hashlib, json, logging, os, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features, LEXICAL_FEATURE_NAMES

_DIR = Path(__file__).resolve().parent.parent / "models_v2"

logger = logging.getLogger("mirage.ml.detector_v2")

# High-confidence gate for ENFORCEMENT (blocking), deliberately well above the
# detection threshold `mal_t`. Detection at 0.5 with a ~5% FP rate is fine to
# shadow-log and unacceptable to block on; this is the knob that separates them.
# Override per deployment via meta["enforce_threshold"] or $WAF_ML_ENFORCE_THRESHOLD.
DEFAULT_ENFORCE_THRESHOLD = 0.90
# Novelty margin required to enforce, as a multiple of the detection threshold
# `nov_t`. Override via meta["novelty_enforce_threshold"] /
# $WAF_ML_NOVELTY_ENFORCE_THRESHOLD (absolute Mahalanobis distance, not a multiple).
DEFAULT_NOVELTY_ENFORCE_MULT = 1.5


def serving_contract_hash() -> str:
    """SHA-256 (16 hex) of the ordered serving feature contract.

    Must equal the hash the trainer stored in the model's meta artifact. One
    function so train-side and serve-side can never compute it differently."""
    return hashlib.sha256(",".join(LEXICAL_FEATURE_NAMES).encode()).hexdigest()[:16]


def _env_float(name: str) -> Optional[float]:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        logger.warning("ignoring non-numeric %s=%r", name, raw)
        return None


@dataclass
class MLResult:
    is_malicious: bool
    mal_prob: float
    novelty: float
    category: str
    is_zero_day: bool          # caught by novelty route while classifier under-scored
    route: str                 # "classifier" | "novelty" | "none"
    # --- enforcement contract (added; defaulted so existing callers keep working) ---
    enforce: bool = False      # True == confident enough to BLOCK on. Gate blocks on THIS.
    enforce_reason: str = ""   # why enforce is/isn't set — for shadow-log triage
    contract_verified: bool = False   # train/serve feature contract proven identical
    model_version: str = ""    # which model produced this verdict


class DetectorV2:
    @staticmethod
    def _resolve(models_dir: Path):
        """One source of truth for WHICH model serves.
        Priority: registry 'live' pointer -> real-data CSIC model -> synthetic fallback.
        Serving the synthetic model silently (the old behaviour) was an audit failure."""
        reg = models_dir / "registry.json"
        if reg.exists():
            try:
                r = json.loads(reg.read_text())
                live = r.get("live")
                arts = (r.get("versions", {}).get(live) or {}).get("artifacts", {})
                clf = arts.get("clf")
                if clf and (models_dir / clf).exists():
                    return {"kind": "registry", "version": live, "clf": clf,
                            "scaler": arts.get("scaler", "csic_scaler.joblib"),
                            "maha": arts.get("maha", "csic_maha.npz"),
                            "meta": arts.get("meta", "csic_meta.json")}
            except Exception:
                pass
        if (models_dir / "csic_classifier.json").exists():
            return {"kind": "real-data (CSIC-2010)", "version": "csic", "clf": "csic_classifier.json",
                    "scaler": "csic_scaler.joblib", "maha": "csic_maha.npz", "meta": "csic_meta.json"}
        return {"kind": "SYNTHETIC (fallback — calibrate on real traffic!)", "version": "synthetic",
                "clf": "classifier.json", "scaler": "scaler.joblib", "maha": "maha.npz", "meta": "meta.json"}

    def __init__(self, models_dir: Path = _DIR):
        import joblib, xgboost as xgb
        sel = self._resolve(models_dir)
        self.model_kind, self.model_version = sel["kind"], sel["version"]
        if sel["version"] != "synthetic":
            return self._init_from(models_dir, sel)
        meta = json.loads((models_dir / "meta.json").read_text())
        self.class_names = meta["class_names"]
        self.mal_t = float(meta.get("malicious_threshold", 0.5))
        self.nov_t = float(meta.get("novelty_threshold", 0.5))
        self.contract_hash = meta.get("contract_hash")
        self.scaler = joblib.load(models_dir / "scaler.joblib")
        m = np.load(models_dir / "maha.npz")
        self.maha_mu = m["mu"].astype(np.float32)
        self.maha_prec = m["prec"].astype(np.float32)
        _clf = xgb.XGBClassifier()
        _clf.load_model(str(models_dir / "classifier.json"))
        self.booster = _clf.get_booster()   # inplace_predict is ~faster than sklearn wrapper
        # sanity: fail loud if the serving feature contract drifted from training
        self._verify_contract(self.contract_hash, "models_v2/meta.json")
        self._init_enforcement(meta)
        self.loaded = True

    def _init_from(self, models_dir: Path, sel: dict):
        """Load a real-data / registry-selected model (binary classifier + Mahalanobis novelty)."""
        import joblib, xgboost as xgb
        self.scaler = joblib.load(models_dir / sel["scaler"])
        m = np.load(models_dir / sel["maha"])
        self.maha_mu = m["mu"].astype(np.float32)
        self.maha_prec = m["prec"].astype(np.float32)
        # The registry/real-data path used to hardcode its thresholds and set
        # contract_hash=None, which silently DISABLED the skew guard on the model
        # that actually serves. Read the meta artifact here too, and run the same
        # guard as the synthetic path.
        meta_name = sel.get("meta") or ""
        meta: Dict = {}
        if meta_name:
            meta_path = models_dir / meta_name
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                except Exception as e:          # corrupt meta == unknown contract
                    logger.error("unreadable model meta %s: %s", meta_path, e)
                    meta = {}
            else:
                logger.error("model meta %s missing — feature contract unknown", meta_path)
        self.nov_t = float(m["nov_t"]) if "nov_t" in m else float(meta.get("novelty_threshold", 10.0))
        _clf = xgb.XGBClassifier(); _clf.load_model(str(models_dir / sel["clf"]))
        self.booster = _clf.get_booster()
        self.binary = True                      # binary model: P(attack) is column 1
        self.class_names = ["benign", "attack"]
        self.mal_t = float(meta.get("malicious_threshold", 0.5))
        self.contract_hash = meta.get("contract_hash")
        self._verify_contract(self.contract_hash, meta_name or "<no meta artifact>")
        self._init_enforcement(meta)
        self.loaded = True

    # ------------------------------------------------------------------ guards
    def _verify_contract(self, trained_hash: Optional[str], source: str) -> None:
        """Train/serve skew guard — FAIL CLOSED.

        mismatch -> refuse to load at all (serving skewed features is the documented
                    recall-collapse failure; there is no safe degraded mode).
        unknown  -> load, but mark the model UNVERIFIED: `enforce` is then False for
                    every verdict, so the model can only shadow-log. An unknown
                    contract must never be treated as a calibrated one."""
        live = serving_contract_hash()
        self.serving_contract = live
        if trained_hash and trained_hash != live:
            raise RuntimeError(
                f"FEATURE CONTRACT MISMATCH: serving={live} trained={trained_hash} "
                f"(from {source}). Retrain (ml/train_v2.py) — do not serve skewed features.")
        self.contract_verified = bool(trained_hash) and trained_hash == live
        if not self.contract_verified:
            logger.critical(
                "ML TRAIN/SERVE SKEW GUARD UNSATISFIED: model '%s' declares no contract_hash "
                "in %s (serving contract=%s). Detector will DETECT but NOT ENFORCE "
                "(MLResult.enforce=False on every verdict). Re-train and persist "
                "contract_hash to enable enforcement.", self.model_version, source, live)

    def _init_enforcement(self, meta: Dict) -> None:
        """Resolve the high-confidence ENFORCEMENT thresholds (env > meta > default)."""
        t = _env_float("WAF_ML_ENFORCE_THRESHOLD")
        if t is None:
            try:
                t = float(meta.get("enforce_threshold", DEFAULT_ENFORCE_THRESHOLD))
            except (TypeError, ValueError):
                t = DEFAULT_ENFORCE_THRESHOLD
        # enforcement can never be looser than detection
        self.enforce_threshold = min(1.0, max(t, self.mal_t))

        n = _env_float("WAF_ML_NOVELTY_ENFORCE_THRESHOLD")
        if n is None:
            try:
                n = float(meta.get("novelty_enforce_threshold",
                                   self.nov_t * DEFAULT_NOVELTY_ENFORCE_MULT))
            except (TypeError, ValueError):
                n = self.nov_t * DEFAULT_NOVELTY_ENFORCE_MULT
        self.novelty_enforce_threshold = max(n, self.nov_t)

    def _enforce_decision(self, clf_hit: bool, nov_hit: bool,
                          mal_prob: float, novelty: float):
        """Is this verdict confident enough for the engine to BLOCK on?"""
        if not (clf_hit or nov_hit):
            return False, "benign"
        if not self.contract_verified:
            return False, "contract unverified — shadow only"
        if clf_hit and mal_prob >= self.enforce_threshold:
            return True, f"classifier {mal_prob:.3f} >= {self.enforce_threshold:.3f}"
        if nov_hit and novelty >= self.novelty_enforce_threshold:
            return True, f"novelty {novelty:.3f} >= {self.novelty_enforce_threshold:.3f}"
        return False, "below enforcement threshold — shadow only"

    def predict(self, method: str = "GET", path: str = "", query: str = "",
                body: str = "", headers: Optional[Dict[str, str]] = None) -> MLResult:
        xf = self.scaler.transform(
            lexical_features(method, path, query, body, headers).reshape(1, -1)).astype(np.float32)
        raw = np.asarray(self.booster.inplace_predict(xf)).reshape(-1)
        if getattr(self, "binary", False):
            # binary model: inplace_predict returns P(attack) as a single value
            mal_prob = float(raw[-1] if raw.size > 1 else raw[0])
            top = "attack" if mal_prob >= self.mal_t else "benign"
        else:
            mal_prob = float(1.0 - raw[0])
            top = self.class_names[int(np.argmax(raw))]
        d = xf[0] - self.maha_mu
        novelty = float(np.sqrt(max(0.0, d @ self.maha_prec @ d)))

        clf_hit = mal_prob >= self.mal_t
        # Open-set route is INDEPENDENT of the classifier. It previously also
        # required `mal_prob >= self.mal_t * 0.6`, which let an adversary who drove
        # the classifier score down disable the novelty net that exists to catch
        # exactly that case. The two routes are ORed, never ANDed.
        nov_hit = novelty >= self.nov_t
        is_mal = clf_hit or nov_hit
        route = "classifier" if clf_hit else ("novelty" if nov_hit else "none")
        is_zero_day = nov_hit and not clf_hit
        cat = top if top != "benign" else ("ANOMALY_ZERO_DAY" if is_zero_day else "benign")
        enforce, why = self._enforce_decision(clf_hit, nov_hit, mal_prob, novelty)
        return MLResult(is_malicious=is_mal, mal_prob=round(mal_prob, 3),
                        novelty=round(novelty, 3), category=cat,
                        is_zero_day=is_zero_day, route=route,
                        enforce=enforce, enforce_reason=why,
                        contract_verified=self.contract_verified,
                        model_version=getattr(self, "model_version", ""))


# lazy singleton
_detector: Optional[DetectorV2] = None


def get_detector():
    """Return the live detector. WAF_ML_MODEL selects which one:
      bytecnn — the research byte-CNN serving model (needs torch)
      gcid    — grammar-conformance injection detection (ml/gcid.py; pure sklearn, no torch)
    On any failure (missing torch/artifacts) we fall back to the XGBoost DetectorV2, so the WAF
    never fails to start over a model choice."""
    global _detector
    if _detector is None:
        choice = os.environ.get("WAF_ML_MODEL", "").strip().lower()
        if choice == "bytecnn":
            try:
                from ml.bytecnn_detector import ByteCNNDetector
                _detector = ByteCNNDetector()
            except Exception as e:
                logger.warning("byte-CNN model unavailable (%s) — falling back to XGBoost detector", e)
                _detector = DetectorV2()
        elif choice == "gcid":
            try:
                from ml.gcid import GcidDetector
                _detector = GcidDetector()
            except Exception as e:
                logger.warning("GCID model unavailable (%s) — falling back to XGBoost detector", e)
                _detector = DetectorV2()
        else:
            _detector = DetectorV2()
    return _detector
