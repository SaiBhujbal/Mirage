"""
THE load-bearing experiment: does evasion-invariant contrastive training make a
byte-CNN detector harder for an adaptive attacker to evade?

Ablation (isolates the ONE novel term, as the red-team demanded):
  baseline    = byte-CNN, classification loss only        (non-invariant)
  contrastive = byte-CNN, classification + NT-Xent         (mutation-invariant)
Same architecture, same data, same attacker — only the invariance term differs.

Three measured outputs (honest, whatever they are):
  1. clean malicious-detection accuracy (sanity — invariance shouldn't wreck it)
  2. embedding invariance: mean cosine distance between a payload and its mutations
     (direct mechanism check — contrastive should be much smaller)
  3. adaptive-attacker Attack Success Rate (headline — contrastive should be lower)
"""
from __future__ import annotations
import os, sys, json, time, random
import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ml.train_v2 as tv
from ml.real_payload_loader import EmbeddedPayloads
from ml.contrastive_encoder import train_encoder, EncoderScorer
from ml.adaptive_attacker import attack_success_rate, mutate

random.seed(11); np.random.seed(11); torch.manual_seed(11)
OUT = tv.ROOT / "models_v2"

ATTACK_CATS = ["sqli", "xss", "rce", "path_traversal", "ssrf", "nosql", "ssti",
               "ldap", "xxe", "crlf", "open_redirect"]


def build_records():
    emb = EmbeddedPayloads.get_all()
    class_names = ["benign"] + ATTACK_CATS
    train, test_attacks = [], []
    for c in ATTACK_CATS:
        pls = list(emb.get(c, []))
        random.shuffle(pls)
        cut = max(1, int(0.8 * len(pls)))
        for pl in pls[:cut]:
            train.append((pl, class_names.index(c)))
        for pl in pls[cut:]:
            test_attacks.append((pl, c))
    for m, p, q, b in tv.gen_benign(2500):
        # represent benign as its query/body string for the byte encoder
        train.append((q or b or p, 0))
    random.shuffle(train)
    return train, test_attacks, class_names


def embedding_invariance(scorer, payloads, k=3, n=200):
    """Mean cosine distance between a payload embedding and its mutation embeddings."""
    sample = random.sample(payloads, min(n, len(payloads)))
    base = scorer.embed(sample)
    muts = scorer.embed([mutate(p, k=k) for p in sample])
    base = base / (np.linalg.norm(base, axis=1, keepdims=True) + 1e-9)
    muts = muts / (np.linalg.norm(muts, axis=1, keepdims=True) + 1e-9)
    cos = np.sum(base * muts, axis=1)
    return float(np.mean(1.0 - cos))   # lower = more invariant


def clean_accuracy(scorer, test_attacks, benign_strings, thr=0.5):
    tp = sum(1 for pl, _ in test_attacks if scorer.score(pl) >= thr)
    rec = tp / len(test_attacks)
    fp = sum(1 for s in benign_strings if scorer.score(s) >= thr)
    fpr = fp / len(benign_strings)
    return rec, fpr


def main():
    t0 = time.time()
    train, test_attacks, class_names = build_records()
    print(f"[data] train={len(train)}  held-out attacks={len(test_attacks)}  classes={len(class_names)}")

    print("[train] baseline (classification only)...")
    base_net = train_encoder(train, class_names, mode="baseline", epochs=10)
    print("[train] contrastive (classification + NT-Xent invariance)...")
    con_net = train_encoder(train, class_names, mode="contrastive", epochs=10, lambda_con=1.0)

    base, con = EncoderScorer(base_net), EncoderScorer(con_net)
    atk_payloads = [pl for pl, _ in test_attacks]
    benign_strings = [(q or b or p) for (m, p, q, b) in tv.gen_benign(400)]

    # 1. clean accuracy
    b_rec, b_fpr = clean_accuracy(base, test_attacks, benign_strings)
    c_rec, c_fpr = clean_accuracy(con, test_attacks, benign_strings)

    # 2. embedding invariance
    b_inv = embedding_invariance(base, atk_payloads)
    c_inv = embedding_invariance(con, atk_payloads)

    # 3. adaptive attacker ASR (attack a fixed subset for comparable cost)
    subset = atk_payloads[:35]
    print(f"[attack] running adaptive attacker on {len(subset)} payloads vs each model...")
    b_asr, b_q, _ = attack_success_rate(subset, base.score, block_threshold=0.5, budget=45)
    c_asr, c_q, _ = attack_success_rate(subset, con.score, block_threshold=0.5, budget=45)

    res = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "baseline": {"clean_recall": round(b_rec, 3), "clean_fpr": round(b_fpr, 3),
                     "embedding_mutation_distance": round(b_inv, 4),
                     "adaptive_ASR": round(b_asr, 3), "avg_queries": round(b_q, 1)},
        "contrastive": {"clean_recall": round(c_rec, 3), "clean_fpr": round(c_fpr, 3),
                        "embedding_mutation_distance": round(c_inv, 4),
                        "adaptive_ASR": round(c_asr, 3), "avg_queries": round(c_q, 1)},
        "attacker_budget": 45, "n_attacked": len(subset), "train_seconds": round(time.time() - t0, 1),
    }
    (OUT / "evasion_experiment.json").write_text(json.dumps(res, indent=2))
    torch.save(con_net.state_dict(), OUT / "contrastive_encoder.pt")

    print("\n=== EVASION ABLATION (honest, measured) ===")
    print(f"{'metric':<34}{'baseline':>12}{'contrastive':>14}")
    print(f"{'clean attack recall':<34}{b_rec:>12.3f}{c_rec:>14.3f}")
    print(f"{'clean benign FPR':<34}{b_fpr:>12.3f}{c_fpr:>14.3f}")
    print(f"{'embed dist(payload,mutation) [lower=inv]':<34}{b_inv:>12.4f}{c_inv:>14.4f}")
    print(f"{'adaptive attacker ASR [lower=robust]':<34}{b_asr:>12.3f}{c_asr:>14.3f}")
    verdict = ("contrastive MORE robust" if c_asr < b_asr - 0.02 else
               "no robustness gain" if c_asr <= b_asr + 0.02 else "contrastive WORSE")
    print(f"\n  invariance gain: embed dist {b_inv:.3f} -> {c_inv:.3f} "
          f"({'more invariant' if c_inv < b_inv else 'no gain'})")
    print(f"  robustness: ASR {b_asr*100:.0f}% -> {c_asr*100:.0f}%  => {verdict}")
    print(f"  ({res['train_seconds']}s)  wrote models_v2/evasion_experiment.json")


if __name__ == "__main__":
    main()
