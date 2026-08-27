"""
OUT-OF-GRAMMAR transfer test — the experiment that decides the thesis.

Red-team objection #1: invariance to a hand-picked mutation set gives no guarantee
against mutations outside it. So we test transfer honestly:

  - Contrastive model is trained with invariance to TRAIN_OPS only
    (surface/encoding: case, whitespace, comment styles).
  - It is then attacked with HELDOUT_OPS only
    (structural/semantic: benign-dilution, equivalent predicates, hex/CHAR, paren-nest)
    — the signal-REDUCING class it NEVER trained invariance to.

If contrastive ASR < baseline ASR even under the held-out attacker, invariance
TRANSFERS past the trained grammar (strong result). If not, the critic was right and
that negative result is the honest contribution. Either way we report it.

Also measures embedding invariance to held-out mutations (mechanism-level transfer).
"""
from __future__ import annotations
import os, sys, json, time, random
import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ml.train_v2 as tv
from ml.contrastive_encoder import train_encoder, EncoderScorer
from ml.adaptive_attacker import attack_success_rate, mutate, TRAIN_OPS, HELDOUT_OPS
from ml.experiment_evasion import build_records, embedding_invariance

random.seed(23); np.random.seed(23); torch.manual_seed(23)
OUT = tv.ROOT / "models_v2"


def main():
    t0 = time.time()
    train, test_attacks, class_names = build_records()
    atk = [pl for pl, _ in test_attacks][:35]
    print(f"[data] train={len(train)}  attacked payloads={len(atk)}")
    print(f"[grammar] TRAIN_OPS={[o.__name__ for o in TRAIN_OPS]}")
    print(f"[grammar] HELDOUT_OPS={[o.__name__ for o in HELDOUT_OPS]}  (attacker uses these; model never trained on them)")

    print("[train] baseline (no invariance)...")
    base = EncoderScorer(train_encoder(train, class_names, mode="baseline", epochs=10))
    print("[train] contrastive (invariance to TRAIN_OPS only)...")
    con = EncoderScorer(train_encoder(train, class_names, mode="contrastive", epochs=10,
                                      lambda_con=1.0, mutation_ops=TRAIN_OPS))

    # embedding invariance, measured separately for in-grammar vs out-of-grammar mutations
    inv = {
        "baseline_in":  embedding_invariance(base, atk, k=3),
        "contrast_in":  None, "baseline_out": None, "contrast_out": None,
    }
    # reuse embedding_invariance but with specific ops by monkeypatching mutate via wrapper
    def emb_inv(scorer, ops):
        sample = random.sample(atk, min(200, len(atk)))
        b = scorer.embed(sample); m = scorer.embed([mutate(p, k=3, ops=ops) for p in sample])
        b = b / (np.linalg.norm(b, axis=1, keepdims=True) + 1e-9)
        m = m / (np.linalg.norm(m, axis=1, keepdims=True) + 1e-9)
        return float(np.mean(1.0 - np.sum(b * m, axis=1)))
    inv = {
        "baseline_in":  emb_inv(base, TRAIN_OPS),  "contrast_in":  emb_inv(con, TRAIN_OPS),
        "baseline_out": emb_inv(base, HELDOUT_OPS), "contrast_out": emb_inv(con, HELDOUT_OPS),
    }

    print("[attack] in-grammar (TRAIN_OPS) and out-of-grammar (HELDOUT_OPS) vs both models...")
    b_in,  _, _ = attack_success_rate(atk, base.score, budget=45, ops=TRAIN_OPS)
    c_in,  _, _ = attack_success_rate(atk, con.score,  budget=45, ops=TRAIN_OPS)
    b_out, _, _ = attack_success_rate(atk, base.score, budget=45, ops=HELDOUT_OPS)
    c_out, _, _ = attack_success_rate(atk, con.score,  budget=45, ops=HELDOUT_OPS)

    res = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "train_ops": [o.__name__ for o in TRAIN_OPS],
        "heldout_ops": [o.__name__ for o in HELDOUT_OPS],
        "embedding_invariance": {k: round(v, 4) for k, v in inv.items()},
        "ASR": {"baseline_in_grammar": round(b_in, 3), "contrast_in_grammar": round(c_in, 3),
                "baseline_out_grammar": round(b_out, 3), "contrast_out_grammar": round(c_out, 3)},
        "train_seconds": round(time.time() - t0, 1),
    }
    (OUT / "transfer_experiment.json").write_text(json.dumps(res, indent=2))

    print("\n=== OUT-OF-GRAMMAR TRANSFER (honest) ===")
    print(f"{'attacker grammar':<20}{'baseline ASR':>14}{'contrastive ASR':>18}{'':>4}")
    print(f"{'in-grammar (train)':<20}{b_in:>14.3f}{c_in:>18.3f}   <- expected win")
    print(f"{'OUT-of-grammar':<20}{b_out:>14.3f}{c_out:>18.3f}   <- the real test")
    print(f"\nembedding invariance (lower=more invariant):")
    print(f"  in-grammar mutations : baseline {inv['baseline_in']:.4f} -> contrastive {inv['contrast_in']:.4f}")
    print(f"  OUT-grammar mutations: baseline {inv['baseline_out']:.4f} -> contrastive {inv['contrast_out']:.4f}")
    d_in, d_out = b_in - c_in, b_out - c_out
    print(f"\nASR reduction in-grammar = {d_in*100:+.0f} pts;  out-of-grammar = {d_out*100:+.0f} pts")
    if d_out > 0.03:
        print("VERDICT: invariance TRANSFERS past the trained grammar (thesis supported).")
    elif d_out > -0.03:
        print("VERDICT: NO meaningful out-of-grammar transfer (critic was right — honest negative).")
    else:
        print("VERDICT: contrastive is WORSE out-of-grammar (invariance overfit to trained ops).")
    print(f"({res['train_seconds']}s)  wrote models_v2/transfer_experiment.json")


if __name__ == "__main__":
    main()
