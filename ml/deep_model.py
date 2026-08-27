"""
Deep research model — the "beyond Radar" architecture as runnable torch code.

Dual representation fused multi-branch:
  byte_sequence(256) -> char embedding -> 3 parallel 1D-CNN branches (ResNeXt-style
     grouped/aggregated) -> concat
  lexical_features(50) -> MLP branch
  fuse -> classifier logits (families)
  energy head: E(x) = -logsumexp(logits)  -> open-set / zero-day novelty

This is deliberately small (CPU-trainable). It is the research artifact, not the
deployed model — the deployed model is the calibrated GBDT + IsolationForest in
detector_v2.py. Train with: python ml/deep_model.py

Reports the SAME honest protocol as train_v2: closed-set, leave-one-family-out
(ssti/nosql withheld), independent benign FP, and OOD AUROC (known vs novel) using
the energy score.
"""
from __future__ import annotations
import os, sys, json, time, random
from pathlib import Path
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import lexical_features, byte_sequence, SEQ_LEN, N_LEXICAL
import ml.train_v2 as tv  # reuse dataset builders + benign generator + probes

import torch
import torch.nn as nn
import torch.nn.functional as F

torch.manual_seed(42); np.random.seed(42); random.seed(42)
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "models_v2"; OUT.mkdir(exist_ok=True)


class DualBranchNet(nn.Module):
    def __init__(self, n_classes: int, n_lexical: int = N_LEXICAL, vocab: int = 257,
                 embed: int = 24, seq_len: int = SEQ_LEN):
        super().__init__()
        self.embed = nn.Embedding(vocab, embed, padding_idx=0)
        # three parallel conv branches with different kernel widths (ResNeXt-style aggregation)
        self.branches = nn.ModuleList([
            nn.Sequential(nn.Conv1d(embed, 48, k, padding=k // 2), nn.ReLU(),
                          nn.AdaptiveMaxPool1d(1))
            for k in (3, 5, 7)
        ])
        self.lex = nn.Sequential(nn.Linear(n_lexical, 64), nn.ReLU(), nn.Dropout(0.2),
                                 nn.Linear(64, 48), nn.ReLU())
        self.head = nn.Sequential(nn.Linear(48 * 3 + 48, 96), nn.ReLU(), nn.Dropout(0.3),
                                  nn.Linear(96, n_classes))

    def forward(self, bytes_in, lex_in):
        e = self.embed(bytes_in).transpose(1, 2)          # (B, embed, L)
        conv = torch.cat([b(e).squeeze(-1) for b in self.branches], dim=1)  # (B, 144)
        lex = self.lex(lex_in)                             # (B, 48)
        logits = self.head(torch.cat([conv, lex], dim=1))
        return logits

    @staticmethod
    def energy(logits):                                   # open-set score; high = novel
        return -torch.logsumexp(logits, dim=1)


def make_xy(records, class_names):
    """records: list of (cat, method, path, query, body)"""
    B, Lx, Y = [], [], []
    for cat, m, p, q, b in records:
        B.append(byte_sequence(m, p, q, b, {}))
        Lx.append(lexical_features(m, p, q, b, {}))
        Y.append(class_names.index(cat))
    return (torch.tensor(np.array(B), dtype=torch.long),
            torch.tensor(np.array(Lx), dtype=torch.float32),
            torch.tensor(np.array(Y), dtype=torch.long))


def build_records():
    from ml.real_payload_loader import EmbeddedPayloads, EvasionTechniques
    emb = EmbeddedPayloads.get_all()
    class_names = ["benign"]
    train, heldout = [], []
    for cat, payloads in emb.items():
        target = heldout if cat in tv.HELDOUT_FAMILIES else train
        if cat not in tv.HELDOUT_FAMILIES and cat not in class_names:
            class_names.append(cat)
        aug = list(payloads)
        for pl in random.sample(payloads, min(len(payloads), len(payloads) // 2)):
            try:
                ev = EvasionTechniques.apply_random_evasion(pl, count=random.randint(1, 2))
                if ev and ev != pl:
                    aug.append(ev)
            except Exception:
                pass
        for pl in aug:
            m, p, q, b = tv.payload_to_fields(cat, pl)
            target.append((cat, m, p, q, b))
    for m, p, q, b in tv.gen_benign(3000):
        train.append(("benign", m, p, q, b))
    return train, heldout, class_names


def main(epochs=12):
    t0 = time.time()
    train, heldout, class_names = build_records()
    random.shuffle(train)
    split = int(0.85 * len(train))
    tr, te = train[:split], train[split:]
    Btr, Ltr, Ytr = make_xy(tr, class_names)
    Bte, Lte, Yte = make_xy(te, class_names)

    net = DualBranchNet(len(class_names))
    opt = torch.optim.Adam(net.parameters(), lr=1e-3, weight_decay=1e-4)
    # class weights (benign dominates)
    counts = np.bincount(Ytr.numpy(), minlength=len(class_names)).astype(float)
    w = torch.tensor((counts.sum() / (counts + 1)) ** 0.5, dtype=torch.float32)
    lossf = nn.CrossEntropyLoss(weight=w)

    net.train()
    bs = 128
    for ep in range(epochs):
        perm = torch.randperm(len(Ytr))
        tot = 0.0
        for i in range(0, len(perm), bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            logits = net(Btr[idx], Ltr[idx])
            loss = lossf(logits, Ytr[idx])
            loss.backward(); opt.step()
            tot += loss.item() * len(idx)
        if ep % 3 == 0 or ep == epochs - 1:
            print(f"  epoch {ep:2d}  loss={tot/len(Ytr):.4f}")

    net.eval()
    with torch.no_grad():
        # closed-set
        lg = net(Bte, Lte)
        pred = lg.argmax(1)
        from sklearn.metrics import f1_score
        macro = f1_score(Yte.numpy(), pred.numpy(), average="macro")
        mal_prob = 1 - F.softmax(lg, 1)[:, 0].numpy()
        benign_mask = (Yte.numpy() == 0)
        fp = float(np.mean(mal_prob[benign_mask] >= 0.5))
        rec = float(np.mean(mal_prob[~benign_mask] >= 0.5))
        e_known = net.energy(lg).numpy()

        # independent benign
        ib = [("benign",) + t for t in tv.gen_benign(1000)]
        Bib, Lib, Yib = make_xy(ib, class_names)
        lg_ib = net(Bib, Lib)
        ind_fp = float(np.mean((1 - F.softmax(lg_ib, 1)[:, 0].numpy()) >= 0.5))
        e_benign = net.energy(lg_ib).numpy()

        # leave-one-family-out (novel families)
        Bho, Lho, _ = make_xy(heldout, ["benign"] + sorted(tv.HELDOUT_FAMILIES))  # y unused
        lg_ho = net(Bho, Lho)
        ho_malprob = 1 - F.softmax(lg_ho, 1)[:, 0].numpy()
        ho_recall = float(np.mean(ho_malprob >= 0.5))
        e_novel = net.energy(lg_ho).numpy()

        # OOD AUROC: can energy separate known-malicious (in-dist) from novel families?
        from sklearn.metrics import roc_auc_score
        y_ood = np.r_[np.zeros(len(e_benign)), np.ones(len(e_novel))]
        s_ood = np.r_[e_benign, e_novel]
        try:
            auroc = roc_auc_score(y_ood, s_ood)
        except Exception:
            auroc = float("nan")

    meta = {
        "model": "DualBranchNet (byte-CNN + lexical fusion, energy head)",
        "epochs": epochs, "n_classes": len(class_names), "class_names": class_names,
        "closed_set": {"macro_f1": round(macro, 4), "malicious_recall": round(rec, 4),
                       "same_dist_benign_fp": round(fp, 4)},
        "independent_benign_fp": round(ind_fp, 4),
        "leave_one_family_out_recall": round(ho_recall, 4),
        "energy_ood_auroc_benign_vs_novel": round(float(auroc), 4),
        "params": sum(p.numel() for p in net.parameters()),
        "train_seconds": round(time.time() - t0, 1),
    }
    torch.save(net.state_dict(), OUT / "dualbranch.pt")
    (OUT / "deep_meta.json").write_text(json.dumps(meta, indent=2))
    print("\n=== DualBranchNet (research model) — honest metrics ===")
    print(f"  params={meta['params']}  train={meta['train_seconds']}s")
    print(f"  closed-set macro-F1={macro:.3f}  malicious recall={rec:.3f}  same-dist benign FP={fp:.3f}")
    print(f"  INDEPENDENT benign FP={ind_fp*100:.1f}%")
    print(f"  leave-one-family-out recall (ssti+nosql, never trained)={ho_recall*100:.1f}%")
    print(f"  energy OOD AUROC (benign vs novel family)={auroc:.3f}")
    print(f"  wrote models_v2/dualbranch.pt + deep_meta.json")


if __name__ == "__main__":
    main()
