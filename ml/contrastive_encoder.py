"""
Evasion-invariant contrastive byte-encoder — the novel component.

Trains a byte-level CNN encoder so that a payload and its semantics-preserving
mutations (from ml/adaptive_attacker's operator set) map to nearly the same
embedding (NT-Xent contrastive loss), while a classifier head stays discriminative
(cross-entropy). The hypothesis: mutation-invariance makes the model harder for an
adaptive attacker to evade, because the directions the attacker searches over are
exactly the ones the embedding is trained to ignore.

Two training modes for the ablation:
  mode="baseline"     -> classification only (lambda_con = 0)   [non-invariant]
  mode="contrastive"  -> classification + NT-Xent invariance    [invariant]

Both expose .score(method, path, query, body) -> malicious probability, so the
same adaptive attacker can be run against either.
"""
from __future__ import annotations
import os, sys, random
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.canonical_features import byte_sequence, SEQ_LEN
from ml.adaptive_attacker import mutate

torch.manual_seed(7); np.random.seed(7); random.seed(7)


class ByteEncoder(nn.Module):
    def __init__(self, n_classes, vocab=257, embed=24, proj=64, seq_len=SEQ_LEN):
        super().__init__()
        self.emb = nn.Embedding(vocab, embed, padding_idx=0)
        self.branches = nn.ModuleList([
            nn.Sequential(nn.Conv1d(embed, 48, k, padding=k // 2), nn.ReLU(), nn.AdaptiveMaxPool1d(1))
            for k in (3, 5, 7)])
        self.repr_dim = 48 * 3
        self.proj = nn.Sequential(nn.Linear(self.repr_dim, 96), nn.ReLU(), nn.Linear(96, proj))
        self.clf = nn.Sequential(nn.Linear(self.repr_dim, 96), nn.ReLU(), nn.Dropout(0.3),
                                 nn.Linear(96, n_classes))

    def encode(self, x):
        e = self.emb(x).transpose(1, 2)
        return torch.cat([b(e).squeeze(-1) for b in self.branches], dim=1)  # (B, repr_dim)

    def forward(self, x):
        h = self.encode(x)
        return self.clf(h), F.normalize(self.proj(h), dim=1), h


def nt_xent(z1, z2, temp=0.2):
    """NT-Xent over 2 views. z1,z2: (B, d) normalized. Positives are matched rows."""
    B = z1.size(0)
    z = torch.cat([z1, z2], 0)                       # (2B, d)
    sim = z @ z.t() / temp                            # (2B, 2B)
    sim.fill_diagonal_(-1e9)
    targets = torch.arange(B, device=z.device)
    targets = torch.cat([targets + B, targets], 0)    # positive index for each row
    return F.cross_entropy(sim, targets)


def _to_bytes(strings):
    return torch.tensor(np.array([byte_sequence("GET", "/search", f"id={s}", "", {}) for s in strings]),
                        dtype=torch.long)


def train_encoder(records, class_names, mode="contrastive", epochs=10,
                  lambda_con=1.0, bs=128, lr=1e-3, mutation_ops=None):
    """records: list of (payload_string, label_id). label 0 == benign."""
    strings = [r[0] for r in records]
    y = torch.tensor([r[1] for r in records], dtype=torch.long)
    net = ByteEncoder(len(class_names))
    opt = torch.optim.Adam(net.parameters(), lr=lr, weight_decay=1e-4)
    counts = np.bincount(y.numpy(), minlength=len(class_names)).astype(float)
    w = torch.tensor((counts.sum() / (counts + 1)) ** 0.5, dtype=torch.float32)
    ce = nn.CrossEntropyLoss(weight=w)
    net.train()
    idx_all = np.arange(len(strings))
    for ep in range(epochs):
        np.random.shuffle(idx_all)
        tot = 0.0
        for i in range(0, len(idx_all), bs):
            bidx = idx_all[i:i + bs]
            batch = [strings[j] for j in bidx]
            yb = y[bidx]
            x1 = _to_bytes(batch)
            logits, z1, _ = net(x1)
            loss = ce(logits, yb)
            if mode == "contrastive" and lambda_con > 0:
                # positive view = a semantics-preserving mutation of each payload
                view2 = [mutate(s, k=random.randint(1, 3), ops=mutation_ops) for s in batch]
                _, z2, _ = net(_to_bytes(view2))
                loss = loss + lambda_con * nt_xent(z1, z2)
            opt.zero_grad(); loss.backward(); opt.step()
            tot += loss.item() * len(bidx)
        if ep % 3 == 0 or ep == epochs - 1:
            print(f"    [{mode}] epoch {ep:2d} loss={tot/len(strings):.4f}")
    net.eval()
    return net


class EncoderScorer:
    """Wraps a trained ByteEncoder to expose mal_prob for a raw payload string."""
    def __init__(self, net):
        self.net = net
    @torch.no_grad()
    def score(self, payload: str) -> float:
        x = _to_bytes([payload])
        logits, _, _ = self.net(x)
        p = F.softmax(logits, 1)[0]
        return float(1.0 - p[0])   # 1 - P(benign)
    @torch.no_grad()
    def embed(self, payloads):
        x = _to_bytes(payloads)
        _, _, h = self.net(x)
        return h.numpy()
