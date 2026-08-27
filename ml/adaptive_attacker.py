"""
Adaptive black-box attacker — the "hard" evasion the red-team demanded.

Naive encoding/comment mutations do NOT fool the detector (measured: they raise the
entropy/keyword signals the model keys on). The dangerous class is SIGNAL-REDUCING,
semantics-preserving rewrites (AdvSQLi / WAF-A-MoLE style). This module implements:

  1. A library of semantics-preserving mutation operators (SQLi-focused, plus XSS and
     generic dilution). Each is equivalence-preserving BY CONSTRUCTION (we do not
     execute payloads, so semantic preservation is an operator guarantee, not a
     dynamic check — honest caveat).
  2. A guided black-box search (greedy hill-climb + restarts, WAF-A-MoLE-style) that
     queries a detector's malicious probability and searches for a variant that drops
     below the block threshold while staying a valid attack.

Attacks any detector exposing `score(method, path, query, body) -> float in [0,1]`.
Used to compute Attack Success Rate (ASR) for the invariant-vs-non-invariant ablation.
"""
from __future__ import annotations
import random, re
from dataclasses import dataclass
from typing import Callable, List, Tuple

random.seed(1337)

# ---- semantics-preserving mutation operators --------------------------------
def _ws(s):  # swap spaces for equivalent whitespace/comment tokens
    reps = ["/**/", "%20", "\t", "\n", "+", "  ", "/*x*/"]
    return re.sub(r" ", lambda _: random.choice(reps), s, count=random.randint(1, max(1, s.count(" "))))

def _case(s):  # random-case SQL/HTML keywords (SQL is case-insensitive)
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)

def _versioned_comment(s):  # MySQL /*!...*/ executes but obfuscates keywords
    for kw in ("UNION", "SELECT", "OR", "AND", "WHERE", "FROM"):
        if kw.lower() in s.lower() and random.random() < 0.5:
            s = re.sub(kw, f"/*!{kw}*/", s, flags=re.I, count=1)
    return s

def _equiv_predicate(s):  # OR 1=1  ->  equivalent always-true predicates
    variants = ["OR 1=1", "OR '1'='1'", "OR 2>1", "OR 'a'='a'", "OR 7=7", "OR true", "OR 1 LIKE 1"]
    for v in variants:
        if v.lower() in s.lower():
            return re.sub(re.escape(v), random.choice(variants), s, flags=re.I, count=1)
    return s

def _inline_pad(s):  # dilute char/keyword ratios with benign-looking padding
    pads = ["q=search", "lang=en", "utm=news", "id=42", "page=1", "ref=home", "name=john"]
    p = random.choice(pads)
    return f"{p}&{s}" if random.random() < 0.5 else f"{s}&{p}"

def _hex_string(s):  # 'admin' -> 0x61646d696e (MySQL) / CHAR(...) equivalents
    m = re.search(r"'([A-Za-z]{2,12})'", s)
    if m:
        w = m.group(1)
        if random.random() < 0.5:
            return s.replace(m.group(0), "0x" + w.encode().hex())
        return s.replace(m.group(0), "CHAR(" + ",".join(str(ord(c)) for c in w) + ")")
    return s

def _comment_terminator(s):  # -- / # / -- - / /*...  equivalents
    return re.sub(r"--(\s|$)", random.choice(["#", "-- -", "--\t", ";%00"]), s)

def _paren_nest(s):
    return re.sub(r"=1\b", "=(1)", s) if random.random() < 0.5 else s

def _tag_case_xss(s):  # XSS: tag/attr case + event swap
    if "<script" in s.lower():
        s = re.sub(r"<script", random.choice(["<ScRiPt", "<SCRIPT", "<script "]), s, flags=re.I)
    s = re.sub(r"onerror", random.choice(["OnErRor", "onerror ", "ONERROR"]), s, flags=re.I)
    return s

OPERATORS = [_ws, _case, _versioned_comment, _equiv_predicate, _inline_pad,
             _hex_string, _comment_terminator, _paren_nest, _tag_case_xss]

# Disjoint operator grammars for the out-of-grammar transfer test (red-team objection #1).
# TRAIN  = surface/encoding tricks (case, whitespace, comment styles).
# HELDOUT= structural/semantic rewrites the model never saw — incl. benign-dilution and
#          logic-equivalent predicate substitution, the signal-REDUCING class that actually
#          drove evasion earlier. A fair transfer test: train invariance on TRAIN only,
#          attack with HELDOUT only.
TRAIN_OPS = [_ws, _case, _versioned_comment, _comment_terminator, _tag_case_xss]
HELDOUT_OPS = [_equiv_predicate, _inline_pad, _hex_string, _paren_nest]


def mutate(payload: str, k: int = 1, ops=None) -> str:
    ops = ops or OPERATORS
    out = payload
    for _ in range(k):
        op = random.choice(ops)
        try:
            nxt = op(out)
            if nxt:
                out = nxt
        except Exception:
            pass
    return out


@dataclass
class AttackResult:
    original: str
    evaded_payload: str
    orig_score: float
    final_score: float
    queries: int
    evaded: bool


def attack(payload: str, score_fn: Callable[[str], float],
           block_threshold: float = 0.5, budget: int = 60,
           restarts: int = 3, ops=None) -> AttackResult:
    """
    WAF-A-MoLE-style guided search: minimise score_fn(payload) via semantics-preserving
    mutations from `ops` (default: full grammar). score_fn takes the (possibly-mutated)
    payload STRING and returns mal_prob.
    """
    orig = score_fn(payload)
    best, best_s = payload, orig
    queries = 1
    for _ in range(restarts):
        cur, cur_s = payload, orig
        stall = 0
        for _ in range(budget // restarts):
            cand = mutate(cur, k=random.randint(1, 3), ops=ops)
            s = score_fn(cand); queries += 1
            if s < cur_s:            # greedy accept improvement
                cur, cur_s = cand, s
                stall = 0
            else:
                stall += 1
            if s < best_s:
                best, best_s = cand, s
            if best_s < block_threshold:
                break
            if stall > 8:            # restart from a fresh random mutation
                cur = mutate(payload, k=random.randint(2, 4), ops=ops); cur_s = score_fn(cur); queries += 1
        if best_s < block_threshold:
            break
    return AttackResult(payload, best, orig, best_s, queries, best_s < block_threshold)


def attack_success_rate(payloads: List[str], score_fn, **kw) -> Tuple[float, float, list]:
    """Returns (ASR, avg_queries, per-payload results)."""
    res = [attack(p, score_fn, **kw) for p in payloads]
    asr = sum(r.evaded for r in res) / len(res) if res else 0.0
    q = sum(r.queries for r in res) / len(res) if res else 0.0
    return asr, q, res
