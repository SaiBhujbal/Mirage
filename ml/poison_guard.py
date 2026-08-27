"""
Poison guard — screens the capture->retrain feed BEFORE any sample reaches training.

The capture loop (honeypot -> captured_zero_days.jsonl -> retrain) is an input channel an
attacker can abuse (threat model #10): flood it with mislabeled samples to teach the model
that attacks are benign (blind it) or that benign is attack (make it self-DoS). The
champion/challenger gate is the LAST backstop; this guard is the FIRST — cheaper and it keeps
the poison out of the training set entirely.

Screens (a sample must pass all to enter training):
  1. reviewed        : only human-reviewed labels train (no auto-train on raw captures).
  2. provenance/attestation (DETECTOR-INDEPENDENT): a sample from an auto-captured or
                       unknown origin may not be labeled BENIGN unless a human attested it
                       (reviewer id) or it is corroborated by >= MIN_CORROBORATION sources
                       that are NOT the deployed detectors. Screens 3-4 below delegate label
                       integrity to the signature engine and the champion model — precisely
                       the two things an evading attacker has already beaten — so this screen
                       exists to not be gameable by evasion alone. Attack->benign relabelling
                       is the model-blinding vector, so it is the one held to attestation.
  3. label-flip vs signatures : a payload a rule engine flags cannot be labeled 'benign'.
  4. label-flip vs champion   : a payload the live model scores >HI cannot be 'benign';
                                one it scores <LO with no signal cannot be 'attack'.
  5. rate caps       : no single source_ip/session (MAX_PER_SOURCE) *and* no single /24 or
                       /64 network block (MAX_PER_SUBNET) contributes more than its cap.
                       A per-IP cap alone is defeated by rotating IPs, so the subnet cap and
                       the batch-fraction cap below are the rotation-resistant controls.
  6. near-dup flood caps : many near-identical samples collapse to MAX_PER_CLUSTER; the
                       structural-shape cap (MAX_PER_SHAPE) additionally collapses payloads
                       padded with varying non-digit/non-hex filler, which defeats _norm().
  7. batch fraction  : untrusted-provenance samples may not exceed MAX_UNTRUSTED_FRACTION of
                       an accepted retrain batch, whatever they cost the attacker to produce.
                       This bound holds under unlimited IP rotation.

Returns (clean_samples, quarantined) with a reason per quarantined item.

Sample keys used: method,path,query,body,label(0/1),source_ip,reviewed(bool),
                  provenance(str),reviewer(str),review_id(str),corroborated_by(list[str]).
Producers of the capture feed SHOULD set `provenance`; a missing value is treated as
untrusted ("unknown"), never as trusted.
"""
from __future__ import annotations
import re, hashlib
from collections import defaultdict, Counter
from typing import Callable, Dict, List, Tuple, Optional

HI, LO = 0.85, 0.05
MAX_PER_SOURCE = 25
MAX_PER_CLUSTER = 15
# Rotation-resistant controls (a per-IP cap alone multiplies by the size of the proxy pool).
MAX_PER_SUBNET = 40           # per /24 (IPv4) or /64 (IPv6)
MAX_PER_SHAPE = 20            # per structural payload shape, filler-insensitive
MAX_UNTRUSTED_FRACTION = 0.25  # share of an accepted batch that may be untrusted-provenance

# Provenance that carries its own integrity story (signed feed, curated corpus, human label).
TRUSTED_PROVENANCE = {"human_labeled", "curated_corpus", "signed_feed", "redteam_exercise"}
# Anything else — including a missing value — is attacker-influenceable.
UNTRUSTED_DEFAULT = "unknown"

# Corroboration must come from something OTHER than the detectors an attacker evades.
MIN_CORROBORATION = 2
DETECTOR_SOURCES = {"champion", "challenger", "classifier", "ml", "detector_v2",
                    "signature", "signatures", "pattern_engine", "waf", "self"}


def _norm(payload: str) -> str:
    s = payload.lower()
    s = re.sub(r"\d+", "#", s)
    s = re.sub(r"[a-f0-9]{6,}", "H", s)
    s = re.sub(r"\s+", " ", s).strip()
    return hashlib.sha1(s.encode()).hexdigest()[:16]


def _shape(payload: str) -> str:
    """Structural signature: character CLASS runs collapsed to one symbol each.

    `_norm` only collapses digits and hex, so padding a payload with varying
    alphabetic filler produces a fresh cluster every time and defeats the near-dup
    cap. Collapsing letter/digit/space runs leaves only the punctuation skeleton —
    the part that actually carries an injection — so filler no longer buys clusters.
    """
    out, prev = [], None
    for ch in payload.lower():
        if ch.isalpha():
            cls = "a"
        elif ch.isdigit():
            cls = "0"
        elif ch.isspace():
            cls = " "
        else:
            cls = ch          # punctuation kept literally: it is the payload structure
        if cls != prev or not cls.isalnum() and cls != " ":
            out.append(cls)
        prev = cls
    return hashlib.sha1("".join(out).encode()).hexdigest()[:16]


def _subnet(ip: str) -> str:
    """/24 for IPv4, /64 for IPv6, raw value otherwise. Bounds a rotating pool that
    sits inside one allocation; it is not a defence against a spread botnet — the
    batch-fraction cap is what bounds that case."""
    ip = str(ip or "?")
    if ":" in ip:                               # IPv6
        return ":".join(ip.split(":")[:4]) + "::/64"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24"
    return ip


def _provenance(s: Dict) -> str:
    return str(s.get("provenance") or UNTRUSTED_DEFAULT).strip().lower()


def _is_trusted(s: Dict) -> bool:
    return _provenance(s) in TRUSTED_PROVENANCE


def _attested(s: Dict) -> bool:
    """A named human signed off on THIS sample's label."""
    return bool(s.get("reviewed")) and bool(s.get("reviewer") or s.get("review_id"))


def _corroboration(s: Dict) -> int:
    """Distinct corroborating sources that are not the deployed detectors."""
    raw = s.get("corroborated_by") or []
    if isinstance(raw, str):
        raw = [raw]
    return len({str(x).strip().lower() for x in raw
                if str(x).strip().lower() not in DETECTOR_SOURCES and str(x).strip()})


def screen(samples: List[Dict],
           champion_score: Callable[[Dict], float],
           signature_hit: Callable[[Dict], bool],
           require_review: bool = True) -> Tuple[List[Dict], List[Dict]]:
    """
    samples: dicts with keys method,path,query,body,label(0/1),source_ip,reviewed(bool),
             and optionally provenance/reviewer/review_id/corroborated_by.
    champion_score(sample)->prob, signature_hit(sample)->bool.
    """
    clean, quarantined = [], []
    per_source = Counter()
    per_subnet = Counter()
    per_cluster = Counter()
    per_shape = Counter()

    for s in samples:
        label = int(s.get("label", -1))
        payload = f"{s.get('query','')} {s.get('body','')}".strip()
        trusted = _is_trusted(s)
        reason = None

        if label not in (0, 1):
            reason = "no valid label"
        elif require_review and not s.get("reviewed", False):
            reason = "unreviewed (human-in-loop required)"
        elif (label == 0 and not trusted
              and not _attested(s) and _corroboration(s) < MIN_CORROBORATION):
            # Detector-independent: an attack->benign relabel from an
            # attacker-influenceable origin needs a named human or independent
            # corroboration. Deliberately does NOT consult the champion or the
            # signature engine — an attacker who evades both would otherwise pass.
            reason = (f"unattested benign label from untrusted provenance "
                      f"'{_provenance(s)}' (need reviewer id or >={MIN_CORROBORATION} "
                      f"non-detector corroborations)")
        elif label == 0 and signature_hit(s):
            reason = "label-flip: signature-matching attack labeled benign"
        elif label == 0 and champion_score(s) >= HI:
            reason = f"label-flip: champion scores {champion_score(s):.2f} (attack) but labeled benign"
        elif label == 1 and champion_score(s) < LO and not signature_hit(s):
            reason = f"label-flip: champion scores {champion_score(s):.2f} (benign) but labeled attack"
        else:
            src = s.get("source_ip", "?")
            net = _subnet(src)
            per_source[src] += 1
            per_subnet[net] += 1
            if per_source[src] > MAX_PER_SOURCE:
                reason = f"per-source cap: >{MAX_PER_SOURCE} samples from {src}"
            elif per_subnet[net] > MAX_PER_SUBNET:
                reason = f"per-subnet cap: >{MAX_PER_SUBNET} samples from {net}"
            else:
                cl = _norm(payload)
                sh = _shape(payload)
                per_cluster[cl] += 1
                per_shape[sh] += 1
                if per_cluster[cl] > MAX_PER_CLUSTER:
                    reason = f"near-duplicate flood: >{MAX_PER_CLUSTER} of the same payload shape"
                elif per_shape[sh] > MAX_PER_SHAPE:
                    reason = (f"structural flood: >{MAX_PER_SHAPE} payloads of the same "
                              f"structure (filler-padded near-duplicates)")

        if reason:
            quarantined.append({**s, "quarantine_reason": reason})
        else:
            clean.append(s)

    clean, over_budget = _apply_untrusted_budget(clean)
    quarantined.extend(over_budget)
    return clean, quarantined


def _apply_untrusted_budget(clean: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Cap the share of an accepted batch that comes from untrusted provenance.

    Per-IP and per-subnet caps both scale with how many addresses an attacker can
    rent. This one does not: whatever the source spread, untrusted-origin samples
    can never exceed MAX_UNTRUSTED_FRACTION of what reaches training. Excess is
    quarantined oldest-first-kept (deterministic, input order)."""
    total = len(clean)
    if total == 0:
        return clean, []
    budget = int(total * MAX_UNTRUSTED_FRACTION)
    kept, dropped, used = [], [], 0
    for s in clean:
        if _is_trusted(s):
            kept.append(s)
            continue
        if used < budget:
            used += 1
            kept.append(s)
        else:
            dropped.append({**s, "quarantine_reason": (
                f"untrusted-provenance batch budget: >{MAX_UNTRUSTED_FRACTION:.0%} "
                f"of the batch (cap {budget} of {total})")})
    return kept, dropped


def summary(clean: List[Dict], quarantined: List[Dict]) -> Dict:
    reasons = Counter(q["quarantine_reason"].split(":")[0] for q in quarantined)
    return {"accepted": len(clean), "quarantined": len(quarantined),
            "accepted_trusted": sum(1 for s in clean if _is_trusted(s)),
            "accepted_untrusted": sum(1 for s in clean if not _is_trusted(s)),
            "quarantine_reasons": dict(reasons)}
