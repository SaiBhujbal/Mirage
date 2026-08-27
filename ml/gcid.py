"""
GCID — Grammar-Conformance Injection Detection (distribution-free injection ML).

The thesis (full design + honest limits in ml/RESEARCH_GCID.md): every other ML layer in this
repo models the BENIGN distribution and flags outliers, and every one of them false-positives on
modern/out-of-distribution benign (JSON APIs, base64 blobs, JWTs) because the space of legitimate
traffic cannot be enumerated. GCID never models benign at all. It measures the invariant of an
*injection*: a value carries CONTROL (code) structure in some downstream interpreter's grammar —
SQL, HTML/JS, shell, path, template, log4j-JNDI, XML, NoSQL, LDAP. `hello world`, a base64 avatar
and a JWT all have ~0 code structure in EVERY grammar regardless of their surface entropy, which is
exactly why they fooled the distribution models and cannot fool this one.

Three stages:
  1. normalize()          — bounded URL-decode rounds + surfaced base64 content, i.e. what the
                            downstream parser actually sees.
  2. structure_vector()   — per-grammar control-structure density in [0,1]; a fixed 12-dim vector.
  3. GcidDetector         — a LEARNED scorer (sklearn) over that vector, conformally calibrated on
                            benign structure scores for a distribution-free false-alarm budget.

The ML novelty is stage 2+3 (the feature space and its calibration), not the stage-2 regexes: a
raw regex max-scorer is the baseline this is measured against, and `--train` prints both.

SCOPE, stated up front and honestly: GCID is an INJECTION detector. SSRF-to-internal,
open-redirect, IDOR/business logic, auth bypass and protocol attacks carry NO injection grammar
and GCID scores them ~0 BY DESIGN — they are other layers' job. Out-of-scope families are excluded
from training for the same reason: labelling a zero-structure record "attack" would only teach the
scorer to guess.

MEASURED (this build; reproduce with `--train`, tests/test_gcid.py, and
`WAF_ML_MODEL=gcid python -m harness.run --targets ml_model`):
  - harness ml_model: 0/21 benign blocked, recall 21/24 — every in-scope family 1.00, all three
    misses are SSRF (out of scope). For contrast the incumbent XGBoost model blocks 21/21 benign.
  - 0/500 modern-generated benign, 0/2000 real CSIC-2010 benign, 0/896 train_v2 benign.
  - held-out in-scope injection recall 98.9%; 11/12 obfuscated (encoded/case/comment/base64).
  - The LEARNED scorer TIES the raw max-scorer baseline on these corpora. Its measured advantage
    (0.05% vs 5.21% FP) existed only against the earlier, buggier featurizer; once the grammar
    scorers stopped firing on `&cp=17463` and bare SQL keywords, the two coincide. Reported as a
    negative result rather than dressed up.
  - KNOWN RESIDUAL FALSE-POSITIVE CLASS (18% on an adversarial hard-benign probe): fields that
    legitimately CARRY code — markdown with ```sql fences or `rm -rf` code spans, CI `script=`
    fields, YAML with `${HOME}`. These are not detector bugs; the application has genuinely made
    that field a control plane, and no distribution-free rule can separate them from injection.
    They are why `enforce` is OFF by default (WAF_GCID_ENFORCE): GCID does not clear a <2% FP bar
    on traffic containing code-bearing content fields. Scope it per-route before enforcing.

    python -m ml.gcid --train     # (re)build models_v2/gcid.joblib + gcid_meta.json, print metrics
    python -m ml.gcid --eval      # metrics only, from the persisted model

    WAF_ML_MODEL=gcid             # select it as the live detector (ml.detector_v2.get_detector)
"""
from __future__ import annotations

import argparse
import base64 as _b64
import hashlib
import json
import logging
import os
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.detector_v2 import MLResult  # noqa: E402  (path bootstrap above, repo convention)

logger = logging.getLogger("mirage.ml.gcid")

_DIR = Path(__file__).resolve().parent.parent / "models_v2"
MODEL_PATH = _DIR / "gcid.joblib"
META_PATH = _DIR / "gcid_meta.json"

# Default false-alarm budget for the conformal decision rule: "I accept <= 1% benign false alarms".
DEFAULT_ALPHA = 0.01
# Minimum control-structure any single grammar must show before a verdict counts, regardless of
# what the conformal p-value says. MEASURED REASON: on every benign corpus available here the
# structure score is *exactly* 0, so the calibration set is degenerate — every calibration score
# collapses to one value and the p-value becomes a step function that flags any nonzero trace.
# That made `{"$and":[{"status":"open"}]}` (a real Mongo-filter API request) and `{{ user.name }}`
# (a template-preview field) false-positive off 0.30-0.35 of structure. A p-value computed against
# a degenerate calibration set is not evidence; require real structure too. Tunable per deployment.
DEFAULT_MIN_STRUCTURE = 0.4
# Stricter budget required before a verdict may BLOCK rather than shadow-log.
DEFAULT_ENFORCE_ALPHA = 0.002
DEFAULT_ENFORCE_PROB = 0.90

# ---------------------------------------------------------------- stage 1: normalize

# 12, not 16: `JyBPUiAnMSc9JzE=` is base64 for `' OR '1'='1` and is only 15 body characters, so a
# 16-char floor let the shortest wrapped SQLi through the decode stage entirely (measured miss).
_B64 = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")


def normalize(value: str, rounds: int = 3) -> str:
    """Normalize a field to what a downstream parser would see.

    Bounded URL-decode rounds (bounded: an unbounded loop is a decode-bomb DoS), plus any
    base64-encoded content surfaced alongside the original — interpreters routinely base64-decode
    a value, and an attacker wrapping SQLi in base64 must not thereby erase its grammar.
    """
    prev = str(value)
    for _ in range(max(0, rounds)):
        try:
            dec = urllib.parse.unquote_plus(prev)
        except Exception:
            break
        if dec == prev:
            break
        prev = dec
    extra: List[str] = []
    for tok in _B64.findall(prev):
        if len(tok) % 4:
            continue
        try:
            dec = _b64.b64decode(tok, validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if len(dec) >= 6 and sum(32 <= ord(ch) < 127 for ch in dec) / len(dec) > 0.8:
            extra.append(dec)
    return prev + (" \x00 " + " ".join(extra) if extra else "")


# ------------------------------------------- stage 2: per-grammar control-structure scorers
#
# Each returns "how much of this value is CODE rather than DATA" in that grammar, in [0,1].
# The discipline throughout: score CONTROL CONSTRUCTS, never bare metacharacters. A cookie's `;`
# is a separator; `; cat /etc/passwd` is a shell command boundary. That distinction is what keeps
# the benign side at ~0 without ever having seen benign traffic.

# A bare keyword is DATA, not grammar: `from=2024-09-01` and prose "... and a link" are benign and
# a lone-keyword term cost 0.35 structure on both (measured: it was the dominant benign FP source).
# Only a keyword bound into a CLAUSE, a control operator, or a quote that closes a literal and
# comments out the rest of the statement counts.
_SQL_CLAUSE = re.compile(
    # `select <column-list> from` — a COLUMN LIST, not prose. "SELECT the best laptop from our
    # catalog" is a shopping query, and a loose `select ... from` gap scored it as SQL.
    r"(?i)\b(?:union\b[\s\S]{0,40}?\bselect|"
    r"select\s+(?:distinct\s+|top\s+\d+\s+|all\s+)?(?:\*|\w+\s*\([^)]*\)|[\w.`\[\]\"]+"
    r"(?:\s*,\s*(?:\w+\s*\([^)]*\)|[\w.`\[\]\"]+))*)\s+from\b|insert\b\s+into|"
    r"drop\s+(?:table|database)|truncate\s+table|update\b[\s\S]{0,60}?\bset\b|delete\s+from|"
    r"waitfor\s+delay|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|load_file\s*\(|into\s+(?:out|dump)file|"
    r"extractvalue\s*\(|updatexml\s*\(|dbms_pipe\.receive_message|dbms_lock\.sleep|utl_inaddr|"
    r"copy\s+\w+\s+to|xp_cmdshell|information_schema|group\s+by\b[\s\S]{0,40}?\bhaving)")
_SQL_OP = re.compile(r"(?i)('|\"|--|#|/\*|\bor\b|\band\b)\s*[\d'\"]*\s*(=|like|rlike|regexp|<|>)")
# `admin'--` : close the literal, comment out the rest. The canonical auth-bypass grammar, and it
# contains no comparison operator at all, so _SQL_OP alone misses it.
_SQL_TERM = re.compile(r"['\"]\s*(?:--|/\*)|['\"]\s*#\s*$|['\"]\s*;\s*(?:\w|$)")
# MySQL treats /*...*/ as whitespace and /*!VERSION x*/ as CODE, and \x0b/\x0c as whitespace, so
# `UN/**/ION SEL/**/ECT` and `uni%0bon` reach the parser as `UNION SELECT`. Undo that before
# scoring — this is parser emulation, not a signature for a specific evasion.
_SQL_DEOBF = re.compile(r"/\*!?\d*|\*/|[\x00-\x08\x0b\x0c\x0e-\x1f]")


def s_sql(v: str) -> float:
    """SQL: score CLAUSE structure, control operators and literal-termination — never bare words."""
    best = 0.0
    for cand in (v, _SQL_DEOBF.sub("", v)):
        clause = len(_SQL_CLAUSE.findall(cand))
        op = len(_SQL_OP.findall(cand))
        term = len(_SQL_TERM.findall(cand))
        quoted = 0.3 if ("'" in cand and (op or clause)) else 0.0
        best = max(best, min(1.0, 0.6 * clause + 0.5 * op + 0.6 * term + quoted))
    return best


# Event handlers via an ALLOWLIST of real handler names: `on\w+=` matches benign `content=`.
_JS = re.compile(r"(?i)(<\s*(script|img|svg|iframe|body|details|marquee|object|embed|video|audio)\b|"
                 r"\bon(error|load|click|mouse[a-z]+|focus|blur|toggle|pointer[a-z]+|start|submit|"
                 r"change|drag|drop|key[a-z]+|animation[a-z]+|wheel|scroll|contextmenu)\s*=|"
                 r"javascript\s*:|</\s*script|srcdoc\s*=|\balert\s*\(|\beval\s*\(|"
                 r"document\.(cookie|location|write))")


def s_xss(v: str) -> float:
    """HTML/JS: a dangerous tag, a real event handler, or a js: / script sink."""
    return min(1.0, 0.6 * len(_JS.findall(v)))


# A bare `;`/`&` is an HTTP/cookie separator, not shell. Only unambiguous control constructs:
# subshell, backtick, ${...}, &&/||, or a metachar IMMEDIATELY followed by a command token —
# that metachar->command transition IS the data-to-code boundary crossing that defines RCE.
# `&&` / `||` are NOT here: measured, `revenue > 1M && growth < 5%` is prose and `^(a|b)+` is a
# regex. A shell chain operator only means "command" when a command FOLLOWS it, which is exactly
# what _SH_CMDSEP checks (its `[;&|\n]` class already covers the second character of `&&`/`||`).
_SH_STRONG = re.compile(r"(?:\$\([^)]*\)|`[^`]*`|\$\{[^}]*\})")
# The `(?!\s*=)` is load-bearing: `&cp=17463` is a benign postal-code PARAMETER, and without the
# lookahead it read as the shell `cp` command after a `&` separator — measured as 11% FP on real
# CSIC-2010 benign traffic. `name=value` is data-plane by construction; a command is not followed
# by `=`. Same guard rescues `&id=`, `&rm=`, `&ls=`.
_SH_CMDSEP = re.compile(r"(?i)[;&|\n]\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|netcat|bash|sh|zsh|"
                        r"powershell|cmd\.exe|ping|nslookup|dig|python[23]?|perl|ruby|php|rm|mv|cp|"
                        r"chmod|chown|touch|echo|env|printenv|base64|xxd|/bin/|/etc/|/usr/bin/|"
                        r"dir|net\s+(?:user|localgroup)|systeminfo|tasklist|ipconfig|certutil)"
                        # `=` -> a query PARAMETER (`&cp=`); `,` -> a MIME parameter
                        # (`data:image/png;base64,...`). Neither is a command invocation.
                        r"\b(?!\s*[=,])")
# `$IFS` (with or without braces) is the classic space-free argument separator: `cat$IFS/etc/passwd`.
_SH_IFS = re.compile(r"(?i)\$\{?IFS")


def s_rce(v: str) -> float:
    strong = len(_SH_STRONG.findall(v))
    cmdsep = len(_SH_CMDSEP.findall(v))
    ifs = 0.5 if _SH_IFS.search(v) else 0.0
    return min(1.0, 0.55 * strong + 0.7 * cmdsep + ifs)


_TRAV = re.compile(r"(?i)(?:\.\.[/\\]|\.\.%2f|%2e%2e|\.\.%c0%af|\.\.\.\.//|/etc/(?:passwd|shadow)|"
                   r"/proc/self|(?:/|\\)windows(?:/|\\)win\.ini)")
# PHP/Java stream wrappers turn a "file name" into an interpreter directive — `php://filter/...`
# reads source, `expect://id` executes, `data://text/plain;base64,` injects code. Deliberately
# excludes http/https, which are ordinary data.
_WRAPPER = re.compile(r"(?i)\b(?:file|php|expect|phar|zip|glob|data|dict|gopher|jar|netdoc)://")


def s_path(v: str) -> float:
    """Path grammar: `/home/user/doc.pdf` is data; a traversal operator, a sentinel target
    (/etc/passwd, /proc/self) or a stream wrapper is control."""
    return min(1.0, 0.6 * len(_TRAV.findall(v)) + 0.6 * len(_WRAPPER.findall(v)))


_TPL = re.compile(r"(\{\{.*?\}\}|\$\{[^}]*\}|<%[^%]*%>|#\{[^}]*\}|<#\w+|\{%[^%]*%\}|"
                  r"\{\s*\d+\s*[*+/%-]\s*\d+\s*\}|#set\s*\(|\{php\}|\{\$\w+[.\w]*\}|"
                  r"[@*~]\{[^}]*\})")
_TPL_CODE = re.compile(r"(?i)(\*|__|class|getclass|runtime|exec|self|config|jndi|smarty|"
                       r"\d\s*[*+%]\s*\d)")


def s_ssti(v: str) -> float:
    """A template DELIMITER is syntax, not code: `{{ user.name }}` in a template-preview field is
    benign, while `{{7*7}}` / `{{config}}` / `${T(Runtime)}` execute. So the delimiter alone scores
    low and the dangerous construct must appear INSIDE the expression — previously `_TPL_CODE` was
    matched against the whole value, so `yaml=path: ${HOME}/.config/app` scored 0.9 off the word
    "config" sitting outside the braces.
    """
    m = _TPL.findall(v)
    if not m:
        return 0.0
    inner = " ".join(x if isinstance(x, str) else " ".join(x) for x in m)
    return min(1.0, 0.35 * len(m) + (0.55 if _TPL_CODE.search(inner) else 0.0))


_JNDI = re.compile(r"(?i)\$\{(jndi|lower|upper|env|sys|date):")


def s_log4(v: str) -> float:
    return min(1.0, 0.9 * len(_JNDI.findall(v)))


# Bounded gap, not `.*?` with DOTALL: an unbounded lazy gap is quadratic on a long body.
_XXE = re.compile(r"(?i)<!(doctype|entity)\b[\s\S]{0,300}?(system|public|%)")


def s_xxe(v: str) -> float:
    return 0.9 if _XXE.search(v) else 0.0


# Split by what the operator DOES. `$where`/`$function`/`$expr`/`$accumulator` execute code — one
# is decisive. The comparison operators are the same ones a legitimate Mongo-backed filter API
# accepts (`{"$and":[{"status":"open"}]}` is a real request shape), so ONE is not evidence; the
# auth-bypass shape that matters stacks at least two (`{"user":{"$gt":""},"pass":{"$ne":null}}`).
_NOSQL_EXEC = re.compile(r"(?i)\$(where|function|accumulator|expr)\b")
_NOSQL = re.compile(r"(?i)\$(gt|lt|ne|gte|lte|in|nin|regex|or|and|not|nor|exists|type|size|"
                    r"text|search|elemMatch|all|mod|jsonSchema)\b")
# `username[$exists]=true` — the bracket form smuggles the same operator through form encoding.
_NOSQL_BRACKET = re.compile(r"\[\s*\$\w+\s*\]\s*=")
# `'; return this.password; var x='` — closing a JS string to inject a $where predicate body.
# Anchored on the literal `;` with BOUNDED whitespace runs: an unanchored `['\"]?\s*;` made the
# engine rescan a whitespace run from every offset — measured 176ms on the harness ReDoS probe
# (" \t" x 8192) against a 500ms budget. Literal-prefix anchoring keeps it linear.
_NOSQL_JS = re.compile(r"(?i);\s{0,4}return\b[\s\S]{0,60}?;\s{0,4}(?:var\b|//|$)")


def s_nosql(v: str) -> float:
    return min(1.0, 0.85 * len(_NOSQL_EXEC.findall(v)) + 0.3 * len(_NOSQL.findall(v))
               + 0.6 * len(_NOSQL_BRACKET.findall(v)) + (0.8 if _NOSQL_JS.search(v) else 0.0))


# LDAP filter grammar: a value that opens/closes filter parens or injects a boolean operator.
# A LONE `*` is deliberately NOT scored — a bare wildcard is a legitimate search value, and
# GCID would rather miss `filter=*` than false-positive on every wildcard search (documented miss).
_LDAP = re.compile(r"(?:\)\s*\(\s*[|&]|\*\)\s*[(\)\x00]|\)\(\||[|&]\(\s*\w+\s*=|\)\s*\x00|"
                   r"\*\(\)|\)\s*\(\s*\w+\s*=\s*\*)")


def s_ldap(v: str) -> float:
    return 0.85 if _LDAP.search(v) else 0.0


# ---- RESOURCE-plane confusion (SSRF): a value targeting a CONTROL resource, not a data one. ----
# Distribution-free like the injection grammars: it is about the TARGET's network class / scheme,
# not about how "usual" the request looks. A public host (`https://api.example.com`) scores 0.
_URL_HOST = re.compile(r"(?i)(?:https?|ftp|gopher|dict|file|ldap|tftp|jar|netdoc)://([^/\s:?#]+)")
# internal / reserved / metadata targets, incl. octal/hex/decimal-integer loopback obfuscation.
_INTERNAL = re.compile(
    r"(?i)^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|"
    r"0\.0\.0\.0$|localhost$|\[?::1\]?$|0x[0-9a-f]+$|0\d{1,3}\.|2130706433$|017700000001$|"
    r"\d{8,10}$|metadata\.(?:google|internal|azure))")
# non-http fetch schemes turn a "URL" into a control channel (gopher->redis, file->read, ...).
_DANGER_SCHEME = re.compile(r"(?i)\b(?:gopher|dict|file|ftp|ldap|tftp|jar|netdoc|expect|php)://")


def s_ssrf(v: str) -> float:
    """SSRF = a value that points the SERVER at a control-plane resource (internal/metadata host,
    obfuscated loopback, or a non-http fetch scheme). Public hosts are data and score 0."""
    s = 0.9 if _DANGER_SCHEME.search(v) else 0.0
    for host in _URL_HOST.findall(v):
        h = host.strip("[]")
        if "@" in host:                       # user@host authority trick -> parser confusion
            s = max(s, 0.7)
        if _INTERNAL.match(h):
            s = max(s, 0.85)
    return min(1.0, s)


# ---- RESOURCE-plane confusion (open redirect): a value that hijacks navigation off-site. ----
# Only the genuinely dangerous targets (scheme-relative //host, backslash, js:/data:) — a plain
# absolute URL is legitimate navigation data (the REDIR-001 false-positive lesson).
# `data:image/...` is a legitimate inline asset; only `data:text/html` executes. Bare `data:`
# false-positived on CDN image URIs — narrow it to the executable content type.
_REDIR = re.compile(r"(?i)(?:^|=)\s*(?:(?:https?:)?[\\]{1,2}|//[a-z0-9.-]+\.[a-z]{2,}|"
                    r"/[\\]|(?:java\s*script|vbscript)\s*:|data\s*:\s*text/html)")


def s_redirect(v: str) -> float:
    return 0.75 if _REDIR.search(v) else 0.0


# ---- PROTOCOL-plane confusion (CRLF / header injection): control chars that forge a header. ----
# A bare newline is benign (multiline text); the ATTACK is CR/LF followed by a header token, which
# injects into the response — distribution-free structure, and it will not fire on ordinary bodies.
_CRLF = re.compile(r"(?i)(?:%0d%0a|%0d|%0a|\r\n|\r|\n)\s*(?:set-cookie|location|content-type|"
                   r"content-length|refresh|link|x-[a-z][a-z0-9-]*)\s*:")


def s_crlf(v: str) -> float:
    return 0.8 if _CRLF.search(v) else 0.0


GRAMMARS: Dict[str, "object"] = {
    "sql": s_sql, "xss": s_xss, "rce": s_rce, "path": s_path, "ssti": s_ssti,
    "log4": s_log4, "xxe": s_xxe, "nosql": s_nosql, "ldap": s_ldap,
    "ssrf": s_ssrf, "redirect": s_redirect, "crlf": s_crlf,
}
GRAMMAR_NAMES: List[str] = list(GRAMMARS)
# 9 per-grammar structure scores + 3 shape aggregates the learned scorer can exploit
# (how strong, how much total, across how many grammars — a real injection concentrates its
# structure in ONE grammar, which is a signal a per-grammar max cannot express).
FEATURE_NAMES: List[str] = GRAMMAR_NAMES + ["struct_max", "struct_sum", "n_active"]
N_FEATURES = len(FEATURE_NAMES)
_MAX_I = FEATURE_NAMES.index("struct_max")

# Families GCID targets. v2 extends the "control-plane confusion" principle beyond injection to the
# RESOURCE plane (SSRF, open-redirect) and PROTOCOL plane (CRLF/header). Still out of scope BY
# DESIGN: business-logic (IDOR, mass-assignment, auth bypass) — no structural signal exists without
# application context, so no blind WAF/ML can decide it. See ml/RESEARCH_GCID.md.
IN_SCOPE_FAMILIES = {"sqli", "xss", "rce", "lfi", "path_traversal", "log4shell",
                     "ssti", "xxe", "nosql", "ldap",
                     "ssrf", "open_redirect", "redirect", "crlf", "header_injection"}


def gcid_contract_hash() -> str:
    """SHA-256 (16 hex) of the ordered feature contract — train and serve must agree."""
    return hashlib.sha256(",".join(FEATURE_NAMES).encode()).hexdigest()[:16]


def _fields(method: str, path: str, query: str, body: str,
            headers: Optional[Dict[str, str]]) -> List[str]:
    vals = [path or "", query or "", body or ""]
    for v in (headers or {}).values():
        if v:
            vals.append(str(v))
    return [v for v in vals if v]


def grammar_scores(method: str = "GET", path: str = "", query: str = "", body: str = "",
                   headers: Optional[Dict[str, str]] = None) -> Dict[str, float]:
    """Per-grammar structure score, max over the request's fields. Named, for explainability.

    Each field is scored in BOTH its raw and its normalized form. Normalization is what the
    downstream parser sees, but it also destroys evidence the *web server* sees: `..%c0%af` and
    `%2e%2e` are traversal in the raw form and become replacement characters once decoded. Taking
    the max over both means an attacker cannot pick an encoding layer that is blind on both sides.
    """
    out = {g: 0.0 for g in GRAMMAR_NAMES}
    for raw in _fields(method, path, query, body, headers):
        forms = {raw, normalize(raw)}
        for name, fn in GRAMMARS.items():
            s = max(float(fn(v)) for v in forms)
            if s > out[name]:
                out[name] = s
    return out


def structure_vector(method: str = "GET", path: str = "", query: str = "", body: str = "",
                     headers: Optional[Dict[str, str]] = None) -> np.ndarray:
    """Fixed-length grammar-structure feature vector for one request. Benign-independent."""
    sc = grammar_scores(method, path, query, body, headers)
    per = np.array([sc[g] for g in GRAMMAR_NAMES], dtype=np.float32)
    agg = np.array([per.max(), per.sum(), float((per > 0.1).sum())], dtype=np.float32)
    return np.concatenate([per, agg]).astype(np.float32)


def raw_max_score(method: str = "GET", path: str = "", query: str = "", body: str = "",
                  headers: Optional[Dict[str, str]] = None) -> float:
    """The v1 BASELINE: max structure over grammars, no learning. `--train` measures against it."""
    return float(structure_vector(method, path, query, body, headers)[_MAX_I])


# ------------------------------------------------------------- stage 3: learned scorer + conformal

def _vectorize(records: Sequence[Tuple[str, str, str, str]]) -> np.ndarray:
    if not records:
        return np.zeros((0, N_FEATURES), dtype=np.float32)
    return np.stack([structure_vector(m, p, q, b, None) for (m, p, q, b) in records])


def build_training_data(n_modern: int = 3000, n_csic: int = 4000,
                        seed: int = 13) -> Tuple[List[Tuple[str, str, str, str]],
                                                 List[Tuple[str, str, str, str]]]:
    """(attacks, benign) request tuples for the learned scorer.

    Attacks: in-scope injection payloads only (embedded real-world corpus + the modern generator,
    minus its SSRF shape) — see the scope note in the module docstring.
    Benign: the modern generator + CSIC-2010 normal traffic (real 2010 e-commerce) + the train_v2
    synthetic benign. Deliberately three very different benign distributions, because the whole
    claim is that GCID's benign side does not depend on which one you pick.
    """
    attacks: List[Tuple[str, str, str, str]] = []
    benign: List[Tuple[str, str, str, str]] = []

    try:
        from ml.real_payload_loader import EmbeddedPayloads
        import ml.train_v2 as tv
        emb = EmbeddedPayloads.get_all()
        for cat, payloads in emb.items():
            if cat not in IN_SCOPE_FAMILIES:
                continue                       # out-of-scope class: no grammar signal to learn
            for pl in payloads:
                attacks.append(tv.payload_to_fields(cat, pl))
    except Exception as e:
        logger.warning("embedded payloads unavailable (%s)", e)

    try:
        from data_pipeline.modern_attacks import generate as gen_attack
        # v2: SSRF (the generator's "/fetch" shape) is now IN scope with its own grammar scorer,
        # so include it — it teaches the scorer the resource-plane structure.
        attacks += gen_attack(n_modern, seed=seed + 1)
    except Exception as e:
        logger.warning("modern attack generator unavailable (%s)", e)
    # explicit resource/protocol-plane attack shapes so the learned scorer sees the new grammars.
    import random as _r
    _rng = _r.Random(seed + 7)
    _hosts = ["127.0.0.1", "169.254.169.254", "0177.0.0.1", "2130706433", "[::1]", "localhost"]
    _redirs = ["//evil.com", "/\\evil.com", "javascript:alert(1)", "\\\\evil.com"]
    for _ in range(300):
        h, port, leaf = _rng.choice(_hosts), _rng.randint(80, 9000), _rng.choice(["admin", "meta", "x"])
        attacks.append(("GET", "/fetch", "url=http://" + h + ":" + str(port) + "/" + leaf, ""))
        attacks.append(("GET", "/go", "next=" + _rng.choice(_redirs), ""))
        attacks.append(("GET", "/r", "redir=%0d%0aSet-Cookie:admin=1", ""))

    try:
        from data_pipeline.modern_benign import generate as gen_benign
        benign += gen_benign(n_modern, seed=seed)
    except Exception as e:
        logger.warning("modern benign generator unavailable (%s)", e)

    try:
        from data_pipeline.csic_loader import load as csic_load
        benign += csic_load("normal_train")[:n_csic]
    except Exception as e:
        logger.warning("CSIC normal traffic unavailable (%s)", e)

    try:
        import ml.train_v2 as tv
        benign += list(tv.gen_benign(1500))
    except Exception as e:
        logger.warning("train_v2 benign unavailable (%s)", e)

    return attacks, benign


def conformal_threshold(calib: np.ndarray, alpha: float) -> float:
    """Score at/above which the conformal p-value drops below `alpha`. Reporting aid only —
    the decision rule itself uses the p-value, so it stays exact."""
    if calib.size == 0:
        return 1.0
    return float(np.quantile(calib, min(1.0, max(0.0, 1.0 - alpha))))


def train(alpha: float = DEFAULT_ALPHA, seed: int = 13, models_dir: Path = _DIR,
          verbose: bool = True) -> Dict:
    """Fit the learned scorer over structure vectors, calibrate conformally, persist, report."""
    import joblib
    from sklearn.linear_model import LogisticRegression

    attacks, benign = build_training_data(seed=seed)
    if not attacks or not benign:
        raise RuntimeError("no training data available (payload loaders/generators all failed)")

    Xa, Xb = _vectorize(attacks), _vectorize(benign)
    rng = np.random.default_rng(seed)
    ia, ib = rng.permutation(len(Xa)), rng.permutation(len(Xb))
    # benign split: fit / conformal-calibrate / held-out test (disjoint — calibration must never
    # be scored on data the model fit, or the guarantee is vacuous)
    b_fit, b_cal, b_test = np.split(ib, [int(0.50 * len(ib)), int(0.75 * len(ib))])
    a_fit, a_test = np.split(ia, [int(0.75 * len(ia))])

    clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)
    Xfit = np.vstack([Xa[a_fit], Xb[b_fit]])
    yfit = np.concatenate([np.ones(len(a_fit)), np.zeros(len(b_fit))])
    clf.fit(Xfit, yfit)

    def prob(X):
        return clf.predict_proba(X)[:, 1] if len(X) else np.zeros(0)

    s_cal, s_bt, s_at = prob(Xb[b_cal]), prob(Xb[b_test]), prob(Xa[a_test])

    from ml.conformal_openset import conformal_pvalues
    p_bt = conformal_pvalues(s_cal, s_bt)
    p_at = conformal_pvalues(s_cal, s_at)

    # The served rule is `p < alpha AND struct_max >= min_structure` — evaluate exactly that.
    floor_b = Xb[b_test][:, _MAX_I] >= DEFAULT_MIN_STRUCTURE
    floor_a = Xa[a_test][:, _MAX_I] >= DEFAULT_MIN_STRUCTURE
    sweep = []
    for a in (0.001, 0.002, 0.005, 0.01, 0.02, 0.05):
        sweep.append({"alpha": a,
                      "benign_false_alarm": round(float(np.mean((p_bt < a) & floor_b)), 5),
                      "injection_recall": round(float(np.mean((p_at < a) & floor_a)), 4),
                      "recall_no_structure_floor": round(float(np.mean(p_at < a)), 4)})

    # BASELINE: the v1 regex max-scorer at its hand-picked 0.4 threshold, same held-out split.
    base_fp = float(np.mean(Xb[b_test][:, _MAX_I] >= 0.4))
    base_rec = float(np.mean(Xa[a_test][:, _MAX_I] >= 0.4))

    meta = {
        "model": "GCID: LogisticRegression over grammar-structure vector + inductive conformal",
        "contract_hash": gcid_contract_hash(),
        "feature_names": FEATURE_NAMES,
        "grammar_names": GRAMMAR_NAMES,
        "alpha": alpha,
        "min_structure": DEFAULT_MIN_STRUCTURE,
        "enforce_alpha": DEFAULT_ENFORCE_ALPHA,
        "enforce_threshold": DEFAULT_ENFORCE_PROB,
        "conformal_threshold_at_alpha": round(conformal_threshold(s_cal, alpha), 6),
        "n_attack": int(len(Xa)), "n_benign": int(len(Xb)), "n_calibration": int(len(s_cal)),
        "in_scope_families": sorted(IN_SCOPE_FAMILIES),
        "coefficients": {n: round(float(c), 4) for n, c in zip(FEATURE_NAMES, clf.coef_[0])},
        "heldout": {
            "conformal_sweep": sweep,
            "learned_at_alpha": {
                "alpha": alpha, "min_structure": DEFAULT_MIN_STRUCTURE,
                "benign_false_alarm": round(float(np.mean((p_bt < alpha) & floor_b)), 5),
                "injection_recall": round(float(np.mean((p_at < alpha) & floor_a)), 4)},
            "calibration_degenerate": bool(np.unique(s_cal).size <= 2),
            "baseline_raw_max_thr0.4": {"benign_false_alarm": round(base_fp, 5),
                                        "injection_recall": round(base_rec, 4)},
        },
        "scope_note": ("INJECTION detector. SSRF/open-redirect/IDOR/business-logic carry no "
                       "interpreter grammar and score ~0 by design; other layers own them."),
    }

    models_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"clf": clf, "calibration_scores": np.sort(s_cal).astype(np.float32),
                 "feature_names": FEATURE_NAMES, "contract_hash": gcid_contract_hash()}, MODEL_PATH)
    META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if verbose:
        print(f"GCID trained — attacks={len(Xa)} benign={len(Xb)} calib={len(s_cal)}")
        print(f"  learned  @alpha={alpha}: benign FP {meta['heldout']['learned_at_alpha']['benign_false_alarm']*100:.2f}%"
              f"  injection recall {meta['heldout']['learned_at_alpha']['injection_recall']*100:.1f}%")
        print(f"  baseline (raw max >=0.4): benign FP {base_fp*100:.2f}%  injection recall {base_rec*100:.1f}%")
        print("  conformal sweep (benign FA should track alpha):")
        for row in sweep:
            print(f"    alpha={row['alpha']:<6} FA={row['benign_false_alarm']*100:6.3f}%  "
                  f"recall={row['injection_recall']*100:6.2f}%")
        print(f"  wrote {MODEL_PATH.name} + {META_PATH.name}")
    return meta


class GcidDetector:
    """Serving detector for GCID, conforming to the ml.detector_v2.MLResult contract.

    Pure python/numpy/sklearn — no torch, so it loads where the byte-CNN cannot.
    """

    model_kind = "gcid (grammar-conformance injection detection: learned scorer + conformal)"

    def __init__(self, models_dir: Path = _DIR, alpha: Optional[float] = None):
        import joblib
        if not (MODEL_PATH.exists() and META_PATH.exists()):
            raise FileNotFoundError(f"GCID artifacts missing in {models_dir} "
                                    "(train with: python -m ml.gcid --train)")
        # Bind the conformal p-value here, at LOAD time. Importing it lazily inside predict() put
        # ml.conformal_openset's module-level `import ml.train_v2` (which drags in xgboost and the
        # payload loaders) inside the first scored request: measured as a 55ms p99 in the harness
        # against a 50ms budget, versus 0.12ms steady-state. Cold-start cost belongs in __init__.
        from ml.conformal_openset import conformal_pvalues
        self._conformal_pvalues = conformal_pvalues

        bundle = joblib.load(MODEL_PATH)
        self.meta = json.loads(META_PATH.read_text(encoding="utf-8"))
        self.clf = bundle["clf"]
        self.calibration = np.asarray(bundle["calibration_scores"], dtype=np.float64)

        live = gcid_contract_hash()
        trained = bundle.get("contract_hash") or self.meta.get("contract_hash")
        if trained and trained != live:
            raise RuntimeError(f"GCID FEATURE CONTRACT MISMATCH: serving={live} trained={trained} "
                               "— retrain (python -m ml.gcid --train), do not serve skewed features.")
        self.contract_verified = bool(trained) and trained == live

        self.alpha = float(alpha if alpha is not None
                           else _env_float("WAF_GCID_ALPHA", self.meta.get("alpha", DEFAULT_ALPHA)))
        self.enforce_alpha = float(_env_float("WAF_GCID_ENFORCE_ALPHA",
                                              self.meta.get("enforce_alpha", DEFAULT_ENFORCE_ALPHA)))
        self.min_structure = float(_env_float("WAF_GCID_MIN_STRUCTURE",
                                              self.meta.get("min_structure", DEFAULT_MIN_STRUCTURE)))
        # `enforce_threshold` is read by the harness (_try_load_detector) — keep the name.
        self.enforce_threshold = float(_env_float("WAF_ML_ENFORCE_THRESHOLD",
                                                  self.meta.get("enforce_threshold", DEFAULT_ENFORCE_PROB)))
        # Shadow by default. Measured enforcement readiness is a deliberate decision, not a default:
        # set WAF_GCID_ENFORCE=true only once the harness --gate-ml passes on production traffic.
        self.enforce_enabled = os.environ.get("WAF_GCID_ENFORCE", "").strip().lower() in ("1", "true", "yes")
        self.mal_t = conformal_threshold(self.calibration, self.alpha)
        self.model_version = f"gcid:a{self.alpha}"
        self.loaded = True
        logger.info("GCID detector loaded (alpha=%s, calib n=%d, contract %s) — %s",
                    self.alpha, len(self.calibration),
                    "verified" if self.contract_verified else "UNVERIFIED",
                    "ENFORCING" if self.enforce_enabled else "shadow")

    # ---------------------------------------------------------------- scoring
    def p_value(self, score: float) -> float:
        """Conformal p-value of an attack score against the benign calibration set."""
        return float(self._conformal_pvalues(self.calibration,
                                             np.array([score], dtype=np.float64))[0])

    def explain(self, method: str = "GET", path: str = "", query: str = "", body: str = "",
                headers: Optional[Dict[str, str]] = None) -> Dict[str, float]:
        """Which grammar(s) the value carries structure in — the human-readable reason."""
        return {g: round(s, 3) for g, s in
                grammar_scores(method, path, query, body, headers).items() if s > 0}

    def predict(self, method: str = "GET", path: str = "", query: str = "",
                body: str = "", headers: Optional[Dict[str, str]] = None) -> MLResult:
        x = structure_vector(method, path, query, body, headers).reshape(1, -1)
        mal_prob = float(self.clf.predict_proba(x)[0, 1])
        p = self.p_value(mal_prob)
        struct_max = float(x[0, _MAX_I])
        hit = (p < self.alpha) and (struct_max >= self.min_structure)

        scores = {g: float(x[0, i]) for i, g in enumerate(GRAMMAR_NAMES)}
        top = max(scores, key=scores.get) if scores else "injection"
        category = f"injection:{top}" if hit and scores[top] > 0 else ("attack" if hit else "benign")

        enforce, why = False, ""
        if not hit:
            why = (f"benign (conformal p={p:.5f}, structure {struct_max:.2f} < "
                   f"{self.min_structure}: no interpreter grammar in any field)")
        elif not self.enforce_enabled:
            why = "GCID shadow (WAF_GCID_ENFORCE not set)"
        elif not self.contract_verified:
            why = "contract unverified — shadow only"
        elif p < self.enforce_alpha and mal_prob >= self.enforce_threshold:
            enforce, why = True, f"conformal p={p:.5f} < {self.enforce_alpha} and prob {mal_prob:.3f}"
        else:
            why = f"below enforcement budget (p={p:.5f}, prob={mal_prob:.3f}) — shadow only"

        return MLResult(
            is_malicious=bool(hit), mal_prob=round(mal_prob, 4),
            # `novelty` carries the conformal p-value here: lower = more surely not benign.
            novelty=round(p, 6), category=category,
            is_zero_day=bool(hit and mal_prob < self.enforce_threshold),
            route="grammar-conformance" if hit else "none",
            enforce=enforce, enforce_reason=why,
            contract_verified=self.contract_verified, model_version=self.model_version)


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        logger.warning("ignoring non-numeric %s=%r", name, raw)
        return float(default)


def _eval(alpha: Optional[float] = None) -> None:
    """Report the persisted model's numbers on data it was not fit on."""
    det = GcidDetector(alpha=alpha)
    print(f"GCID @alpha={det.alpha} (calib n={len(det.calibration)}, "
          f"contract {'verified' if det.contract_verified else 'UNVERIFIED'})")
    print(json.dumps(det.meta.get("heldout", {}), indent=2))
    try:
        from data_pipeline.modern_benign import generate as gen_benign
        recs = gen_benign(500, seed=999)      # a seed never used in training
        fp = [r for r in recs if det.predict(*r).is_malicious]
        print(f"  fresh modern benign (seed 999): FP {len(fp)}/{len(recs)} = {len(fp)/len(recs)*100:.2f}%")
        for r in fp[:5]:
            print(f"    FP {r[0]} {r[1]} q={r[2][:60]!r} b={r[3][:60]!r} -> {det.explain(*r)}")
    except Exception as e:
        print(f"  modern benign unavailable: {e}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GCID — grammar-conformance injection detection")
    ap.add_argument("--train", action="store_true", help="fit + calibrate + persist the model")
    ap.add_argument("--eval", action="store_true", help="report metrics from the persisted model")
    ap.add_argument("--alpha", type=float, default=None, help="conformal false-alarm budget")
    args = ap.parse_args(argv)
    if args.train:
        train(alpha=args.alpha if args.alpha is not None else DEFAULT_ALPHA)
    if args.eval or not args.train:
        _eval(alpha=args.alpha)
    return 0


if __name__ == "__main__":
    sys.exit(main())
