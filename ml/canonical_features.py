"""
Canonical feature contract — THE single source of truth for train and serve.

The whole reason the previous ML was broken: `ml/dataset_loader.HTTPFeatureExtractor`
(training) and `ml/secure_inference.SafeFeatureExtractor` (serving) computed
DIFFERENT 50-dim vectors, and serving never applied the scaler. The model was
fed out-of-distribution garbage and collapsed to a constant 0.992.

Fix: exactly one extractor, imported by both the trainer (ml/train_v2.py) and the
detector (ml/detector_v2.py). If this file changes, both sides change together, so
skew is structurally impossible.

Two outputs from the same raw request:
  - lexical_features(...) -> np.float32[N_LEXICAL]  (interpretable, fast, for GBDT/energy)
  - byte_sequence(...)    -> np.int64[SEQ_LEN]        (0..256, for the byte-CNN research model)

Design goals: deterministic, dependency-light (numpy only), < 0.25 ms per call.
"""
from __future__ import annotations
import math
import re
from collections import Counter
from typing import Dict, List, Optional
import numpy as np

# ---- vocabularies -----------------------------------------------------------
SQL_KEYWORDS = ("select", "union", "insert", "update", "delete", "drop", "create",
                "exec", "execute", "declare", "cast", "convert", "from", "where",
                "or", "and", "sleep", "benchmark", "waitfor", "load_file", "outfile",
                "information_schema", "sysobjects", "pg_sleep", "extractvalue", "updatexml")
XSS_TAGS = ("script", "img", "svg", "iframe", "object", "embed", "video", "audio",
            "body", "input", "form", "style", "marquee", "details", "onerror",
            "onload", "onclick", "onmouseover", "onfocus", "ontoggle", "onstart")
JS_SINKS = ("javascript:", "eval(", "alert(", "prompt(", "document.cookie",
            "document.location", "window.location", "settimeout", "fromcharcode", "atob(")
RCE_TOKENS = ("/bin/bash", "/bin/sh", "sh -c", "cmd.exe", "powershell", "system(",
              "exec(", "passthru", "shell_exec", "popen", "subprocess", "processbuilder",
              "wget ", "curl ", "nc ", "ncat ", "$(", "`", "${", ";id", "|id", "&&")
TRAVERSAL = ("../", "..\\", "..%2f", "..%5c", "%2e%2e", "/etc/passwd", "/etc/shadow",
             "win.ini", "boot.ini", "c:\\", "file://")
SSRF_TOKENS = ("169.254.169.254", "metadata.google", "localhost", "127.0.0.1", "0.0.0.0",
               "http://", "https://", "gopher://", "dict://", "ftp://")
TEMPLATE = ("${", "#{", "{{", "%{", "<%", "t(", "freemarker", "velocity", "jndi:",
            "ldap://", "rmi://", "dns://")
NOSQL = ("$gt", "$lt", "$ne", "$where", "$regex", "$exists", "$in", "$nin", "mapreduce")
ENCODING = ("%25", "%2527", "\\x", "\\u", "&#x", "&#", "char(", "chr(", "0x", "base64")

_word_re = re.compile(r"[A-Za-z0-9_]+")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _ratios(s: str) -> Dict[str, float]:
    if not s:
        return dict(special=0.0, upper=0.0, digit=0.0, space=0.0, non_ascii=0.0, punct=0.0, letter=0.0)
    n = len(s)
    special = sum(1 for c in s if not c.isalnum() and not c.isspace())
    upper = sum(1 for c in s if c.isupper())
    digit = sum(1 for c in s if c.isdigit())
    space = sum(1 for c in s if c.isspace())
    non_ascii = sum(1 for c in s if ord(c) > 127)
    punct = sum(1 for c in s if c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
    letter = sum(1 for c in s if c.isalpha())
    return dict(special=special / n, upper=upper / n, digit=digit / n, space=space / n,
                non_ascii=non_ascii / n, punct=punct / n, letter=letter / n)


def _count_any(hay: str, needles) -> int:
    return sum(hay.count(t) for t in needles)


# Ordered feature names — the contract. Changing order = retrain both sides.
LEXICAL_FEATURE_NAMES: List[str] = [
    # lengths (5)
    "len_total", "len_path", "len_query", "len_body", "len_headers",
    # entropy per region (4)
    "ent_total", "ent_path", "ent_query", "ent_body",
    # char-class ratios on combined (7)
    "r_special", "r_upper", "r_digit", "r_space", "r_nonascii", "r_punct", "r_letter",
    # security-lexical family counts (10)
    "c_sql", "c_xss", "c_jssink", "c_rce", "c_traversal", "c_ssrf", "c_template", "c_nosql",
    "c_encoding", "c_comment",
    # specific char signals (12)
    "n_quote", "n_dquote", "n_angle", "n_semicolon", "n_pipe", "n_backtick",
    "n_paren", "n_brace", "n_bracket", "n_percent", "n_equals", "n_dollar",
    # structure / tokens (8)
    "param_count", "max_param_len", "avg_param_len", "dup_param",
    "word_count", "max_word_len", "avg_word_len", "char_diversity",
    # n-gram novelty (2)
    "bigram_uniq", "trigram_uniq",
    # encoding depth (2)
    "url_decode_layers", "hex_unicode_hits",
]
N_LEXICAL = len(LEXICAL_FEATURE_NAMES)
SEQ_LEN = 256  # byte-CNN input length


def _url_decode_layers(s: str, max_layers: int = 4) -> int:
    """How many times %XX-decoding changes the string (obfuscation depth)."""
    try:
        from urllib.parse import unquote
    except Exception:
        return 0
    layers = 0
    cur = s
    for _ in range(max_layers):
        dec = unquote(cur)
        if dec == cur:
            break
        layers += 1
        cur = dec
    return layers


def lexical_features(method: str = "GET", path: str = "", query: str = "",
                     body: str = "", headers: Optional[Dict[str, str]] = None) -> np.ndarray:
    headers = headers or {}
    path, query, body = str(path), str(query), str(body)
    header_blob = " ".join(f"{k}:{v}" for k, v in headers.items())
    combined = f"{path} {query} {body}".lower()
    low_raw = f"{path} {query} {body} {header_blob}".lower()

    r = _ratios(combined)
    params = [p for p in query.split("&") if p]
    param_lens = [len(p) for p in params]
    words = _word_re.findall(combined)
    word_lens = [len(w) for w in words]
    bigrams = {combined[i:i + 2] for i in range(len(combined) - 1)}
    trigrams = {combined[i:i + 3] for i in range(len(combined) - 2)}

    f: List[float] = [
        len(combined), len(path), len(query), len(body), len(header_blob),
        _entropy(combined), _entropy(path), _entropy(query), _entropy(body),
        r["special"], r["upper"], r["digit"], r["space"], r["non_ascii"], r["punct"], r["letter"],
        _count_any(low_raw, SQL_KEYWORDS), _count_any(low_raw, XSS_TAGS), _count_any(low_raw, JS_SINKS),
        _count_any(low_raw, RCE_TOKENS), _count_any(low_raw, TRAVERSAL), _count_any(low_raw, SSRF_TOKENS),
        _count_any(low_raw, TEMPLATE), _count_any(low_raw, NOSQL), _count_any(low_raw, ENCODING),
        low_raw.count("--") + low_raw.count("/*") + low_raw.count("#"),
        combined.count("'"), combined.count('"'), combined.count("<") + combined.count(">"),
        combined.count(";"), combined.count("|"), combined.count("`"),
        combined.count("(") + combined.count(")"), combined.count("{") + combined.count("}"),
        combined.count("[") + combined.count("]"), combined.count("%"),
        combined.count("="), combined.count("$"),
        len(params), (max(param_lens) if param_lens else 0),
        (sum(param_lens) / len(param_lens) if param_lens else 0.0),
        (len(params) - len({p.split("=", 1)[0] for p in params}) if params else 0),
        len(words), (max(word_lens) if word_lens else 0),
        (sum(word_lens) / len(word_lens) if word_lens else 0.0),
        (len(set(combined)) / len(combined) if combined else 0.0),
        (len(bigrams) / max(len(combined) - 1, 1)), (len(trigrams) / max(len(combined) - 2, 1)),
        _url_decode_layers(query + body),
        low_raw.count("\\x") + low_raw.count("\\u") + low_raw.count("&#x"),
    ]
    assert len(f) == N_LEXICAL, f"feature count drift: {len(f)} != {N_LEXICAL}"
    return np.array(f, dtype=np.float32)


def byte_sequence(method: str = "GET", path: str = "", query: str = "",
                  body: str = "", headers: Optional[Dict[str, str]] = None,
                  seq_len: int = SEQ_LEN) -> np.ndarray:
    """Byte-level encoding for the CNN branch. 0 = pad, 1..256 = byte+1."""
    raw = f"{method} {path}?{query} {body}"
    b = raw.encode("utf-8", "ignore")[:seq_len]
    arr = np.zeros(seq_len, dtype=np.int64)
    for i, byte in enumerate(b):
        arr[i] = byte + 1
    return arr
