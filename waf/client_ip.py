"""
Trusted client-IP resolution — the WAF's own trust boundary.

THE VULNERABILITY THIS FIXES (measured, not theoretical):
    def _client_ip():
        xff = request.headers.get("X-Forwarded-For", "")
        return xff.split(",")[0].strip() if xff else request.remote_addr

`X-Forwarded-For` is an ATTACKER-CONTROLLED REQUEST HEADER. Anyone can send any value.
Taking the LEFTMOST entry means the attacker picks their own identity. Measured against
the WAF before this fix: 150 requests with a rotating fake XFF -> 150 allowed, 0 throttled,
against a 120/10s limit. The same 150 requests without the header -> 30 correctly throttled.

Every per-client control collapses with it:
  * rate limiting            — infinite budget by rotating the header
  * IP reputation escalation — and you can frame an innocent IP by forging theirs
  * poison-guard per-source cap — rotate fake source IPs to smuggle a poisoned batch past
                                  MAX_PER_SOURCE
  * honeypot attribution, metrics, alerts — all report the attacker's chosen value

THE FIX — rightmost-untrusted, with an explicit trusted-proxy allowlist:
  * If the immediate peer (the TCP source, which cannot be forged over an established
    connection) is NOT a configured trusted proxy, ignore XFF entirely and use the peer.
    That is the secure default: no config -> no header trust.
  * If the peer IS a trusted proxy, walk XFF RIGHT-TO-LEFT and return the first address
    that is not itself a trusted proxy. The right end is appended by infrastructure you
    control; the left end is whatever the client sent, so the left end is never authoritative.

Config:
    TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12   # your LB / ingress / CDN egress ranges
Unset means "trust nothing", which is correct for a WAF exposed directly.
"""
from __future__ import annotations
import ipaddress, logging, os
from typing import List, Optional, Sequence

log = logging.getLogger("waf.client_ip")


def parse_networks(spec: str) -> List[ipaddress._BaseNetwork]:
    nets = []
    for raw in (spec or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            log.error("TRUSTED_PROXIES: ignoring invalid entry %r", raw[:60])
    return nets


def _ip(val: str) -> Optional[ipaddress._BaseAddress]:
    val = (val or "").strip()
    if not val:
        return None
    # strip an IPv6 bracket form and any :port suffix on IPv4
    if val.startswith("["):
        val = val[1:].split("]")[0]
    elif val.count(":") == 1 and "." in val:
        val = val.split(":")[0]
    try:
        return ipaddress.ip_address(val)
    except ValueError:
        return None


def _trusted(addr: Optional[ipaddress._BaseAddress], nets: Sequence) -> bool:
    return bool(addr) and any(addr in n for n in nets)


def resolve_client_ip(remote_addr: str, xff_header: str,
                      trusted: Sequence, real_ip_header: str = "") -> str:
    """
    remote_addr : the TCP peer (Flask's request.remote_addr) — forgeable only by
                  controlling the network path, so it is the root of trust.
    xff_header  : raw X-Forwarded-For value (attacker-influenced).
    trusted     : networks from parse_networks(TRUSTED_PROXIES).
    """
    peer = _ip(remote_addr)
    if not trusted or not _trusted(peer, trusted):
        # Peer is not a proxy we trust => the header is unauthenticated. Ignore it.
        return str(peer) if peer else (remote_addr or "unknown")

    # Peer IS a trusted proxy: the rightmost entries were appended by our own infra.
    chain = [_ip(p) for p in (xff_header or "").split(",")]
    for addr in reversed(chain):
        if addr and not _trusted(addr, trusted):
            return str(addr)          # first non-proxy from the right = real client
    if real_ip_header:
        a = _ip(real_ip_header)
        if a and not _trusted(a, trusted):
            return str(a)
    # Whole chain was trusted proxies (or empty) — fall back to the peer.
    return str(peer) if peer else "unknown"


class ClientIPResolver:
    def __init__(self, trusted_spec: Optional[str] = None):
        spec = trusted_spec if trusted_spec is not None else os.environ.get("TRUSTED_PROXIES", "")
        self.networks = parse_networks(spec)
        if self.networks:
            log.info("client IP: trusting X-Forwarded-For from %d proxy network(s)", len(self.networks))
        else:
            log.warning("client IP: TRUSTED_PROXIES unset — X-Forwarded-For is IGNORED and the "
                        "TCP peer is used. Correct when the WAF is directly exposed; if you run "
                        "behind a load balancer you MUST set TRUSTED_PROXIES or every client will "
                        "look like the LB (one shared rate-limit bucket).")

    def resolve(self, remote_addr: str, xff: str, real_ip: str = "") -> str:
        return resolve_client_ip(remote_addr, xff, self.networks, real_ip)
