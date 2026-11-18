"""Rules that turn a plain diff line into "you probably want to look at this".

Each rule: which op it fires on, regex on the changed line, optional regex
on the section (top-level parent), severity and a message. Kept as plain
data so adding one is a 1-line PR.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .tree import Change


@dataclass(frozen=True)
class RiskRule:
    op: str                 # add | remove | reorder | any
    line: str               # regex on the changed line
    section: str = ""       # regex on the top-level section ("" = any, "^$" = global)
    severity: str = "medium"
    why: str = ""

    def hits(self, ch: Change) -> bool:
        if self.op != "any" and self.op != ch.op:
            return False
        if not re.search(self.line, ch.line):
            return False
        if self.section:
            sec = ch.path[0] if ch.path else ""
            if not re.search(self.section, sec):
                return False
        return True


RULES = [
    # --- things that drop traffic or lock you out ---
    RiskRule("add", r"^shutdown$", r"^interface ", "high", "interface will go down"),
    RiskRule("remove", r"^no shutdown$", r"^interface ", "high", "interface may go down"),
    RiskRule("remove", r"^ip address \d", r"^interface ", "high", "interface loses its IP address"),
    RiskRule("add", r"^ip address \d", r"^interface ", "medium", "interface IP changed/added"),
    RiskRule("remove", r"^ip access-group ", r"^interface ", "high", "ACL removed from interface - traffic is no longer filtered"),
    RiskRule("add", r"^ip access-group ", r"^interface ", "medium", "ACL applied to interface - check it doesn't block your own session"),
    RiskRule("remove", r"^switchport trunk allowed vlan", r"^interface ", "high", "trunk allowed list removed (defaults to ALL vlans)"),
    RiskRule("add", r"^switchport trunk allowed vlan(?! add)", r"^interface ", "high", "trunk allowed list replaced - vlans not listed will be pruned"),
    RiskRule("any", r"^access-class ", r"^line vty", "high", "VTY access-class changed - you can lock yourself out"),
    RiskRule("reorder", r"", r"access-list|route-map", "high", "entries re-ordered; first match wins, so behaviour changed"),

    # --- routing ---
    RiskRule("remove", r"^neighbor \S+ remote-as", r"^router bgp", "high", "BGP neighbour removed"),
    RiskRule("add", r"^neighbor \S+ shutdown", r"^router bgp", "high", "BGP neighbour shut down"),
    RiskRule("any", r"^neighbor \S+ (route-map|prefix-list|filter-list) ", r"^router bgp", "high", "BGP policy on a neighbour changed"),
    RiskRule("any", r"^network ", r"^router (bgp|ospf|eigrp)", "medium", "advertised networks changed"),
    RiskRule("any", r"^ip route 0\.0\.0\.0 0\.0\.0\.0", "^$", "high", "default route changed"),
    RiskRule("remove", r"^ip route ", "^$", "medium", "static route removed"),
    RiskRule("any", r"^(passive-interface|area \S+ )", r"^router ospf", "medium", "OSPF adjacency behaviour changed"),
    RiskRule("any", r"^ip prefix-list ", "^$", "medium", "prefix-list changed"),

    # --- security posture ---
    RiskRule("add", r"^snmp-server community (public|private)\b", "^$", "high", "default SNMP community"),
    RiskRule("add", r"^snmp-server community \S+ RW", "^$", "high", "read-write SNMP community"),
    RiskRule("add", r"^enable password ", "^$", "high", "'enable password' is reversible, use 'enable secret'"),
    RiskRule("remove", r"^enable secret ", "^$", "high", "enable secret removed"),
    RiskRule("remove", r"^service password-encryption$", "^$", "medium", "password encryption turned off"),
    RiskRule("add", r"^transport input (telnet|all)", r"^line vty", "high", "telnet allowed on VTY"),
    RiskRule("add", r"^ip http server$", "^$", "medium", "HTTP server enabled"),
    RiskRule("remove", r"^aaa ", "^$", "high", "AAA config removed"),
    RiskRule("remove", r"^(logging host|logging \d)", "^$", "medium", "syslog destination removed"),
    RiskRule("add", r"^no logging ", "^$", "medium", "logging disabled"),
    RiskRule("add", r"^username \S+ (privilege 15 )?password ", "^$", "high", "local user with reversible password"),
    RiskRule("remove", r"^spanning-tree (bpduguard|guard root)", r"^interface ", "medium", "STP protection removed from port"),
]

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def assess(changes: list) -> list:
    """Return [(change, rule)] for every change that trips a rule."""
    out = []
    for ch in changes:
        for rule in RULES:
            if rule.hits(ch):
                out.append((ch, rule))
                break
    out.sort(key=lambda x: SEVERITY_ORDER[x[1].severity])
    return out


_SECRET = re.compile(r"\b(secret|password|key|community|key-string)(\s+\d)?\s+(\S+)")


def redact(line: str) -> str:
    """Hide secrets so diffs can go in a ticket / chat safely."""
    def sub(m):
        kind, enc = m.group(1), m.group(2) or ""
        return f"{kind}{enc} <redacted>"
    return _SECRET.sub(sub, line)
