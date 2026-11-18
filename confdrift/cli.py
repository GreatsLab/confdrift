"""confdrift - diff two IOS configs the way a network engineer reads them."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict

from . import __version__
from .risk import SEVERITY_ORDER, assess, redact
from .tree import diff, parse

COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def col(s, code):
    return f"\033[{code}m{s}\033[0m" if COLOR else s


SEV = {"high": "1;31", "medium": "33", "low": "36"}
OPS = {"add": ("+", "32"), "remove": ("-", "31"), "reorder": ("~", "35")}


def load(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as e:
        sys.exit(f"confdrift: {e}")


def hostname(text, fallback):
    for line in text.splitlines():
        if line.startswith("hostname "):
            return line.split(None, 1)[1].strip()
    return fallback


def main(argv=None):
    ap = argparse.ArgumentParser(prog="confdrift", description=__doc__)
    ap.add_argument("old", help="config before (file)")
    ap.add_argument("new", help="config after (file)")
    ap.add_argument("--json", action="store_true", help="machine readable output")
    ap.add_argument("--risk-only", action="store_true", help="only print the risk section")
    ap.add_argument("--show-secrets", action="store_true", help="don't redact passwords/keys")
    ap.add_argument("--fail-on", choices=["high", "medium", "low", "any"],
                    help="exit 3 if a finding at this level (or worse) exists. 'any' = any change at all")
    ap.add_argument("--version", action="version", version=f"confdrift {__version__}")
    a = ap.parse_args(argv)

    old_txt, new_txt = load(a.old), load(a.new)
    changes = diff(parse(old_txt), parse(new_txt))
    risks = assess(changes)
    show = (lambda s: s) if a.show_secrets else redact

    if a.json:
        print(json.dumps({
            "old": a.old, "new": a.new,
            "summary": _summary(changes),
            "risks": [{"severity": r.severity, "why": r.why, "op": c.op,
                       "section": " > ".join(c.path), "line": show(c.line)} for c, r in risks],
            "changes": [{"op": c.op, "path": list(c.path), "line": show(c.line),
                         "lineno": c.lineno} for c in changes],
        }, indent=2))
    else:
        _print_text(a, old_txt, new_txt, changes, risks, show)

    return _exit_code(a.fail_on, changes, risks)


def _summary(changes):
    s = {"added": 0, "removed": 0, "reordered": 0}
    for c in changes:
        s[{"add": "added", "remove": "removed", "reorder": "reordered"}[c.op]] += 1
    s["sections"] = len({c.section or c.line for c in changes})
    return s


def _print_text(a, old_txt, new_txt, changes, risks, show):
    h_old, h_new = hostname(old_txt, a.old), hostname(new_txt, a.new)
    title = h_old if h_old == h_new else f"{h_old} -> {h_new}"
    s = _summary(changes)
    print(col(f"confdrift: {title}", "1"))
    if not changes:
        print("  no semantic differences")
        return
    print(f"  {s['added']} added, {s['removed']} removed, {s['reordered']} reordered "
          f"across {s['sections']} section(s)\n")

    if risks:
        print(col("RISK", "1"))
        for c, r in risks:
            where = " > ".join(c.path) or "global"
            sym, cc = OPS[c.op]
            print(f"  {col(r.severity.upper().ljust(6), SEV[r.severity])} {where}: {r.why}")
            if c.op != "reorder":
                print(f"         {col(sym + ' ' + show(c.line), cc)}")
        print()
    elif not a.risk_only:
        print(col("RISK", "1") + "\n  nothing on the risk list\n")

    if a.risk_only:
        return

    print(col("CHANGES", "1"))
    groups: "OrderedDict[tuple, list]" = OrderedDict()
    for c in changes:
        groups.setdefault(c.path, []).append(c)
    for path, items in groups.items():
        if path:
            for depth, p in enumerate(path):
                print("  " * depth + col(show(p), "2"))
        indent = "  " * len(path)
        for c in items:
            sym, cc = OPS[c.op]
            text = "(lines re-ordered)" if c.op == "reorder" else show(c.line)
            print(f"{indent}{col(sym + ' ' + text, cc)}")
        print()


def _exit_code(fail_on, changes, risks):
    if not fail_on:
        return 0
    if fail_on == "any":
        return 3 if changes else 0
    limit = SEVERITY_ORDER[fail_on]
    return 3 if any(SEVERITY_ORDER[r.severity] <= limit for _, r in risks) else 0


if __name__ == "__main__":
    sys.exit(main())
