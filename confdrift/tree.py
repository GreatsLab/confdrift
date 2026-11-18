"""Turn an IOS-style config into a tree and diff two trees.

IOS config is a tree hidden in indentation:

    interface Gi0/1          <- parent
     description uplink      <- child
     ip address 10.0.0.1 255.255.255.252

Text diff tools don't know that, so moving a block or re-ordering
`show run` output gives you a wall of red/green. Here we diff by path:
`interface Gi0/1 > ip address ...` either exists in both configs or it
doesn't.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# lines that change on every save and mean nothing
NOISE = [
    re.compile(r"^Building configuration"),
    re.compile(r"^Current configuration\s*:"),
    re.compile(r"^! (Last configuration change|NVRAM config last updated)"),
    re.compile(r"^!Time:"),
    re.compile(r"^ntp clock-period"),
    re.compile(r"^end$"),
]

# sections where line order is meaningful - first match wins on the box,
# so a re-order is a real change
ORDERED_SECTIONS = [
    re.compile(r"^ip access-list "),
    re.compile(r"^ipv6 access-list "),
    re.compile(r"^route-map "),
    re.compile(r"^class-map "),
    re.compile(r"^policy-map "),
]

# collapse certificate hex dumps into one line, nobody reviews those by eye
CERT_START = re.compile(r"^\s*certificate( ca)? \S+")


@dataclass
class Node:
    text: str
    children: dict = field(default_factory=dict)   # text -> Node, insertion ordered
    lineno: int = 0

    @property
    def ordered(self) -> bool:
        return any(p.match(self.text) for p in ORDERED_SECTIONS)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse(text: str) -> Node:
    root = Node("<root>")
    stack: list[tuple[int, Node]] = [(-1, root)]
    in_cert = None

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip().replace("\t", " ")
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            # bang lines are separators/comments, IOS doesn't keep them
            continue
        if any(p.match(stripped) for p in NOISE):
            continue

        ind = _indent(line)

        if in_cert is not None:
            if stripped == "quit":
                in_cert = None
                continue
            if ind > in_cert[0]:
                in_cert[1].append(stripped)
                continue
            in_cert = None

        while stack and stack[-1][0] >= ind:
            stack.pop()
        parent = stack[-1][1]

        if CERT_START.match(line):
            node = Node(stripped, lineno=lineno)
            hexlines: list = []
            in_cert = (ind, hexlines)
            node.children["<certificate body>"] = Node("<certificate body>", lineno=lineno)
            parent.children[stripped] = node
            continue

        node = parent.children.get(stripped)
        if node is None:
            node = Node(stripped, lineno=lineno)
            parent.children[stripped] = node
        stack.append((ind, node))
    return root


@dataclass
class Change:
    op: str            # add | remove | reorder
    path: tuple        # parents, outermost first
    line: str
    lineno: int        # in the file it came from (new file for add, old for remove)

    @property
    def section(self) -> str:
        return self.path[0] if self.path else ""


def diff(old: Node, new: Node, path: tuple = ()) -> list:
    changes: list[Change] = []
    old_keys = list(old.children)
    new_keys = list(new.children)
    old_set, new_set = set(old_keys), set(new_keys)

    for k in old_keys:
        if k not in new_set:
            _collect(old.children[k], path, "remove", changes)
    for k in new_keys:
        if k not in old_set:
            _collect(new.children[k], path, "add", changes)
        else:
            changes.extend(diff(old.children[k], new.children[k], path + (k,)))

    if (old.ordered or new.ordered) and not changes_under(changes, path):
        common_old = [k for k in old_keys if k in new_set]
        common_new = [k for k in new_keys if k in old_set]
        if common_old != common_new:
            changes.append(Change("reorder", path, old.text, new.lineno))
    return changes


def changes_under(changes, path) -> bool:
    return any(c.path[:len(path)] == path and c.op != "reorder" for c in changes)


def _collect(node: Node, path: tuple, op: str, out: list):
    out.append(Change(op, path, node.text, node.lineno))
    for child in node.children.values():
        _collect(child, path + (node.text,), op, out)
