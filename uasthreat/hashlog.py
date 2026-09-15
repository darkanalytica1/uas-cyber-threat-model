"""Tamper-evident, hash-chained event log.

Each entry commits to the previous one:

    hash_i = SHA-256( canonical_json({index, ts, event, prev}) ),  prev = hash_{i-1}

Editing, deleting or reordering any entry breaks every link after it. A chain
on its own does not stop someone with write access from rewriting the whole
log and recomputing every hash, so the head is periodically **anchored**:
authenticated with a key the log writer does not hold, or copied to an
append-only store elsewhere. The anchor is what turns "consistent" into
"unaltered since the anchor".
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(index: int, ts: float, event: Dict[str, Any], prev: str) -> str:
    return hashlib.sha256(_canonical({"index": index, "ts": ts, "event": event, "prev": prev})).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    first_bad_index: Optional[int] = None
    reason: str = "ok"


@dataclass(frozen=True)
class Anchor:
    count: int
    head: str
    tag: str


class HashChainLog:
    def __init__(self, entries: Optional[List[Dict[str, Any]]] = None):
        self.entries: List[Dict[str, Any]] = [dict(e) for e in (entries or [])]

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, event: Dict[str, Any], ts: Optional[float] = None) -> Dict[str, Any]:
        index = len(self.entries)
        ts = round(time.time(), 6) if ts is None else ts
        prev = self.head
        entry = {"index": index, "ts": ts, "event": event, "prev": prev, "hash": entry_hash(index, ts, event, prev)}
        self.entries.append(entry)
        return entry

    def verify(self) -> VerifyResult:
        prev = GENESIS
        last_ts = float("-inf")
        for i, e in enumerate(self.entries):
            if e.get("index") != i:
                return VerifyResult(False, i, "index gap or reordering")
            if e.get("prev") != prev:
                return VerifyResult(False, i, "broken link to previous entry")
            if entry_hash(e["index"], e["ts"], e["event"], e["prev"]) != e.get("hash"):
                return VerifyResult(False, i, "entry content does not match its hash")
            if e["ts"] < last_ts:
                return VerifyResult(False, i, "timestamp goes backwards")
            prev, last_ts = e["hash"], e["ts"]
        return VerifyResult(True)

    # anchoring ---------------------------------------------------------------

    def anchor(self, key: bytes) -> Anchor:
        """Authenticate (count, head) with a key held outside the logging system."""
        msg = f"{len(self.entries)}:{self.head}".encode()
        return Anchor(len(self.entries), self.head, hmac.new(key, msg, hashlib.sha256).hexdigest())

    def verify_against_anchor(self, anchor: Anchor, key: bytes) -> VerifyResult:
        expected = hmac.new(key, f"{anchor.count}:{anchor.head}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, anchor.tag):
            return VerifyResult(False, None, "anchor itself is not authentic")
        chain = self.verify()
        if not chain.ok:
            return chain
        if len(self.entries) < anchor.count:
            return VerifyResult(False, len(self.entries), "log truncated below the anchored length")
        if anchor.count and self.entries[anchor.count - 1]["hash"] != anchor.head:
            return VerifyResult(False, anchor.count - 1, "history rewritten before the anchor")
        return VerifyResult(True)

    # persistence -------------------------------------------------------------

    def to_jsonl(self) -> str:
        return "".join(json.dumps(e, sort_keys=True, ensure_ascii=False) + "\n" for e in self.entries)

    @classmethod
    def from_jsonl(cls, text: str) -> "HashChainLog":
        return cls([json.loads(line) for line in text.splitlines() if line.strip()])
