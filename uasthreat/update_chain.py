"""A secure update chain of trust, modelled to show the decisions, not to be deployed.

Real devices verify **asymmetric** signatures: the device holds only a public
key (or its hash, burned into one-time-programmable fuses), so extracting it
from a captured airframe does not let anyone sign firmware. The Python standard
library has no public-key signatures, so `HmacDemoVerifier` stands in behind a
`Verifier` interface. Swap in an Ed25519 or ECDSA verifier and every decision
below stays the same.

Decisions made at every stage:

1. Is the manifest authentic? (signature by a key that chains to the root)
2. Does the image match the manifest? (digest)
3. Is it for this component? (no cross-flashing a payload image onto the autopilot)
4. Is it not older than what is allowed? (anti-rollback security version, monotonic)
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Protocol, Tuple


@dataclass(frozen=True)
class Manifest:
    component: str
    version: str
    security_version: int
    digest: str

    def canonical(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class SignedManifest:
    manifest: Manifest
    signature: str


class Verifier(Protocol):
    def verify(self, message: bytes, signature: str) -> bool: ...


class HmacDemoVerifier:
    """Symmetric stand-in for a public-key verifier. Demonstration only (see module docstring)."""

    def __init__(self, key: bytes):
        self._key = key

    def sign(self, message: bytes) -> str:
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


def digest(image: bytes) -> str:
    return hashlib.sha256(image).hexdigest()


def make_signed_manifest(signer: HmacDemoVerifier, component: str, version: str, security_version: int, image: bytes) -> SignedManifest:
    m = Manifest(component, version, security_version, digest(image))
    return SignedManifest(m, signer.sign(m.canonical()))


@dataclass(frozen=True)
class Decision:
    component: str
    accepted: bool
    reason: str


@dataclass
class Device:
    """Holds the root verifier and the anti-rollback counters (think: fuses or protected storage)."""

    root: Verifier
    min_security_version: Dict[str, int] = field(default_factory=dict)

    def check(self, component: str, image: bytes, sm: SignedManifest) -> Decision:
        if not self.root.verify(sm.manifest.canonical(), sm.signature):
            return Decision(component, False, "manifest signature invalid")
        if sm.manifest.component != component:
            return Decision(component, False, f"manifest is for {sm.manifest.component!r}, not {component!r}")
        if digest(image) != sm.manifest.digest:
            return Decision(component, False, "image does not match manifest digest")
        floor = self.min_security_version.get(component, 0)
        if sm.manifest.security_version < floor:
            return Decision(component, False, f"rollback: security version {sm.manifest.security_version} < {floor}")
        return Decision(component, True, "ok")

    def install(self, component: str, image: bytes, sm: SignedManifest) -> Decision:
        """Verify, then raise the anti-rollback floor only after success."""
        d = self.check(component, image, sm)
        if d.accepted:
            self.min_security_version[component] = max(self.min_security_version.get(component, 0), sm.manifest.security_version)
        return d

    def boot(self, chain: List[Tuple[str, bytes, SignedManifest]]) -> List[Decision]:
        """Verify each stage in order; stop at the first failure (nothing after it runs)."""
        out = []
        for component, image, sm in chain:
            d = self.check(component, image, sm)
            out.append(d)
            if not d.accepted:
                break
        return out
