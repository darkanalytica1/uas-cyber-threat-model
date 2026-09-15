"""uasthreat: a defensive, educational threat model toolkit for small unmanned aircraft systems."""
from .hashlog import Anchor, HashChainLog, VerifyResult
from .model import STRIDE_ORDER, ThreatModel, from_dict, load
from .render import to_html, to_markdown
from .signing import SigningVerifier, build_frame, expected_attempts, expected_years, forgery_probability, sign
from .update_chain import Device, HmacDemoVerifier, Manifest, SignedManifest, make_signed_manifest

__all__ = [
    "Anchor", "HashChainLog", "VerifyResult", "STRIDE_ORDER", "ThreatModel", "from_dict", "load",
    "to_html", "to_markdown", "SigningVerifier", "build_frame", "expected_attempts", "expected_years",
    "forgery_probability", "sign", "Device", "HmacDemoVerifier", "Manifest", "SignedManifest",
    "make_signed_manifest",
]
__version__ = "0.1.0"
