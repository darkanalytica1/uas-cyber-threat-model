"""python -m uasthreat <command>

    validate                 check the model is complete and consistent
    render                   write docs/MATRIX.md and docs/matrix.html from the YAML
    forgery                  blind-forgery arithmetic for a truncated tag
    signing-demo             sign and verify MAVLink 2 frames, show what is rejected and why
    log-demo                 build a hash-chained log, tamper with it, detect it
    update-demo              walk a secure update chain: valid, altered, rollback, wrong component
"""
from __future__ import annotations

import argparse
import os
import sys

from . import hashlog, signing, update_chain
from .model import load
from .render import to_html, to_markdown

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_YAML = os.path.join(HERE, "data", "threat-model.yaml")


def cmd_validate(a) -> int:
    m = load(a.yaml)
    errors = m.validate()
    for err in errors:
        print("ERROR", err)
    if not errors:
        print(f"ok: {len(m.surfaces)} surfaces x 6 STRIDE categories covered, {len(m.threats)} threats, {len(m.controls)} controls")
    return 1 if errors else 0


def cmd_render(a) -> int:
    m = load(a.yaml)
    errors = m.validate()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    with open(a.md, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(m))
    with open(a.html, "w", encoding="utf-8") as fh:
        fh.write(to_html(m))
    print(f"wrote {a.md} and {a.html}")
    return 0


def cmd_forgery(a) -> int:
    p1 = signing.forgery_probability(a.bits, 1)
    n = signing.expected_attempts(a.bits)
    print(f"tag length                 {a.bits} bits")
    print(f"P(one blind guess accepted) {p1:.3e}")
    print(f"expected guesses            {n:.3e}")
    print(f"at {a.rate:,.0f} guesses/s        {signing.expected_years(a.bits, a.rate):,.0f} years expected")
    if a.attempts:
        print(f"P(success in {a.attempts:.3g} guesses) {signing.forgery_probability(a.bits, a.attempts):.3e}")
    print("\nBlind guessing is not the practical risk against a keyed tag: key theft and endpoint compromise are.")
    return 0


def cmd_signing_demo(_a) -> int:
    key = bytes(range(32))                         # demonstration key: never use a fixed key
    now = signing.timestamp_from_unix(1_760_000_000)
    rx = signing.SigningVerifier(key)
    frame = signing.build_frame(seq=1, sysid=1, compid=1, msgid=0, payload=b"\x00" * 9, crc_extra=50)
    pkt = signing.sign(frame, key, link_id=0, timestamp=now)
    print(f"signed packet ({len(pkt)} bytes): header 10, payload 9, CRC 2, signature block 13")
    print("  link id   ", pkt[-13:-12].hex())
    print("  timestamp ", pkt[-12:-6].hex(), f"({now} x 10 us since 2015-01-01)")
    print("  signature ", pkt[-6:].hex())
    cases = [
        ("genuine packet", pkt, now),
        ("same packet again (replay)", pkt, now + 10),
        ("payload bit flipped, CRC recomputed", _flip_and_fix(pkt), now + 20),
        ("wrong key", signing.sign(frame, bytes(32), 0, now + 30), now + 30),
        ("valid signature, timestamp 2 minutes old", signing.sign(frame, key, 1, now - 12_000_000), now + 40),
        ("newer genuine packet", signing.sign(frame, key, 0, now + 50), now + 50),
    ]
    for name, p, t in cases:
        v = rx.verify(p, t)
        print(f"  {'ACCEPT' if v.accepted else 'REJECT'}  {name:<42} {v.reason}")
    return 0


def _flip_and_fix(pkt: bytes) -> bytes:
    """Flip a payload bit and recompute the CRC: the CRC passes, the signature does not."""
    b = bytearray(pkt)
    b[10] ^= 0x01
    end = 10 + b[1]
    crc = signing.crc_x25(bytes(b[1:end]) + bytes([50]))
    b[end:end + 2] = crc.to_bytes(2, "little")
    return bytes(b)


def cmd_log_demo(_a) -> int:
    anchor_key = b"held-by-a-separate-system--demo!"
    log = hashlog.HashChainLog()
    events = [
        {"node": "gcs", "event": "login", "user": "operator-1"},
        {"node": "gcs", "event": "mission_upload", "mission": "survey-07"},
        {"node": "av", "event": "arm"},
        {"node": "av", "event": "nav_integrity_flag", "detail": "gnss inconsistent with vision"},
        {"node": "av", "event": "mode_change", "to": "return"},
    ]
    for i, ev in enumerate(events):
        log.append(ev, ts=1000.0 + i)
    anchor = log.anchor(anchor_key)
    print(f"{len(log.entries)} entries, head {log.head[:16]}..., anchored")
    print("  intact                   ", log.verify())
    edited = hashlog.HashChainLog(log.entries)
    edited.entries[3] = {**edited.entries[3], "event": {"node": "av", "event": "nav_ok"}}
    print("  edited entry 3           ", edited.verify())
    deleted = hashlog.HashChainLog(log.entries[:3] + log.entries[4:])
    print("  deleted entry 3          ", deleted.verify())
    truncated = hashlog.HashChainLog(log.entries[:3])
    print("  truncated (chain only)   ", truncated.verify())
    print("  truncated (with anchor)  ", truncated.verify_against_anchor(anchor, anchor_key))
    rewritten = hashlog.HashChainLog()
    for i, ev in enumerate(events):
        rewritten.append(ev if i != 3 else {"node": "av", "event": "nav_ok"}, ts=1000.0 + i)
    print("  fully recomputed chain   ", rewritten.verify())
    print("  ... checked against anchor", rewritten.verify_against_anchor(anchor, anchor_key))
    return 0


def cmd_update_demo(_a) -> int:
    root = update_chain.HmacDemoVerifier(b"demo-root-key: real devices hold a public key only")
    dev = update_chain.Device(root)
    boot = b"bootloader v3"
    fc = b"flight controller firmware 4.2"
    fc_old = b"flight controller firmware 4.0"
    chain = [
        ("bootloader", boot, update_chain.make_signed_manifest(root, "bootloader", "3", 3, boot)),
        ("flight-controller", fc, update_chain.make_signed_manifest(root, "flight-controller", "4.2", 7, fc)),
    ]
    print("boot chain:")
    for d in dev.boot(chain):
        print(f"  {'OK  ' if d.accepted else 'STOP'} {d.component:<18} {d.reason}")
    print("updates:")
    cases = [
        ("valid 4.2", "flight-controller", fc, chain[1][2]),
        ("image altered after signing", "flight-controller", fc + b"\x00", chain[1][2]),
        ("rollback to 4.0 (security version 5)", "flight-controller", fc_old,
         update_chain.make_signed_manifest(root, "flight-controller", "4.0", 5, fc_old)),
        ("payload image flashed to autopilot", "flight-controller", b"payload app",
         update_chain.make_signed_manifest(root, "payload", "1.0", 9, b"payload app")),
        ("signed by an unknown key", "flight-controller", fc,
         update_chain.make_signed_manifest(update_chain.HmacDemoVerifier(b"other"), "flight-controller", "4.3", 8, fc)),
    ]
    for name, comp, img, sm in cases:
        d = dev.install(comp, img, sm)
        print(f"  {'ACCEPT' if d.accepted else 'REJECT'} {name:<40} {d.reason}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="uasthreat", description="UAS threat model tools (defensive, educational).")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("validate")
    s.add_argument("--yaml", default=DEFAULT_YAML)
    s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("render")
    s.add_argument("--yaml", default=DEFAULT_YAML)
    s.add_argument("--md", default=os.path.join(HERE, "docs", "MATRIX.md"))
    s.add_argument("--html", default=os.path.join(HERE, "docs", "matrix.html"))
    s.set_defaults(fn=cmd_render)
    s = sub.add_parser("forgery")
    s.add_argument("--bits", type=int, default=48)
    s.add_argument("--rate", type=float, default=10_000.0, help="guesses per second")
    s.add_argument("--attempts", type=float, default=None)
    s.set_defaults(fn=cmd_forgery)
    sub.add_parser("signing-demo").set_defaults(fn=cmd_signing_demo)
    sub.add_parser("log-demo").set_defaults(fn=cmd_log_demo)
    sub.add_parser("update-demo").set_defaults(fn=cmd_update_demo)
    a = p.parse_args(argv)
    return a.fn(a)
