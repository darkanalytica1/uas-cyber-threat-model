"""MAVLink 2 message signing, implemented for understanding and for defensive verification.

What the public specification defines (mavlink.io, "Message signing"):

- A signed packet sets bit 0x01 of the incompatibility flags and appends a
  13-byte trailer: link ID (1 byte), timestamp (6 bytes), signature (6 bytes).
- signature = first 48 bits of SHA-256(secret_key + header + payload + CRC + link_id + timestamp)
- The secret key is 32 bytes.
- The timestamp is a 48-bit count of 10 microsecond units since 1 January 2015 GMT.
- A receiver rejects a packet whose signature does not match, whose timestamp is
  not newer than the last one accepted for the same (system ID, component ID,
  link ID) stream, or whose timestamp is more than one minute (6,000,000 units)
  behind the receiver's own clock.

Note that the construction is a keyed-prefix hash truncated to 48 bits, not the
RFC 2104 HMAC. `hmac_sha256_48` is included so the two can be compared; see
docs/03-mavlink-signing.md for why truncation also blunts length extension here.

This module signs and verifies. It contains nothing that helps anyone forge a
signature without the key, which is the point: without the key, the only
generic approach is guessing, and `forgery_*` below shows what that costs.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

MAGIC_V2 = 0xFD
IFLAG_SIGNED = 0x01
HEADER_LEN = 10
CRC_LEN = 2
SIGNATURE_BLOCK_LEN = 13
KEY_LEN = 32
EPOCH_2015_UNIX_S = 1_420_070_400
TIMESTAMP_UNITS_PER_S = 100_000       # 10 microseconds
ONE_MINUTE = 60 * TIMESTAMP_UNITS_PER_S


# --------------------------------------------------------------------------- framing

def crc_x25(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/MCRF4XX as used by MAVLink. It detects corruption; it authenticates nothing."""
    for byte in data:
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def timestamp_from_unix(unix_s: float) -> int:
    return int(round((unix_s - EPOCH_2015_UNIX_S) * TIMESTAMP_UNITS_PER_S))


def build_frame(
    seq: int, sysid: int, compid: int, msgid: int, payload: bytes, crc_extra: int, signed: bool = True
) -> bytes:
    """Header + payload + CRC of a MAVLink 2 frame (no signature block yet).

    crc_extra is the per-message seed byte derived from the message definition.
    """
    if len(payload) > 255:
        raise ValueError("payload too long")
    header = bytes([
        MAGIC_V2, len(payload), IFLAG_SIGNED if signed else 0, 0, seq & 0xFF, sysid & 0xFF, compid & 0xFF,
    ]) + struct.pack("<I", msgid)[:3]
    crc = crc_x25(header[1:] + payload + bytes([crc_extra]))
    return header + payload + struct.pack("<H", crc)


def signature48(key: bytes, frame: bytes, link_id: int, timestamp: int) -> bytes:
    """First 6 bytes of SHA-256(key + header + payload + CRC + link_id + timestamp)."""
    if len(key) != KEY_LEN:
        raise ValueError("MAVLink 2 signing keys are 32 bytes")
    if not 0 <= timestamp < 2 ** 48:
        raise ValueError("timestamp must fit in 48 bits")
    h = hashlib.sha256()
    h.update(key)
    h.update(frame)
    h.update(bytes([link_id & 0xFF]))
    h.update(timestamp.to_bytes(6, "little"))
    return h.digest()[:6]


def hmac_sha256_48(key: bytes, frame: bytes, link_id: int, timestamp: int) -> bytes:
    """RFC 2104 HMAC-SHA256 over the same fields, truncated to 48 bits, for comparison only."""
    msg = frame + bytes([link_id & 0xFF]) + timestamp.to_bytes(6, "little")
    return hmac.new(key, msg, hashlib.sha256).digest()[:6]


def sign(frame: bytes, key: bytes, link_id: int, timestamp: int) -> bytes:
    """Append the 13-byte signature block to a frame built with signed=True."""
    if not frame[2] & IFLAG_SIGNED:
        raise ValueError("frame does not set the signed incompatibility flag")
    return frame + bytes([link_id & 0xFF]) + timestamp.to_bytes(6, "little") + signature48(key, frame, link_id, timestamp)


@dataclass(frozen=True)
class SignedPacket:
    frame: bytes
    sysid: int
    compid: int
    msgid: int
    payload: bytes
    link_id: int
    timestamp: int
    signature: bytes

    @property
    def stream(self) -> Tuple[int, int, int]:
        return (self.sysid, self.compid, self.link_id)


def parse_signed(packet: bytes) -> SignedPacket:
    if len(packet) < HEADER_LEN + CRC_LEN + SIGNATURE_BLOCK_LEN or packet[0] != MAGIC_V2:
        raise ValueError("not a MAVLink 2 packet")
    plen = packet[1]
    if not packet[2] & IFLAG_SIGNED:
        raise ValueError("packet is not signed")
    end = HEADER_LEN + plen + CRC_LEN
    if len(packet) != end + SIGNATURE_BLOCK_LEN:
        raise ValueError("length does not match header")
    frame = packet[:end]
    block = packet[end:]
    return SignedPacket(
        frame=frame,
        sysid=packet[5],
        compid=packet[6],
        msgid=int.from_bytes(packet[7:10], "little"),
        payload=packet[HEADER_LEN:HEADER_LEN + plen],
        link_id=block[0],
        timestamp=int.from_bytes(block[1:7], "little"),
        signature=block[7:13],
    )


# --------------------------------------------------------------------------- verification

@dataclass(frozen=True)
class Verdict:
    accepted: bool
    reason: str


@dataclass
class SigningVerifier:
    """Receiver-side acceptance rules from the specification.

    The rules separate three properties that are often blurred:
    authenticity (signature), freshness within a stream (strictly increasing
    timestamp) and bounded staleness (not more than a minute behind local time).
    """

    key: bytes
    last_seen: Dict[Tuple[int, int, int], int] = field(default_factory=dict)
    max_behind: int = ONE_MINUTE

    def verify(self, packet: bytes, local_timestamp: int) -> Verdict:
        try:
            p = parse_signed(packet)
        except ValueError as exc:
            return Verdict(False, f"malformed: {exc}")
        expected = signature48(self.key, p.frame, p.link_id, p.timestamp)
        if not hmac.compare_digest(expected, p.signature):
            return Verdict(False, "bad signature")
        last = self.last_seen.get(p.stream)
        if last is not None and p.timestamp <= last:
            return Verdict(False, "replay or reordering: timestamp not newer than last accepted for this stream")
        if p.timestamp < local_timestamp - self.max_behind:
            return Verdict(False, "stale: more than one minute behind local time")
        self.last_seen[p.stream] = p.timestamp
        return Verdict(True, "ok")


# --------------------------------------------------------------------------- blind forgery arithmetic

def forgery_probability(bits: int = 48, attempts: float = 1.0) -> float:
    """Probability that at least one of `attempts` random tag guesses is accepted, for a chosen packet.

    1 - (1 - 2^-bits)^attempts, computed stably.
    """
    import math

    p = 2.0 ** -bits
    return -math.expm1(attempts * math.log1p(-p))


def expected_attempts(bits: int = 48) -> float:
    """Expected guesses for one blind forgery: 2^bits."""
    return 2.0 ** bits


def expected_years(bits: int = 48, attempts_per_s: float = 10_000.0) -> float:
    return expected_attempts(bits) / attempts_per_s / (365.25 * 24 * 3600)
