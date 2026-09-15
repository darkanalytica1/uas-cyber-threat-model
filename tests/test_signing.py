import hashlib

import pytest

from uasthreat import signing as s

KEY = bytes(range(32))
NOW = s.timestamp_from_unix(1_760_000_000)


def frame(payload=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09"):
    return s.build_frame(seq=7, sysid=1, compid=1, msgid=0, payload=payload, crc_extra=50)


def test_timestamp_epoch_and_units():
    assert s.timestamp_from_unix(1_420_070_400) == 0
    assert s.timestamp_from_unix(1_420_070_401) == 100_000


def test_trailer_layout():
    f = frame()
    p = s.sign(f, KEY, link_id=3, timestamp=NOW)
    assert len(p) == len(f) + 13
    assert p[2] & s.IFLAG_SIGNED
    assert p[-13] == 3
    assert int.from_bytes(p[-12:-6], "little") == NOW
    parsed = s.parse_signed(p)
    assert parsed.stream == (1, 1, 3) and parsed.payload == f[10:19]


def test_signature_matches_specification_formula():
    f = frame()
    expected = hashlib.sha256(KEY + f + bytes([3]) + NOW.to_bytes(6, "little")).digest()[:6]
    assert s.signature48(KEY, f, 3, NOW) == expected
    assert len(expected) * 8 == 48


def test_keyed_prefix_differs_from_rfc2104_hmac():
    f = frame()
    assert s.signature48(KEY, f, 0, NOW) != s.hmac_sha256_48(KEY, f, 0, NOW)


def test_key_length_enforced():
    with pytest.raises(ValueError):
        s.signature48(b"short", frame(), 0, NOW)


def test_genuine_packet_accepted():
    rx = s.SigningVerifier(KEY)
    assert rx.verify(s.sign(frame(), KEY, 0, NOW), NOW).accepted


def test_replay_rejected():
    rx = s.SigningVerifier(KEY)
    p = s.sign(frame(), KEY, 0, NOW)
    assert rx.verify(p, NOW).accepted
    v = rx.verify(p, NOW + 5)
    assert not v.accepted and "replay" in v.reason


def test_older_timestamp_rejected_but_other_stream_independent():
    rx = s.SigningVerifier(KEY)
    assert rx.verify(s.sign(frame(), KEY, 0, NOW + 100), NOW + 100).accepted
    assert not rx.verify(s.sign(frame(), KEY, 0, NOW + 50), NOW + 100).accepted
    assert rx.verify(s.sign(frame(), KEY, 1, NOW + 50), NOW + 100).accepted


def test_stale_beyond_one_minute_rejected():
    rx = s.SigningVerifier(KEY)
    old = NOW - s.ONE_MINUTE - 1
    v = rx.verify(s.sign(frame(), KEY, 0, old), NOW)
    assert not v.accepted and "stale" in v.reason
    assert rx.verify(s.sign(frame(), KEY, 0, NOW - s.ONE_MINUTE + 1), NOW).accepted


def test_wrong_key_rejected():
    rx = s.SigningVerifier(KEY)
    assert rx.verify(s.sign(frame(), bytes(32), 0, NOW), NOW).reason == "bad signature"


def test_crc_is_not_authentication():
    """Altering the payload and recomputing the CRC yields a well-formed frame that still fails the signature."""
    p = bytearray(s.sign(frame(), KEY, 0, NOW))
    p[10] ^= 0xFF
    end = 10 + p[1]
    p[end:end + 2] = s.crc_x25(bytes(p[1:end]) + bytes([50])).to_bytes(2, "little")
    rx = s.SigningVerifier(KEY)
    assert rx.verify(bytes(p), NOW).reason == "bad signature"


def test_crc_known_vector():
    # CRC-16/MCRF4XX check value for "123456789"
    assert s.crc_x25(b"123456789") == 0x6F91


def test_forgery_arithmetic():
    assert s.forgery_probability(48, 1) == pytest.approx(3.55e-15, rel=1e-2)
    assert s.expected_attempts(48) == pytest.approx(2.81e14, rel=1e-2)
    assert s.expected_years(48, 10_000) == pytest.approx(892, rel=1e-2)
    assert s.forgery_probability(48, 2 ** 48) == pytest.approx(1 - 1 / 2.718281828, rel=1e-3)
