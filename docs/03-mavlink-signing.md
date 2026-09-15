# 03 · MAVLink 2 message signing

![Signed packet](../assets/signing-frame.svg)

MAVLink is a widely used open messaging protocol between autopilots, companion computers and ground stations. Its two versions bracket the link-authentication problem neatly: MAVLink 1 frames carry a checksum and nothing else; MAVLink 2 adds an optional signature.

## 3.1 What the specification defines

From the public MAVLink message signing specification:

| Element | Definition |
|---|---|
| Signed flag | bit `0x01` of the incompatibility flags in the header |
| Signature block | 13 bytes appended after the CRC: link ID (1 byte), timestamp (6 bytes), signature (6 bytes) |
| Secret key | 32 bytes, shared by the endpoints of the link |
| Timestamp | 48-bit count of 10 µs units since 1 January 2015 GMT |
| Signature | first 48 bits of SHA-256(key ‖ header ‖ payload ‖ CRC ‖ link ID ‖ timestamp) |

$$\text{sig}_{48} = \text{first}_{48}\big(\text{SHA-256}(K \,\|\, \text{header} \,\|\, \text{payload} \,\|\, \text{CRC} \,\|\, \text{link} \,\|\, ts)\big)$$

```python
from uasthreat import signing
frame = signing.build_frame(seq=1, sysid=1, compid=1, msgid=0, payload=b"\x00" * 9, crc_extra=50)
packet = signing.sign(frame, key, link_id=0, timestamp=signing.timestamp_from_unix(time.time()))
signing.SigningVerifier(key).verify(packet, local_timestamp)   # Verdict(accepted=True, reason='ok')
```

Run `python -m uasthreat signing-demo` to see a genuine packet accepted and a replay, a bit flip with a recomputed CRC, a wrong key and a stale timestamp each rejected, with the reason.

## 3.2 A checksum is not authentication

The CRC (CRC-16/MCRF4XX, seeded with a per-message byte) detects accidental corruption. An adversary recomputes it as easily as the sender. The test `test_crc_is_not_authentication` flips a payload bit and fixes the CRC: the frame is well formed and the signature check still rejects it. Any datasheet that lists a checksum as a security feature describes an unauthenticated link.

## 3.3 Keyed-prefix hash versus HMAC

The specification's construction is a SHA-256 hash with the key as a prefix, truncated to 48 bits. It is not the RFC 2104 HMAC:

$$\text{HMAC}(K, m) = H\big((K' \oplus opad) \,\|\, H((K' \oplus ipad) \,\|\, m)\big)$$

HMAC's nested structure exists to defeat length-extension attacks on Merkle-Damgård hashes such as SHA-256, where knowing $H(K \| m)$ lets someone compute $H(K \| m \| \text{padding} \| m')$ without the key. For the MAVLink construction, truncation to 48 bits removes the full internal state an extension would need, and the fixed field layout constrains what could be appended. For new designs, HMAC (or an authenticated encryption mode) is still the standard recommendation, because its security argument does not depend on such details. `hmac_sha256_48` is provided alongside for comparison.

## 3.4 What 48 bits buys: blind forgery arithmetic

Without the key, the only generic way to get a chosen packet accepted is to guess the tag:

$$p_{\text{forge}} = 2^{-48} \approx 3.55 \times 10^{-15}, \qquad E[\text{attempts}] = 2^{48} \approx 2.81 \times 10^{14}$$

$$P(\text{at least one success in } n) = 1 - (1 - 2^{-48})^n$$

At an optimistic 10,000 guesses per second, each one a transmitted frame the receiver must process, the expected time to one forgery is about **890 years**.

```bash
python -m uasthreat forgery --bits 48 --rate 10000
python -m uasthreat forgery --bits 32 --rate 10000     # compare: about 5 days
```

The conclusion is about where to spend effort. Online tag guessing is not the practical risk against a keyed tag. **Key management is**: how the 32-byte key is generated, provisioned per vehicle, stored, rotated and destroyed, and whether an endpoint that holds it (usually the ground station) is compromised. A single key shared across a fleet also means a command cannot be attributed to one station (threat DL-R1 in the matrix).

## 3.5 What signing does not give you

| Property | Provided? |
|---|---|
| Authenticity (sender holds the key) | Yes |
| Integrity of header, payload and CRC | Yes |
| Freshness within a stream | Yes, via the timestamp rule ([04](04-replay-and-freshness.md)) |
| Confidentiality | **No**: payload is in clear; encrypt separately if needed |
| Per-operator attribution | Only if keys are per link or per station |
| Protection if an endpoint is compromised | **No** |
| Protection against jamming or detection | **No** |

## 3.6 Evaluation questions

1. Is signing **enabled and enforced**, or merely supported? Are unsigned packets rejected?
2. How is the key generated, provisioned, rotated and revoked? Is it unique per vehicle or per link?
3. Where is the key stored on the ground station and on the aircraft?
4. How does the system get a trustworthy clock for the timestamp rule after a cold start?
5. Is the link also encrypted where confidentiality matters?

## Limitations

The implementation here follows the public specification closely enough to test the acceptance rules. It is not an interoperability-tested MAVLink library: message definitions, CRC extra bytes and edge cases such as timestamp persistence across restarts belong to the real protocol libraries.
