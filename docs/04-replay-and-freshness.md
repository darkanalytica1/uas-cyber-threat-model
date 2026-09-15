# 04 · Replay and freshness

## 4.1 Authentication proves who, not when

A replay attack captures a legitimate, correctly authenticated message and sends it again later. The signature still verifies, because nothing about the message changed. Without a freshness rule, every valid command ever transmitted becomes a stored capability for anyone who recorded it.

## 4.2 Three ways to add freshness

| Mechanism | Receiver keeps | Strength | Weakness |
|---|---|---|---|
| Monotonic timestamp | Last accepted timestamp per stream | No round trip; also gives ordering for forensics | Needs a sane clock after restart |
| Sequence counter | Last accepted counter per stream | No clock needed | Counter must persist across restarts or be re-keyed |
| Nonce / challenge-response | Recently seen nonces, or issues challenges | Strong for one-off, high-value actions | Adds a round trip; state to manage |

The rule in all cases is the same: accept only if the freshness value **strictly advances** for that stream, and bind the value into the authenticated data so it cannot be changed without breaking the tag.

## 4.3 How MAVLink 2 does it

The 48-bit timestamp sits inside the hashed data. The receiver keeps the last accepted timestamp for each (system ID, component ID, link ID) stream and rejects anything not newer. It also rejects packets more than one minute behind its own clock, which bounds how old a first packet on a new stream can be.

```python
rx = signing.SigningVerifier(key)
rx.verify(packet, now)        # accepted
rx.verify(packet, now + 10)   # rejected: timestamp not newer than last accepted for this stream
```

Separate streams are tracked independently, so a second link can carry an older timestamp than the first without being rejected (see `test_older_timestamp_rejected_but_other_stream_independent`).

## 4.4 Design notes

- **Clock sanity is part of the security design.** If a receiver's clock can be set far into the future, it will reject genuine traffic; if it restarts with no memory and a clock in the past, the one-minute window is its only protection. Persist the last timestamp or re-key after restart.
- **Freshness applies beyond the radio.** API requests, mission uploads, and update manifests all need it. An update manifest without an anti-rollback version is a replay of old, vulnerable firmware.
- **Freshness is forensic evidence.** The same strictly ordered values that stop replay let an investigator reconstruct the order of events.

## Limitations

A freshness rule stops replay of recorded traffic. It does not stop a compromised endpoint that holds the key from creating new, fresh, valid messages.
