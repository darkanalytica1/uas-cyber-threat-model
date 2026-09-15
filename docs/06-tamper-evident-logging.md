# 06 · Tamper-evident, hash-chained logging

A log an attacker can edit is a story, not evidence. Tamper evidence makes alteration detectable; anchoring makes it provable.

## 6.1 The chain

Each entry commits to the one before it:

$$h_i = \text{SHA-256}\big(\text{canonical}(\{index_i,\ ts_i,\ event_i,\ h_{i-1}\})\big), \qquad h_{-1} = 0^{64}$$

Canonical serialisation (sorted keys, fixed separators) matters: the same event must always hash the same way.

```python
from uasthreat import HashChainLog
log = HashChainLog()
log.append({"node": "gcs", "event": "mission_upload", "mission": "survey-07"})
log.append({"node": "av", "event": "nav_integrity_flag"})
log.verify()                  # VerifyResult(ok=True, ...)
anchor = log.anchor(key)      # authenticate (count, head) with a key held elsewhere
```

## 6.2 What the chain detects, and what needs an anchor

`python -m uasthreat log-demo` runs each case:

| Tampering | Chain alone | Chain + anchor |
|---|---|---|
| Edit an entry | detected at that entry | detected |
| Delete an entry | detected | detected |
| Reorder entries | detected | detected |
| Truncate the tail | **not detected** | detected: shorter than anchored length |
| Rewrite everything and recompute all hashes | **not detected** | detected: head differs from anchored head |

The last two rows are the reason anchoring exists. Anyone with write access to the whole log can produce a new, internally consistent chain. The anchor, an authenticated `(count, head)` pair made with a key the logging system does not hold, or a copy of the head written to an append-only store on another system, is what the rewrite cannot reproduce.

## 6.3 Design notes for a UAS

- **Log the security-relevant events**: authentication, command issuance, configuration and parameter changes, updates, navigation-integrity flags, link loss and mode changes.
- **Time is a prerequisite.** Without synchronised, trustworthy time across aircraft, ground station and backend, events cannot be correlated, and correlation is the value of the logs. Record the time source and its quality.
- **Anchor off-device and often.** An aircraft can be lost with its log. Export chain heads to the ground station and from there to separate storage at intervals.
- **Tamper evidence is not confidentiality.** Logs can contain position histories and personal data; access control and retention rules still apply.
- **Signatures add attribution.** Replacing the HMAC anchor with a digital signature by each node gives non-repudiation per node.

## 6.4 Decision tree: is this logging forensically usable?

1. Are security-relevant events recorded at all? If not, no reconstruction is possible: close this gap first.
2. Is the log hash-chained with an anchored or signed head? If not, treat it as indicative, not evidential.
3. Is time synchronised across nodes to a common reference? If not, only ordering within one node can be trusted.
4. Are retention and access defined? If yes, the logs can serve as evidence.

## Limitations

Hash chaining proves a log was not altered after the fact. It does not prove the events were recorded truthfully in the first place by a node that was already compromised.
