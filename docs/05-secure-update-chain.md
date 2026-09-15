# 05 · Secure boot and the update chain of trust

## 5.1 The chain

A hardware root of trust (a public-key hash in one-time-programmable fuses, a secure element or a TPM) verifies the bootloader. The verified bootloader verifies the flight-controller image, which verifies the application. Each stage runs the next only if its signature chains back to the root. Because the root is immutable and the private signing key never leaves the manufacturer's signing infrastructure, someone who cannot produce a valid signature cannot get code to run, even with physical access to the update port.

USB, SD card and over-the-air updates all pass through the same verification, so once it is **enforced** they stop being three separate attack surfaces.

## 5.2 Four decisions at every stage

`uasthreat/update_chain.py` models the decisions, and `python -m uasthreat update-demo` walks through them:

| Check | Rejects |
|---|---|
| Manifest signature verifies against the root | Images signed by anyone else |
| Image digest matches the manifest | An image altered after signing |
| Manifest names this component | A validly signed payload image flashed onto the autopilot |
| Security version is not below the stored floor | **Rollback** to an older, vulnerable, but genuinely signed image |

The anti-rollback floor rises only after a successful install (`test_failed_install_does_not_raise_floor`), and a boot chain stops at the first stage that fails, so nothing after it runs.

## 5.3 Why the demo verifier is symmetric, and why real ones are not

The Python standard library has no public-key signatures, so the demo uses an HMAC behind a `Verifier` interface. That stand-in has one property a real design must not have: the device holds the same secret that signs, so extracting it from a captured aircraft would allow signing firmware. Real devices hold only a **public** key; the private key stays in a hardware security module in the signing infrastructure. Replace `HmacDemoVerifier` with an Ed25519 or ECDSA verifier and every decision in the table stays the same.

## 5.4 Supply-chain evidence around the chain

| Artefact | Question it answers |
|---|---|
| Software bill of materials (SBOM) | Which builds contain the component in today's vulnerability advisory? |
| Build provenance attestation | Was this binary produced by the expected pipeline from the expected source? |
| Reproducible build | Can an independent party rebuild it bit for bit? |
| Configuration record | Which image and security version is on each airframe? |
| Staged rollout | Can a bad update be stopped before it reaches the whole fleet? |

## 5.5 Evaluation questions

1. Where is the root of trust, and is verification enforced or only available?
2. Who holds the signing keys, in what hardware, with what access control?
3. Is there anti-rollback, and what happens to it during a recovery procedure?
4. Are debug interfaces locked on production units?
5. Can the supplier produce an SBOM for the delivered configuration?

## Limitations

The model shows decision logic only. It does not model hardware fault injection, key revocation, recovery modes, or the measured-boot attestation used to prove state to a remote verifier.
