# Defensive checklists

Use these in design reviews, supplier evaluations and acceptance. Each item should be answered with evidence (a document, a configuration, a test result), not with a yes.

## A. UAS cyber hardening

- [ ] Threat model current: STRIDE per trust boundary (air vehicle, companion computer, datalink, ground station, cloud, supply chain), with owners and residual risks.
- [ ] Datalink authenticated with anti-replay; for MAVLink 2, signing enabled and unsigned packets rejected, per-vehicle keys, strictly increasing timestamps.
- [ ] Link encrypted where confidentiality of commands, telemetry or video matters.
- [ ] Safety-critical and configuration commands authorised by role and flight phase.
- [ ] Ground station is a hardened, dedicated endpoint: full-disk encryption, least privilege, application allow-listing, patched by version, no general browsing or email.
- [ ] Individual accounts with phishing-resistant MFA for ground, cloud and fleet management; no shared credentials.
- [ ] Secure boot and signed firmware on autopilot and companion computer; anti-rollback; debug interfaces locked.
- [ ] SBOM maintained for the delivered configuration; vulnerabilities in third-party components tracked.
- [ ] Companion computer segmented from flight control through an allow-listed conduit.
- [ ] Cloud and API access: object- and function-level authorisation, short-lived scoped tokens, rate limiting, keys rotated.
- [ ] Navigation integrity: independent position sources cross-checked, GNSS interference detection, defined behaviour on disagreement.
- [ ] Failsafe behaviour tested for link loss, GNSS loss and inconsistent position, and documented for operators.
- [ ] Tamper-evident, time-synchronised logs from aircraft, ground station and cloud, anchored off-device.
- [ ] Incident response plan covering a compromised ground station, leaked keys and suspected spoofing, including reporting obligations.

## B. Key management

- [ ] Keys generated with a cryptographically secure source, never derived from serial numbers or defaults.
- [ ] Unique per vehicle or per link; no fleet-wide shared secret.
- [ ] Stored in a secure element, TPM or HSM where the platform allows.
- [ ] Rotation schedule and revocation procedure defined and rehearsed.
- [ ] Zeroisation on tamper detection and a procedure for lost or captured equipment.
- [ ] Signing keys for firmware held separately from operational link keys, with access logging.

## C. Supplier evaluation questions

- [ ] Is message authentication enforced on the command link, and how are keys provisioned?
- [ ] Where is the root of trust, who holds the firmware signing keys, and is there anti-rollback?
- [ ] Can you provide an SBOM and build provenance for the delivered configuration?
- [ ] What does the flight controller accept from the companion computer?
- [ ] What happens on link loss, GNSS loss and navigation-source disagreement? Show the test evidence.
- [ ] How long do API tokens live, what are they scoped to, and how is object-level authorisation tested?
- [ ] What logs are exported, how is their integrity protected, and how is time synchronised?
- [ ] How are vulnerabilities reported to you, and what is your disclosure and patch timeline?

## D. Before each flight (operator level)

- [ ] Ground station is the approved device, updated, and used for nothing else.
- [ ] Link signing status confirmed as enabled on both ends.
- [ ] Mission file integrity verified before upload.
- [ ] Navigation sources healthy and consistent before take-off; interference indicators checked.
- [ ] Log export from the previous flight completed and its chain head recorded.

## E. After a suspected incident

- [ ] Preserve logs from aircraft, ground station and backend before power cycling where safe.
- [ ] Record chain heads and compare with the last anchors.
- [ ] Treat link keys on affected equipment as compromised; rotate.
- [ ] Isolate the ground station for analysis; do not reuse it for operations.
- [ ] Report according to the organisation's incident plan and applicable regulation.
