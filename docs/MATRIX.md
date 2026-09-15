# Threat matrix: Generic small UAS (reference architecture)

<!-- Generated from data/threat-model.yaml by `python -m uasthreat render`. Do not edit by hand. -->

Rows are attack surfaces, columns are STRIDE categories with the property each one attacks. Each cell lists the threats identified there; every cell is filled, which is the point of STRIDE: gaps are named rather than missed. Threat IDs link to the detail tables below.

| Surface | S · Spoofing<br><sub>Authentication</sub> | T · Tampering<br><sub>Integrity</sub> | R · Repudiation<br><sub>Non-repudiation</sub> | I · Information disclosure<br><sub>Confidentiality</sub> | D · Denial of service<br><sub>Availability</sub> | E · Elevation of privilege<br><sub>Authorisation</sub> |
|---|---|---|---|---|---|---|
| **AV** Air vehicle | [AV-S1](#av-s1) | [AV-T1](#av-t1) | [AV-R1](#av-r1) | [AV-I1](#av-i1) | [AV-D1](#av-d1) | [AV-E1](#av-e1) |
| **CC** Companion computer | [CC-S1](#cc-s1) | [CC-T1](#cc-t1) | [CC-R1](#cc-r1) | [CC-I1](#cc-i1) | [CC-D1](#cc-d1) | [CC-E1](#cc-e1) |
| **DL** Command and telemetry datalink | [DL-S1](#dl-s1)<br>[DL-S2](#dl-s2) | [DL-T1](#dl-t1) | [DL-R1](#dl-r1) | [DL-I1](#dl-i1) | [DL-D1](#dl-d1) | [DL-E1](#dl-e1) |
| **GCS** Ground control station | [GCS-S1](#gcs-s1) | [GCS-T1](#gcs-t1) | [GCS-R1](#gcs-r1) | [GCS-I1](#gcs-i1) | [GCS-D1](#gcs-d1) | [GCS-E1](#gcs-e1) |
| **API** Cloud and fleet API | [API-S1](#api-s1) | [API-T1](#api-t1) | [API-R1](#api-r1) | [API-I1](#api-i1) | [API-D1](#api-d1) | [API-E1](#api-e1) |
| **SC** Supply chain and update path | [SC-S1](#sc-s1) | [SC-T1](#sc-t1) | [SC-R1](#sc-r1) | [SC-I1](#sc-i1) | [SC-D1](#sc-d1) | [SC-E1](#sc-e1) |

## Trust boundaries

| ID | Boundary | Why it matters |
|---|---|---|
| TB-RF | Air-ground radio boundary | Anyone within radio range can transmit and receive. Nothing crossing it is trusted by default. |
| TB-ONBOARD | Flight-critical zone versus payload zone | The flight controller must keep flying even if the companion computer is compromised. |
| TB-GROUND | Operator endpoint versus enterprise and internet | The ground control station sits on networks and runs software the operator does not fully control. |
| TB-CLOUD | Organisation versus cloud service and other tenants | Fleet data and tasking cross a public network into a multi-tenant service. |
| TB-SUPPLY | Organisation versus suppliers and build infrastructure | Components, software and signing happen outside the operator's direct control. |

## AV · Air vehicle

Flight controller, GNSS receiver, inertial and air-data sensors, maintenance ports. Trust boundary: TB-RF.

| ID | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| <a id="av-s1"></a>AV-S1 | Spoofing | Counterfeit GNSS signals produce a false position and time that the flight controller accepts as truth. | [C-NAVX](#c-navx), [C-GNSSAUTH](#c-gnssauth) | Slow carry-off is detected only once it exceeds what independent sensors can explain. |
| <a id="av-t1"></a>AV-T1 | Tampering | Parameters or firmware altered through a maintenance port during storage or maintenance. | [C-BOOT](#c-boot), [C-DEBUG](#c-debug), [C-PHYS](#c-phys), [C-LOG](#c-log) | Insider with legitimate maintenance access. |
| <a id="av-r1"></a>AV-R1 | Repudiation | A configuration or flight-mode change cannot be attributed to a person or a message. | [C-LOG](#c-log), [C-SIGN](#c-sign) | Clock drift without authenticated time weakens ordering across nodes. |
| <a id="av-i1"></a>AV-I1 | Information disclosure | A lost or captured airframe exposes link keys, mission data and stored imagery. | [C-KEY](#c-key), [C-DATA](#c-data) | Data in volatile memory at the moment of capture. |
| <a id="av-d1"></a>AV-D1 | Denial of service | GNSS jamming or sensor saturation removes navigation inputs. | [C-NAVX](#c-navx), [C-DIV](#c-div) | Vision-based fallbacks fail over featureless terrain, at night without infrared, or in smoke. |
| <a id="av-e1"></a>AV-E1 | Elevation of privilege | An unsigned image or open debug interface gives full control of the flight controller. | [C-BOOT](#c-boot), [C-DEBUG](#c-debug) | Hardware-level fault injection by a well-resourced attacker with physical access. |

## CC · Companion computer

Onboard processor running autonomy, perception and payload software beside the flight controller. Trust boundary: TB-ONBOARD.

| ID | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| <a id="cc-s1"></a>CC-S1 | Spoofing | A process on the onboard network impersonates the autopilot or a sensor to other onboard software. | [C-SEG](#c-seg), [C-SIGN](#c-sign) | Shared-memory or bus designs without per-component identity. |
| <a id="cc-t1"></a>CC-T1 | Tampering | Autonomy, perception software or model files are modified. | [C-BOOT](#c-boot), [C-SBOM](#c-sbom), [C-REPRO](#c-repro) | Models are hard to review; integrity proves origin, not correctness. |
| <a id="cc-r1"></a>CC-R1 | Repudiation | An autonomous decision cannot be reconstructed afterwards. | [C-LOG](#c-log), [C-CM](#c-cm) | Log volume limits on small platforms force summarisation. |
| <a id="cc-i1"></a>CC-I1 | Information disclosure | Payload imagery or intelligence leaks through network services running on the companion computer. | [C-DATA](#c-data), [C-LEAST](#c-least), [C-TLS](#c-tls) | Debug and development services left enabled in the field. |
| <a id="cc-d1"></a>CC-D1 | Denial of service | Resource exhaustion or a crash stops perception and autonomy mid-mission. | [C-RTA](#c-rta), [C-SEG](#c-seg) | Mission capability is lost even when flight safety is preserved. |
| <a id="cc-e1"></a>CC-E1 | Elevation of privilege | A compromised companion computer reaches flight control through an unrestricted bus. | [C-SEG](#c-seg), [C-LEAST](#c-least), [C-CMDAUTHZ](#c-cmdauthz) | Allow-listed commands can still be misused within their bounds. |

## DL · Command and telemetry datalink

Radio links carrying commands up and telemetry and video down. Trust boundary: TB-RF.

| ID | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| <a id="dl-s1"></a>DL-S1 | Spoofing | Commands from an unauthenticated source are accepted because the link does not authenticate messages. | [C-SIGN](#c-sign), [C-KEY](#c-key) | Key compromise on any endpoint that holds the key. |
| <a id="dl-s2"></a>DL-S2 | Spoofing | A recorded, validly authenticated command is replayed later. | [C-SIGN](#c-sign) | Freshness depends on correct timestamp handling and clock sanity at both ends. |
| <a id="dl-t1"></a>DL-T1 | Tampering | Telemetry is altered in transit so the operator acts on a false picture. | [C-SIGN](#c-sign), [C-ENC](#c-enc) | Unauthenticated video downlinks. |
| <a id="dl-r1"></a>DL-R1 | Repudiation | A command cannot be tied to one ground station because a single key is shared across the fleet. | [C-KEY](#c-key), [C-LOG](#c-log) | Shared keys remain common for operational convenience. |
| <a id="dl-i1"></a>DL-I1 | Information disclosure | Telemetry and video reveal position, mission and operator location to a passive listener. | [C-ENC](#c-enc) | Emissions remain detectable and locatable even when encrypted. |
| <a id="dl-d1"></a>DL-D1 | Denial of service | Radio jamming or message flooding denies command and control. | [C-DIV](#c-div), [C-RATE](#c-rate) | Physics: a sufficiently powerful jammer in the right geometry wins. |
| <a id="dl-e1"></a>DL-E1 | Elevation of privilege | Configuration, firmware upload or arming commands are accepted from any authenticated sender in any flight phase. | [C-CMDAUTHZ](#c-cmdauthz), [C-SIGN](#c-sign) | Authorisation policy errors. |

## GCS · Ground control station

Operator laptop or tablet running mission planning and control software. Trust boundary: TB-GROUND.

| ID | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| <a id="gcs-s1"></a>GCS-S1 | Spoofing | Stolen operator credentials let someone operate as the pilot. | [C-MFA](#c-mfa), [C-EP](#c-ep) | Session hijacking on an already compromised host. |
| <a id="gcs-t1"></a>GCS-T1 | Tampering | A mission plan, geofence or map file is altered before upload. | [C-INTEG](#c-integ), [C-EP](#c-ep) | Plans edited in the field under time pressure. |
| <a id="gcs-r1"></a>GCS-R1 | Repudiation | An operator action cannot be attributed because accounts are shared. | [C-MFA](#c-mfa), [C-LOG](#c-log) | Physical access to an unlocked station. |
| <a id="gcs-i1"></a>GCS-I1 | Information disclosure | A lost laptop exposes keys, plans, imagery and credentials. | [C-DATA](#c-data), [C-KEY](#c-key) | Data copied to removable media. |
| <a id="gcs-d1"></a>GCS-D1 | Denial of service | Malware or an untested update disables the station during a mission. | [C-EP](#c-ep), [C-SPARE](#c-spare), [C-IR](#c-ir) | Common-mode failure if spares share the same image. |
| <a id="gcs-e1"></a>GCS-E1 | Elevation of privilege | Unpatched software allows local privilege escalation to the control application and its keys. | [C-EP](#c-ep), [C-LEAST](#c-least) | Vulnerabilities not yet known or patched. |

## API · Cloud and fleet API

Backend for fleet management, flight logs, media, tasking and updates. Trust boundary: TB-CLOUD.

| ID | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| <a id="api-s1"></a>API-S1 | Spoofing | A leaked bearer token grants API access with no further authentication. | [C-TOKEN](#c-token), [C-MFA](#c-mfa) | Tokens stolen from a compromised endpoint within their lifetime. |
| <a id="api-t1"></a>API-T1 | Tampering | Uploaded flight logs, missions or fleet configuration are altered in the backend. | [C-INTEG](#c-integ), [C-LOG](#c-log), [C-API](#c-api) | Privileged backend administrators. |
| <a id="api-r1"></a>API-R1 | Repudiation | API actions such as tasking or configuration changes leave no attributable audit trail. | [C-LOG](#c-log) | Logs held by the same provider that is being audited. |
| <a id="api-i1"></a>API-I1 | Information disclosure | Broken object-level authorisation exposes another tenant's telemetry and flight history. | [C-API](#c-api), [C-LEAST](#c-least) | New endpoints added without the same checks. |
| <a id="api-d1"></a>API-D1 | Denial of service | API abuse or outage blocks synchronisation, tasking and updates. | [C-RATE](#c-rate), [C-OFFLINE](#c-offline) | Features that genuinely depend on the cloud. |
| <a id="api-e1"></a>API-E1 | Elevation of privilege | Broken function-level authorisation lets an ordinary user reach administrative functions such as pushing updates. | [C-API](#c-api), [C-LEAST](#c-least), [C-STAGED](#c-staged) | Misconfigured roles. |

## SC · Supply chain and update path

Hardware components, third-party software, build pipeline, signing keys and update distribution. Trust boundary: TB-SUPPLY.

| ID | STRIDE | Threat | Controls | Residual risk |
|---|---|---|---|---|
| <a id="sc-s1"></a>SC-S1 | Spoofing | A counterfeit component or an impostor update server is accepted as genuine. | [C-SBOM](#c-sbom), [C-BOOT](#c-boot), [C-TLS](#c-tls) | Counterfeits that are functionally identical until they fail. |
| <a id="sc-t1"></a>SC-T1 | Tampering | A malicious or vulnerable third-party component enters the build. | [C-SBOM](#c-sbom), [C-REPRO](#c-repro) | Vulnerabilities in components that are correctly inventoried but not yet disclosed. |
| <a id="sc-r1"></a>SC-R1 | Repudiation | Nobody can establish which firmware and components were shipped on which unit. | [C-CM](#c-cm), [C-SBOM](#c-sbom) | Field modifications outside configuration control. |
| <a id="sc-i1"></a>SC-I1 | Information disclosure | Source code or signing keys leak from the build pipeline. | [C-KEY](#c-key), [C-LEAST](#c-least) | Insiders with legitimate access. |
| <a id="sc-d1"></a>SC-D1 | Denial of service | A faulty update disables the fleet, or a sole-source part becomes unavailable. | [C-STAGED](#c-staged), [C-CM](#c-cm) | Long-lead obsolescence. |
| <a id="sc-e1"></a>SC-E1 | Elevation of privilege | A compromised build system signs attacker-supplied code with genuine keys. | [C-KEY](#c-key), [C-REPRO](#c-repro) | Signing infrastructure is a single point of trust. |

## Control catalogue

| ID | Control | What it means | Counters | References |
|---|---|---|---|---|
| <a id="c-sign"></a>C-SIGN | Authenticated datalink with anti-replay | Per-vehicle link keys, message authentication on every command and telemetry frame, strictly increasing timestamps or counters. | AV-R1, CC-S1, DL-S1, DL-S2, DL-T1, DL-E1 | MAVLink 2 message signing; RFC 2104 |
| <a id="c-enc"></a>C-ENC | Link encryption | Confidentiality for commands, telemetry and video where the mission requires it. Complements, does not replace, authentication. | DL-T1, DL-I1 | NIST SP 800-207 |
| <a id="c-cmdauthz"></a>C-CMDAUTHZ | Command authorisation by role | Safety-critical and configuration commands (parameter write, firmware upload, arming) allowed only from explicitly authorised identities and flight phases. | CC-E1, DL-E1 | NIST SP 800-207 |
| <a id="c-div"></a>C-DIV | Link diversity and tested lost-link behaviour | Independent bearers where justified; documented and tested behaviour on link loss. | AV-D1, DL-D1 | ASTM F3269 |
| <a id="c-navx"></a>C-NAVX | Multi-source navigation integrity | Inertial, visual and absolute sources cross-checked by an estimator with innovation gating and independent consistency monitors; defined behaviour on disagreement. | AV-S1, AV-D1 | Psiaki and Humphreys 2016; Groves 2013 |
| <a id="c-gnssauth"></a>C-GNSSAUTH | GNSS interference detection and authenticated signals | Monitor power, C/N0 and clock behaviour; use navigation message authentication where available. | AV-S1 | EUSPA Galileo OSNMA; Psiaki and Humphreys 2016 |
| <a id="c-boot"></a>C-BOOT | Secure boot and signed firmware with anti-rollback | Each stage verifies the next against a hardware root of trust; images carry a monotonic security version. | AV-T1, AV-E1, CC-T1, SC-S1 | NIST SP 800-193; NIST SP 800-147 |
| <a id="c-debug"></a>C-DEBUG | Locked debug interfaces | Hardware debug ports disabled or authenticated in production units. | AV-T1, AV-E1 | NIST SP 800-193 |
| <a id="c-phys"></a>C-PHYS | Physical tamper evidence | Seals, enclosure switches and inspection on recovery of a vehicle. | AV-T1 | IEC 62443-4-2 |
| <a id="c-key"></a>C-KEY | Key management and zeroisation | Keys in secure elements or HSMs, unique per device, rotated, revocable, and erased on tamper or loss. | AV-I1, DL-S1, DL-R1, GCS-I1, SC-I1, SC-E1 | NIST SP 800-57 |
| <a id="c-data"></a>C-DATA | Encryption at rest and data minimisation | Full-disk encryption on ground and onboard storage; keep only what the mission needs. | AV-I1, CC-I1, GCS-I1 | NIST SP 800-111 |
| <a id="c-seg"></a>C-SEG | Segmentation with a constrained conduit | Companion computer reaches the flight controller only through an allow-listed, validated command set. | CC-S1, CC-D1, CC-E1 | IEC 62443-3-3 zones and conduits |
| <a id="c-least"></a>C-LEAST | Least privilege | Services run unprivileged; accounts, tokens and processes get only the rights they need. | CC-I1, CC-E1, GCS-E1, API-I1, API-E1, SC-I1 | NIST SP 800-207 |
| <a id="c-rta"></a>C-RTA | Runtime assurance and resource limits | Watchdogs, resource quotas and a simple verified fallback that takes over if complex software misbehaves. | CC-D1 | ASTM F3269 |
| <a id="c-ep"></a>C-EP | Hardened ground endpoint | Dedicated device, patched by version, application allow-listing, no general browsing or email, endpoint monitoring. | GCS-S1, GCS-T1, GCS-D1, GCS-E1 | NIST SP 800-123 |
| <a id="c-mfa"></a>C-MFA | Individual accounts with phishing-resistant MFA | No shared operator accounts; hardware-backed authenticators for ground, cloud and fleet logins. | GCS-S1, GCS-R1, API-S1 | NIST SP 800-63B |
| <a id="c-integ"></a>C-INTEG | Signed mission and configuration files | Mission plans, geofences and parameter sets are signed by the planning authority and verified before use. | GCS-T1, API-T1 | NIST SP 800-207 |
| <a id="c-log"></a>C-LOG | Tamper-evident, time-synchronised logging | Hash-chained logs on vehicle, ground and cloud, anchored off-device, with authenticated time. | AV-T1, AV-R1, CC-R1, DL-R1, GCS-R1, API-T1, API-R1 | NIST SP 800-92 |
| <a id="c-spare"></a>C-SPARE | Redundant ground capability | Tested spare GCS and a procedure to transfer control. | GCS-D1 | ASTM F3269 |
| <a id="c-token"></a>C-TOKEN | Short-lived, scoped, bound tokens | Access tokens with short expiry, narrow scope, refresh rotation and sender constraint. | API-S1 | OAuth 2.0 Security Best Current Practice (RFC 9700) |
| <a id="c-api"></a>C-API | Object- and function-level authorisation | Every request authorised server-side for the specific object and function, from the caller's identity. | API-T1, API-I1, API-E1 | OWASP API Security Top 10 |
| <a id="c-rate"></a>C-RATE | Rate limiting and abuse protection | Quotas and throttling on APIs and on link message handling. | DL-D1, API-D1 | OWASP API Security Top 10 |
| <a id="c-offline"></a>C-OFFLINE | Degraded local operation | Core flight and mission functions continue without the cloud; synchronisation resumes later. | API-D1 | NIST SP 800-207 |
| <a id="c-tls"></a>C-TLS | Authenticated transport | Mutual TLS or certificate validation for every service connection, including update downloads. | CC-I1, SC-S1 | NIST SP 800-52 |
| <a id="c-sbom"></a>C-SBOM | SBOM and component provenance | Machine-readable inventory of software and hardware components with origin; vulnerability monitoring against it. | CC-T1, SC-S1, SC-T1, SC-R1 | NTIA SBOM minimum elements; EU Cyber Resilience Act |
| <a id="c-repro"></a>C-REPRO | Build provenance and reproducible builds | Signed build attestations; independent rebuilds confirm binaries match source. | CC-T1, SC-T1, SC-E1 | SLSA; Reproducible Builds |
| <a id="c-cm"></a>C-CM | Configuration management | Record of what hardware, firmware and software is on which unit. | CC-R1, SC-R1, SC-D1 | ISO 10007 |
| <a id="c-staged"></a>C-STAGED | Staged rollout with recovery | Updates reach a small group first; a known-good image can be restored. | API-E1, SC-D1 | NIST SP 800-193 |
| <a id="c-ir"></a>C-IR | Incident response plan | Procedures for compromised GCS, leaked keys and suspected spoofing, with contacts and reporting obligations. | GCS-D1 | NIST SP 800-61 |
