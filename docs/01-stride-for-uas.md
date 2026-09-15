# 01 · STRIDE applied to an unmanned aircraft system

`METHOD` Decompose the system into surfaces separated by trust boundaries, then ask all six STRIDE questions of every surface. Write down an answer for every cell, including "not applicable, because". A cell with no entry is a gap you cannot see.

## 1.1 The six categories and the property each attacks

| Letter | Threat | Property violated | Typical UAS example |
|---|---|---|---|
| S | Spoofing | Authentication | Commands accepted from a sender without the key; counterfeit GNSS position |
| T | Tampering | Integrity | Altered telemetry, mission file or firmware image |
| R | Repudiation | Non-repudiation | A mode change nobody can attribute; logs that can be edited |
| I | Information disclosure | Confidentiality | Unencrypted video revealing the operator; a lost laptop with keys |
| D | Denial of service | Availability | Jamming; a crashed companion computer; cloud outage |
| E | Elevation of privilege | Authorisation | Companion computer reaching flight control; user reaching admin API |

## 1.2 Why an unmanned aircraft is a distributed system

A small UAS is not one computer that flies. It is at least six places where trust changes hands:

| Surface | Trust boundary | Why it is different |
|---|---|---|
| Air vehicle | Radio boundary | Resource-constrained, can be captured physically |
| Companion computer | Onboard: flight-critical versus payload | Large, updatable software next to the thing that keeps the aircraft in the air |
| Datalink | Radio boundary | Anyone in range can transmit |
| Ground control station | Operator endpoint versus networks | A general-purpose computer holding keys, plans and the live picture |
| Cloud and fleet API | Organisation versus service and other tenants | Ordinary web software, now attached to aircraft |
| Supply chain and update path | Organisation versus suppliers and build systems | Cross-cuts all the others |

Securing one surface while ignoring the others secures nothing. "The link is encrypted" answers one cell of a 36-cell matrix.

## 1.3 The asset is usually the picture, not the airframe

A threat model that protects the aircraft but lets an adversary feed the operator a plausible false track has protected the wrong thing. Model the information and the decision it supports: integrity of the operator's picture, confidentiality of what is collected, availability of the platform at the moment it is needed.

## 1.4 How this repository encodes it

The model lives in [`data/threat-model.yaml`](../data/threat-model.yaml): surfaces, trust boundaries, a control catalogue, and threats that each name a surface, a STRIDE letter, the controls that counter it, and the residual risk that remains. `python -m uasthreat validate` enforces:

- every surface has at least one entry in every STRIDE column, or an explicit `not_applicable` rationale;
- every control referenced exists, and every control counters at least one threat;
- every surface sits on a declared trust boundary.

`python -m uasthreat render` turns the YAML into [MATRIX.md](MATRIX.md) and [matrix.html](matrix.html). A test fails if the committed renders drift from the data, so the matrix cannot silently go stale.

## 1.5 Using the output

- **Design review.** Walk the matrix row by row; for each control, ask for the evidence it is implemented, not only specified.
- **Procurement.** Turn each cell into a question for the supplier. "How is the link key provisioned and rotated?" is sharper than "is it secure?".
- **Assurance.** Residual risks are the honest part of the document: they state what remains after the control, which is what an accreditation authority needs to accept.

## Limitations

- STRIDE is an enumeration aid, not a risk score. Likelihood and impact need a separate assessment against a specific mission and adversary.
- The model is a generic reference architecture. A real system adds surfaces (mobile apps, payload data links, remote identification broadcasts, maintenance tooling) and removes others.
- For adversary behaviour observed in the wild, pair STRIDE with a technique catalogue such as MITRE ATT&CK for ICS.
