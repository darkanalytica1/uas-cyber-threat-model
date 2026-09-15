# Sources

The threat model, code and diagrams are original synthesis from public standards and literature. No vulnerability, incident or assessment result concerning any real product or organisation is used.

## Protocols and cryptography

1. MAVLink Developer Guide, *Message Signing* (mavlink.io/en/guide/message_signing.html). Signature block, key length, timestamp units, acceptance rules.
2. MAVLink Developer Guide, *Serialization* (mavlink.io/en/guide/serialization.html). MAVLink 2 header, incompatibility flags, CRC and CRC extra.
3. H. Krawczyk, M. Bellare and R. Canetti, RFC 2104, *HMAC: Keyed-Hashing for Message Authentication*, 1997.
4. NIST FIPS 180-4, *Secure Hash Standard*. SHA-256.
5. NIST SP 800-107 Rev. 1, *Recommendation for Applications Using Approved Hash Algorithms*. Truncated MACs.
6. NIST SP 800-57 Part 1, *Recommendation for Key Management*.

## Threat modelling and architecture

7. A. Shostack, *Threat Modeling: Designing for Security*, Wiley, 2014. STRIDE.
8. Microsoft, *The STRIDE Threat Model* (public documentation).
9. NIST SP 800-154 (draft), *Guide to Data-Centric System Threat Modeling*.
10. NIST SP 800-207, *Zero Trust Architecture*, 2020.
11. IEC 62443-3-3 and 62443-4-2, *Security for industrial automation and control systems*. Zones and conduits; component requirements.
12. MITRE ATT&CK for ICS (attack.mitre.org). Adversary technique catalogue.

## Firmware, supply chain and endpoints

13. NIST SP 800-193, *Platform Firmware Resiliency Guidelines*, 2018.
14. NIST SP 800-147, *BIOS Protection Guidelines*. Authenticated update and rollback.
15. NTIA, *The Minimum Elements for a Software Bill of Materials*, 2021.
16. SLSA, *Supply-chain Levels for Software Artifacts* (slsa.dev); Reproducible Builds project (reproducible-builds.org).
17. Regulation (EU) 2024/2847, *Cyber Resilience Act*. Vulnerability handling and SBOM obligations for products with digital elements.
18. NIST SP 800-123, *Guide to General Server Security*; NIST SP 800-111, *Guide to Storage Encryption Technologies*.
19. NIST SP 800-63B, *Digital Identity Guidelines: Authentication*. Phishing-resistant authenticators.

## Web, API and identity

20. OWASP, *API Security Top 10*, 2023. Broken object-level and function-level authorisation.
21. RFC 9700, *OAuth 2.0 Security Best Current Practice*, 2025.
22. NIST SP 800-52 Rev. 2, *Guidelines for TLS Implementations*.

## Logging, response and assurance

23. NIST SP 800-92, *Guide to Computer Security Log Management*.
24. S. A. Crosby and D. S. Wallach, "Efficient Data Structures for Tamper-Evident Logging", *USENIX Security*, 2009.
25. NIST SP 800-61, *Computer Security Incident Handling Guide*.
26. ASTM F3269, *Standard Practice for Methods to Safely Bound Behavior of Aircraft Systems Containing Complex Functions Using Run-Time Assurance*.

## Navigation integrity

27. M. L. Psiaki and T. E. Humphreys, "GNSS Spoofing and Detection", *Proceedings of the IEEE*, 104(6), 2016.
28. P. D. Groves, *Principles of GNSS, Inertial, and Multisensor Integrated Navigation Systems*, 2nd ed., Artech House, 2013.

## Confidence

| Claim type | Confidence | Why |
|---|---|---|
| MAVLink 2 signing structure and acceptance rules | High | Public protocol specification; implemented and tested |
| Forgery probability arithmetic | High | Direct calculation; reproduced by tests |
| STRIDE mapping and controls | Medium to high | Standard practice; the mapping to a generic UAS is the author's synthesis |
| Residual risk statements | Judgement | Generic; must be reassessed for a specific system and mission |
