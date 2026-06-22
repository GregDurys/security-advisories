# Cohesity TranZman Security Advisories

This directory contains security advisories for vulnerabilities discovered in
Cohesity TranZman Migration Appliance (formerly Stone Ram TranZman).

## Summary

During an authorised security assessment in September 2025, five vulnerabilities
were identified in TranZman Release 4.0 Build 14614. These vulnerabilities allow
authenticated administrators to escape the intended restricted shell environment,
escalate privileges to root, execute arbitrary code, and recover stored credentials
through weak cryptographic protections.

## About TranZman

TranZman is a migration appliance developed by Stone Ram Limited (acquired by
Cohesity in October 2025) used to facilitate migrations between NetBackup
domains. It is deployed as a virtual appliance (OVA) and is intended as a
temporary solution used solely for the duration of the migration process.

Core components include:

- Web application for administration
- CLISH restricted shell for SSH access
- FTP daemon for file transfers
- Message queue service
- TZM Recorder utility for NetBackup environment assessment

For more information, see the [TranZman product page](https://www.stoneram.com/tranzman-overview).

| CVE | Vulnerability | CVSS v3.1 | Severity |
| --- | --- | --- | --- |
| [CVE-2025-67840](CVE-2025-67840.md) | Web API Command Injection | 7.2 | High |
| [CVE-2025-63911](CVE-2025-63911.md) | CLISH Command Injection | 7.2 | High |
| [CVE-2025-63909](CVE-2025-63909.md) | Local Privilege Escalation | 7.2 | High |
| [CVE-2025-63910](CVE-2025-63910.md) | Unsigned Patch Upload | 7.2 | High |
| [CVE-2025-63912](CVE-2025-63912.md) | Weak Cryptography (Static XOR) | 5.5 | Medium |

## Affected Products

- Product: Cohesity TranZman Migration Appliance (formerly Stone Ram TranZman)
- Vendor: Cohesity, Inc. (acquired Stone Ram Limited, October 2025)
- Affected Versions: Release 4.0 Build 14614
  including patch TZM_1757588060_SEP2025_FULL.depot

## Remediation

Cohesity has released patches addressing these vulnerabilities.
Apply the following updates in order:

1. `TZM_patch_1.patch`
2. `TZM_1760106063_OCT2025R2_FULL.depot`

A new OVA version incorporating all fixes was planned for release in late
November 2025. Contact Cohesity support for the latest patched version.

## Disclosure Timeline

| Date | Event |
| --- | --- |
| 12-26 September 2025 | Security assessment conducted |
| 26 September 2025 | Vulnerabilities reported to Cohesity |
| 17 October 2025 | Initial CVE requests submitted to MITRE |
| 20 October 2025 | Cohesity confirmed patches available |
| October-November 2025 | CVE IDs assigned by MITRE |
| 25 December 2025 | Embargo period ends (90 days) |
| 27 December 2025 | Public disclosure |

## Credit

Discovered by Greg Durys, LME

Contact: `gregdurys.security@proton.me`
