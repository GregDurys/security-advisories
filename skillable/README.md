# Skillable SCORM launch: userId parameter not validated against session token allows allocation bypass and cross-user DoS

## Identifiers

- CVE: [CVE-2026-56877](https://www.cve.org/CVERecord?id=CVE-2026-56877)

## Affected project

- Vendor: [Skillable](https://www.skillable.com) (formerly Learn on Demand Systems)
- Product: Skillable hosted lab platform, SCORM launch integration (cloud service, no on-premises deployment)
- Language/runtime: ASP.NET Core (Microsoft-IIS/10.0), client-side SCORM JavaScript launch flow

## Affected component

`scorm.skillable.com/scorm/launch` - lab launch endpoint that enforces the per-user launch limit against a client-supplied `userId` query parameter

## Affected versions

- Tested affected: `scorm.skillable.com` production endpoint as observed between 2026-04-28 and 2026-05-11
- Fixed commit: none. Skillable classifies the behaviour as an inherent limitation of the SCORM standard and has stated no fix is planned for the SCORM launch path. The remediation offered to customers is migration to an API or LTI 1.3 launch integration.

## Severity

- CVSS 3.1 Base Score: 6.5 (Medium)
- Vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

The score covers the confirmed denial of service across enrolled users. Skillable subsequently identified a possible exposure of another learner's active or saved session data through the same launch response, which was not independently verified by the reporter and is not reflected in this score.

## CWE

- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

## Summary

The Skillable SCORM lab launch endpoint validates the SCORM session token as an enrolment check, then evaluates the per-user launch limit against a `userId` query parameter the browser supplies. The token and the `userId` are never cross-validated. An authenticated student can modify the `userId` on the launch request to bypass the per-user launch limit, provision additional concurrent lab instances, and consume the lab allocation of other enrolled users. The parameter accepts arbitrary strings with no format validation, including values that are not valid hexadecimal and structures that are entirely fabricated.

## Impact

Any enrolled student can launch lab instances beyond the configured per-user limit and can deny another student access by consuming that student's allocation. Each launch under a distinct `userId` provisions real cloud virtual machines (typically a domain controller plus one to three additional machines, active for 30 to 60 minutes) at the course provider's expense. Where the same SCORM launch mechanism serves a certification exam, consuming a victim's single-use exam attempt would deny them the ability to sit the exam and trigger the associated cooldown. Combined with a user enumeration vector on the learning management system, an attacker could obtain the `userId` values of the enrolled population and scale allocation exhaustion across the full student body.

## Deployment context

The behaviour was observed on the Zero Point Security platform (now operated by Fortra), which uses Skillable's SCORM integration to provision the Red Team Ops course labs and exam. The same launch pattern applies to any Skillable customer whose SCORM integration passes a client-supplied `userId` to the launch endpoint. Skillable serves enterprise training providers including Microsoft, IBM, CompTIA, and Pearson VUE.

## Technical details

The SCORM lab launch flow operates in five steps:

1. The student opens a lab unit in the LearnWorlds course player.
2. LearnWorlds loads the SCORM token and constructs the launch URL, dropping the student's `userId` in as a query parameter.
3. The browser requests the launch URL from `scorm.skillable.com`.
4. Skillable validates the SCORM token as an enrolment check, then evaluates the per-user launch limit against the supplied `userId`.
5. If the limit has not been exceeded, a lab instance is provisioned and a one-time access URL is returned.

The vulnerability is in step 4. The token answers one question (is this session enrolled) and the `userId` answers another (whose allocation does this launch count against), but only the token is a value the server can trust, and the two are never checked against each other. Every layer of the launch flow runs client-side, so by the time the request reaches `scorm.skillable.com` the token, the `userId`, and the rest of the query string have all passed through JavaScript the student controls.

The `userId` parameter accepts arbitrary strings with no format validation. Both `683175c1ac36b0299c24b31g` (valid length, non-hexadecimal final character) and `000000000000000000000001` (a fabricated structure) were accepted and provisioned lab instances. The same SCORM token launches labs under different `userId` values, confirming the token is not bound to a specific user identity. Each launch under a distinct `userId` creates a separate `LabInstanceId` and provisions real cloud virtual machines.

Launching the target lab a second time under the original `userId` returns the per-user limit error:

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/problem+json; charset=utf-8
Server: Microsoft-IIS/10.0

{
    "type": "https://tools.ietf.org/html/rfc7231#section-6.6.1",
    "title": "An error occurred while processing your request.",
    "status": 500,
    "detail": "Sorry, you have taken this lab the maximum number of 1 times.",
    "traceId": "[REDACTED]"
}
```

Replaying the same launch with a single character of the `userId` altered returns 200 with a fresh instance:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Server: Microsoft-IIS/10.0

{
    "LabInstanceId": "[REDACTED]",
    "Url": "https://labclient.labondemand.com/access/[REDACTED]",
    "Status": 1
}
```

Both the original instance and the bypassed instance run simultaneously, each with its own virtual machine environment and countdown timer.

### Cross-user denial of service

A consenting colleague's `userId` was obtained through an authenticated user enumeration vector on the LMS. A single practice lab was then launched under that `userId`. The colleague then attempted to launch the same lab and received a launch error while his other labs launched normally. Only the targeted lab was locked out, matching how a consumed per-user allocation presents to the victim.

### Related endpoint

The `/scorm/details/{LabInstanceId}?token=` endpoint is accessible for any instance launched by the same token, regardless of which `userId` was used, and returns lab status, exam pass or fail, and score fields. This was observed for practice labs only, not tested against exam instances. Practical impact of this endpoint is limited, since the attacker controls the instance in question.

## Remediation

Skillable has stated no fix is planned for the SCORM launch path. The following would remove the primitive:

1. Derive the `userId` used for allocation from the authenticated SCORM token's claims rather than the client-supplied query parameter, and reject requests where the supplied `userId` does not match the authenticated identity.
2. Enforce launch limits per SCORM token or authenticated session rather than per `userId` string.
3. Apply rate limiting to the SCORM launch endpoint.
4. Log and alert on `userId` mismatches between the SCORM token and the query parameter.

The vendor-recommended path for customers is migration away from the SCORM launch integration to an API or LTI 1.3 integration, which carries a verified identity the server can check rather than a `userId` the browser supplies.

## Disclosure timeline

| Date | Event |
| ------ | ------- |
| 2026-04-28 | `userId` modification via proxy match-and-replace rule returned a new `LabInstanceId` |
| 2026-04-29 | Concurrent lab instances confirmed against the reporter's own account |
| 2026-04-30 | Consenting colleague contacted for a cross-user test |
| 2026-05-03 | Cross-user denial of service confirmed |
| 2026-05-08 | Findings documented; Skillable support ticket #4043837 raised; disclosure channel provided |
| 2026-05-11 | Report submitted to Disclosures@skillable.com |
| 2026-05-12 | Report shared with Daniel Duggan (Zero Point Security / Fortra) for visibility |
| 2026-05-13 | Skillable acknowledged receipt (Nat Shere, Manager, Product Security) |
| 2026-05-19 | CVE request submitted to MITRE (Skillable not a CNA) |
| 2026-05-27 | Status request to Skillable, no response |
| 2026-06-08 | Second follow-up, restating the 60-day window closing on 2026-07-12 |
| 2026-06-10 | Skillable responded that the behaviour is an inherent flaw in the SCORM technology; requested no disclosure without written permission |
| 2026-06-10 | Pushback sent; open-ended embargo declined; 2026-07-12 date held |
| 2026-06-23 | MITRE reserved CVE-2026-56877; technical details embargoed until 2026-07-12 |
| 2026-06-26 | Skillable customer advisory sent (Paul Adkins, VP, Security Operations); coordination update sent to Skillable |
| 2026-07-12 | Advisory published |

## Current status

- Affected endpoint: unfixed. Skillable classifies the behaviour as an inherent SCORM limitation and plans no fix on the SCORM launch path.
- Vendor customer action: private migration advisory issued to affected customers on 2026-06-26 recommending migration to an API or LTI 1.3 integration.
- [CVE-2026-56877](https://www.cve.org/CVERecord?id=CVE-2026-56877), reserved by MITRE as CNA of last resort on 2026-06-23.

## Testing disclosure

All validation was performed within a normal student workflow. A small number of lab launches were made with fabricated `userId` values against the reporter's own account to confirm the bypass, and each instance auto-expired within its standard timer. A single additional launch was performed using a consenting colleague's `userId` to confirm cross-user impact; the colleague independently verified the lockout and confirmed it as expected. No other students' accounts were accessed or affected. The certification exam endpoint was not tested; the exam scenario is inferred by parity with the confirmed practice-lab behaviour. All SCORM tokens shown have been redacted or randomised and are single-use or expired.

## Credit

Discovered by [GregDurys](https://github.com/GregDurys).

## References

- CVE record: [CVE-2026-56877](https://www.cve.org/CVERecord?id=CVE-2026-56877)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- Vendor trust page: [trust.skillable.com](https://trust.skillable.com)
- Blog post: [Beyond CRTO: Skillable](https://payloadforge.io/beyond-crto-skillable/)
