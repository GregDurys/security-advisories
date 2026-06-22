# Symlink following and TOCTOU in pwnlift upload handler allow arbitrary file write as root

## Identifiers

- GHSA: [GHSA-2v7v-rhpw-m9w4](https://github.com/rasta-mouse/pwnlift/security/advisories/GHSA-2v7v-rhpw-m9w4)
- CVE: requested via GHSA, rejected by GitHub 9 and 19 June; MITRE request pending since 15 June

## Affected project

- Repository: [rasta-mouse/pwnlift](https://github.com/rasta-mouse/pwnlift)
- Language/runtime: .NET / Blazor (ASP.NET Core, Kestrel)

## Affected component

`pwnlift/Components/Pages/Home.razor` - upload handler

## Affected versions

- Tested affected commit: `211f2b3` (2025-08-29)
- Initial remediation: [`e3eddac`](https://github.com/rasta-mouse/pwnlift/commit/e3eddaca42b4b3e9c69f2d7aa024b6c82e27a5a2) (addresses CWE-59, does not address CWE-367)
- Fixed commit: [`d7a9544`](https://github.com/rasta-mouse/pwnlift/commit/d7a95449d9ee1ea09ec1529286685f6187afbbed) (merged 2026-06-18)

## Severity

- **High**
- CVSS 3.1 Base Score: **7.8**
- Vector: `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`

## CWE

- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)

## Summary

The upload handler in pwnlift constructs its destination path from the caller's working directory and writes uploaded files without validating symlinks, canonicalising paths, or sanitising filenames. When pwnlift runs in a privileged execution context, a local user with filesystem access can redirect uploaded files to arbitrary locations on the host, achieving file write with the privileges of the pwnlift process.

## Impact

Arbitrary file write as root in deployments where pwnlift executes with elevated privileges. For example, writing to a privileged configuration path such as `/etc/sudoers.d/` can grant the attacker full passwordless sudo, escalating from an unprivileged local user to root.

## Deployment context

One known affected deployment ran pwnlift as root via a passwordless `sudo` entry on a shared training lab VM. Docker containment on the same host protected shared licence material; root on the VM bypassed that boundary. The downstream deployment operator confirmed the lab was patched on 28 May 2026 by removing the sudo entry for pwnlift.

The upstream code remains vulnerable in any deployment that runs pwnlift with elevated privileges.

## Technical details

### Original issue (CWE-59)

The upload handler builds its destination from `Directory.GetCurrentDirectory()`:

```csharp
var destination = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
```

The sudoers configuration does not set a `cwd=` directive, so `sudo` preserves the caller's working directory. An attacker creates a directory under their control, places an `Uploads` symlink pointing at the target (e.g. `/etc/sudoers.d`), and launches pwnlift via sudo from that directory. `Directory.Exists` returns `true` for symlinks, so `CreateDirectory` is skipped and subsequent writes follow the symlink. The client-supplied filename (`file.Name`) is used directly in `Path.Combine` without sanitisation.

### TOCTOU bypass of initial fix (CWE-367)

The initial fix in `e3eddac` added a `FileAttributes.ReparsePoint` check on the `Uploads` directory, filename sanitisation via `Path.GetFileName`, and a `StartsWith` path containment check. These changes resolve the direct symlink case but do not address the caller-controlled working directory.

Because `destination` is still derived from `Directory.GetCurrentDirectory()`, the attacker controls the parent directory containing `Uploads`. A race script alternates `Uploads` between a real directory and a symlink:

1. Create `Uploads` as a real directory - passes the `ReparsePoint` check
2. Remove it and replace with a symlink to the target - subsequent `File.WriteAllBytesAsync` follows the symlink

The `StartsWith` containment check has a separate weakness: prefix matching without a trailing directory separator means a sibling path like `/tmp/Uploads-evil` passes a `StartsWith("/tmp/Uploads")` check.

## Remediation

The complete fix requires:

1. **Replace `Directory.GetCurrentDirectory()` with `AppContext.BaseDirectory`** to anchor the upload root to the application install directory rather than the caller's working directory
2. **Canonicalise the destination** using `Path.GetFullPath`
3. **Sanitise filenames** with `Path.GetFileName` to strip directory segments
4. **Enforce path containment** with `Path.GetRelativePath(canonicalDest, path)`, rejecting rooted results, `..`, and paths beginning with `../`
5. **Retain the `ReparsePoint` check** as defence in depth
6. **Ensure the application directory and `Uploads` are owned by root** (or the privileged service account) and not writable by lower-privileged users. If `Uploads` already exists as a symlink, remove it and recreate it as a real directory before applying ownership changes

```csharp
var destination = Path.Combine(AppContext.BaseDirectory, "Uploads");
```

With `AppContext.BaseDirectory` resolving to a root-owned directory (e.g. `/opt/pwnlift/`), the attacker cannot replace `Uploads` between validation and write. The exploitable precondition is removed.

## Disclosure timeline

| Date | Event |
| ------ | ------- |
| 2026-04-30 | Privileged pwnlift deployment observed during normal lab usage |
| 2026-05-07 | Initial contact with upstream maintainer |
| 2026-05-08 | Vulnerability reproduced end-to-end in local testbed |
| 2026-05-08 | Reported to upstream maintainer and downstream deployment operator |
| 2026-05-08 | Downstream operator acknowledged and forwarded to product security team |
| 2026-05-12 | Initial fix committed upstream (`e3eddac`) with reporter credit |
| 2026-05-19 | Downstream operator declined CVE assignment on CNA scope grounds |
| 2026-05-20 | TOCTOU bypass of initial fix reproduced and reported to maintainer |
| 2026-05-28 | Downstream operator confirmed lab patched, sudo entry removed |
| 2026-05-30 | CVE requested via GHSA |
| 2026-06-09 | GitHub rejected CVE request |
| 2026-06-09 | GHSA re-review requested, clarifying that the advisory was not a test submission |
| 2026-06-15 | CVE request submitted to MITRE |
| 2026-06-18 | Final fix merged upstream (`d7a9544`); CVE re-requested via GHSA |
| 2026-06-19 | Second CVE request rejected by GitHub |

## Current status

- Downstream affected deployment: **patched** (sudo entry removed, 28 May 2026)
- Upstream final fix: **merged upstream 2026-06-18** ([`d7a9544`](https://github.com/rasta-mouse/pwnlift/commit/d7a95449d9ee1ea09ec1529286685f6187afbbed))
- CVE: **requested via GHSA, rejected by GitHub twice** (9 and 19 June); MITRE request pending since 15 June

## Testing disclosure

All testing was performed in a local testbed using pwnlift source code and a sudoers configuration matching the observed deployment. No exploitation was performed against the live environment.

## Credit

Discovered by Greg Durys ([GregDurys](https://github.com/GregDurys)).

## References

- pwnlift repository: [rasta-mouse/pwnlift](https://github.com/rasta-mouse/pwnlift)
- GHSA: [GHSA-2v7v-rhpw-m9w4](https://github.com/rasta-mouse/pwnlift/security/advisories/GHSA-2v7v-rhpw-m9w4)
- Initial fix: [`e3eddac`](https://github.com/rasta-mouse/pwnlift/commit/e3eddaca42b4b3e9c69f2d7aa024b6c82e27a5a2)
- [CWE-59: Improper Link Resolution Before File Access](https://cwe.mitre.org/data/definitions/59.html)
- [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- Blog post: [Beyond CRTO: pwnlift](https://payloadforge.io/beyond-crto-pwnlift/) (link to be updated on publication)
