# Security notes

This is the in-repo security record for shipped behavior and pinned native
parsers. To report a vulnerability privately, follow the root
[`SECURITY.md`](../SECURITY.md) policy.

| Document | When to read it |
| --- | --- |
| [security-corrections.md](security-corrections.md) | A security-relevant behavior change that *intentionally* differs from ADR 0001 compatibility (zeroization, ciphertext precedence, Debug redaction, …). Append-only ledger. |
| [sqlite-security.md](sqlite-security.md) | Which SQLite amalgamation release artifacts ship, the source ID, and the 90-day review. Updated on a calendar / release, not when extraction semantics change. |
| [cryptography-review.md](cryptography-review.md) | Review requirements and current independent-review status for the Linux Secret Service DH/HKDF implementation. |
| [troubleshooting.md](troubleshooting.md) | Keychain prompts, Safari Full Disk Access, empty session-cookie results. |
| [ADR 0001](adr/0001-cookie-extraction-compatibility-and-report-contracts.md) | The compatibility contract those corrections amend. |

Do not merge the corrections table with the SQLite inventory: they have
different owners of *when the file changes*. Report a new vulnerability through
the private channel in `SECURITY.md`, not by editing these files.
