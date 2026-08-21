# Security policy

## Supported versions

Security fixes are applied to the current `0.6.x` prerelease line and the
default branch. Older releases and the archived upstream project are not
supported. If a fix cannot be backported safely, maintainers may require an
upgrade to the next `0.6.x` release.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use
[GitHub's private vulnerability reporting form](https://github.com/teng-lin/rookie-cookies/security/advisories/new).
Include the affected version or commit, operating system, reproduction steps,
impact, and any suggested mitigation. Do not include real browser profiles,
cookies, keys, credentials, or other personal data; use a synthetic fixture.

If the private form is unavailable, open a public issue containing no
sensitive details and ask a maintainer to establish a private channel.

## What to expect

These are response targets, not guarantees:

- acknowledgement within three business days;
- an initial severity and scope assessment within seven business days;
- a status update at least every 14 days while remediation is active; and
- coordinated publication of a fix and advisory when affected users can act.

Please allow up to 90 days for coordinated disclosure unless active
exploitation or another material risk requires a different timeline. The
reporter and maintainers should agree on attribution before publication.

## Scope and safe research

The Rust core, Python and Node bindings, CLI, release artifacts, browser-file
parsers, credential-provider boundaries, and Windows App-Bound recovery are in
scope. Research must use systems and browser profiles you own or are expressly
authorized to test. Do not access another person's cookies or credentials,
degrade third-party services, or publish an exploit before coordination is
complete.

Project security notes and parser inventories live in
[`docs/security.md`](docs/security.md). That engineering record does not
replace this reporting policy.
