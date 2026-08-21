# Linux confidential-session cryptography review

## Current status

The Linux Secret Service confidential-session path contains fixed-width MODP
Diffie-Hellman arithmetic and a zeroizing SHA-256/HMAC/HKDF implementation in
`rookie-rs/src/linux/zeroizing_dh.rs` and `zeroizing_hkdf.rs`. The code has
known-answer and independent-reference tests, but **no independent specialist
review has been completed or claimed**.

The in-tree implementation exists because keyed state and intermediate values
must be wiped, while the otherwise suitable general-purpose contexts did not
provide the required zeroization guarantees when this code was written. That
tradeoff does not make custom cryptography self-validating.

## Required review record

Before describing these primitives as independently reviewed, add a dated
record to this file containing all of the following:

- reviewer identity, relevant expertise, and independence from the author;
- exact commit and files reviewed;
- protocol references and threat model used;
- checks performed for arithmetic correctness, peer-key validation,
  constant-time behavior, memory cleanup, and interoperability;
- every finding, its severity, and its resolution commit; and
- any residual risks or conditions that require re-review.

A substantive change to the arithmetic, key validation, SHA-256/HMAC/HKDF
logic, or confidential-session transcript invalidates the prior scope and must
be reviewed again. Formatting, tests, and comments alone do not.

## Continuous evidence

CI runs known-answer tests, independent arithmetic reference cases, coverage
ratchets for security/error-policy code, and sanitizer-backed fuzz targets for
the untrusted parser boundaries. Those controls can find regressions; they are
not a substitute for the independent review above.

The deprecated Internet Explorer path remains a separate native-parser risk:
`libesedb` executes in the caller's process on Windows. The portable ESE record
fuzzer intentionally does not claim to sandbox or fuzz that C parser. Removal
or a real subprocess boundary requires a compatibility decision for a future
release.
