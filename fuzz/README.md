# Parser fuzzing

These libFuzzer targets exercise byte boundaries shared by production code:

- `portable_decoders`: Chromium SQLite row values, Safari BinaryCookies, and
  the platform-neutral ESE record decoder;
- `mozilla_session`: Firefox legacy JSON and bounded mozLz4 containers; and
- `source_classifier`: portable SQLite, BinaryCookies, and ESE signatures.

Run one target with a pinned nightly toolchain:

```console
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2025-11-23 fuzz run portable_decoders -- \
  -max_total_time=60 -timeout=10 -max_len=4096 -rss_limit_mb=2048
```

The nightly CI lane runs every target with libFuzzer's default sanitizer
instrumentation. Manual dispatches use a shorter smoke budget; this assurance
workflow does not run on pull requests. Crashes and hangs are failures;
ordinary parse errors are expected. CI also wraps the complete process in a
wall-clock timeout so sanitizer startup or harness deadlock cannot consume the
job indefinitely.

`libesedb` itself is not exercised by these portable targets. It remains an
in-process native dependency on Windows for deprecated Internet Explorer
support; removing that support or introducing a real process boundary is a
separate compatibility decision, not something this harness claims to solve.
