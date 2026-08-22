# Browser-generated cookie fixture capture

`capture_browser_cookie_fixture.py` turns a disposable browser profile's cookie
database into a sanitized review candidate with machine-readable provenance.
It is intentionally not a general profile-export tool.

## Safety contract

The command fails unless all of the following are true:

- `--source-database` is below an explicit `--source-root`;
- that root contains `.rookie-cookie-fixture-source.json` with
  `kind: rookie-cookie-fixture-source` and `schema_version: 1`;
- both outputs are outside the source root and do not already exist;
- the retained cookie identities exactly match an independent expected
  manifest;
- every cookie not present in the manifest is removed;
- rows in non-cookie tables are removed, except Chromium's safe schema-version
  metadata;
- SQLite runs with secure deletion and vacuums the sanitized database before
  it becomes the output artifact.

Never place the disposable marker in a normal browser profile. Never pass a
real user's browser database, `Local State`, history, cache, credentials, or
other profile files to this command. The manual CI workflow is the preferred
capture environment.

## Marker

The workflow creates this file at the root of its temporary profile before the
browser launches:

```json
{
  "schema_version": 1,
  "kind": "rookie-cookie-fixture-source",
  "source_kind": "disposable_e2e_profile"
}
```

The marker authorizes only the database contained below that one root. It does
not opt other profiles on the same machine into capture.

## Expected manifest

The browser seeder produces or is paired with an independent manifest. A flat
record is accepted, as is the detailed `{ "cookie": ..., "context": ... }`
shape. The exact corpus manifest's `expected.detailed` array is accepted
directly as well:

```json
{
  "schema_version": 1,
  "engine": "firefox",
  "cookies": [
    {
      "cookie": {
        "domain": ".example.test",
        "path": "/",
        "name": "rookie_fixture",
        "value": "synthetic"
      },
      "context": {
        "origin_attributes": ""
      }
    }
  ]
}
```

Chromium identity additionally includes `top_frame_site_key` and
`has_cross_site_ancestor`; Firefox identity includes the complete
`origin_attributes` value. Values remain in the expected manifest for decoder
verification, but the capture sanitizer does not attempt to decrypt Chromium
rows.

## Output provenance

The provenance JSON records:

- browser product, version, and build ID;
- engine, platform, and architecture;
- expected-manifest and sanitized-fixture SHA-256 digests;
- retained identities and before/after row counts;
- `sqlite_master` objects and `PRAGMA table_xinfo` results;
- Chromium `version` and `compatible_version` metadata when present.

Review the database, provenance JSON, and expected manifest together. A
committed fixture must also be documented with its capture date and exact
browser download/build source, following
[`rookie-rs/src/browser/fixtures/README.md`](../../rookie-rs/src/browser/fixtures/README.md).

## Direct invocation

Use only a newly-created disposable profile:

```console
python3 tests/e2e/capture_browser_cookie_fixture.py \
  --source-root "$DISPOSABLE_PROFILE" \
  --source-database "$DISPOSABLE_PROFILE/cookies.sqlite" \
  --output-database firefox-candidate.sqlite \
  --expected-manifest accepted-cookie-manifest.json \
  --provenance-output firefox-candidate.provenance.json \
  --engine firefox \
  --browser Firefox \
  --browser-version 142.0 \
  --build-id 20250811145442
```

The capture workflow uploads candidates for review; it never commits them and
has read-only repository permissions. Its `playwright_version` input is the
version pin for capturing current and previous redistributable browser schema
generations; each resulting candidate remains a manually reviewed artifact.
