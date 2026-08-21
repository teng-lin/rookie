import assert from "node:assert/strict";
import test from "node:test";

import {
  applicableScenarios,
  buildExpectedManifest,
  expandedValue,
  selectedTiers,
} from "./seed_cookie_corpus.mjs";

const identities = {
  filtered_flat: ["domain", "path", "name"],
  unfiltered_flat: ["domain", "path", "name"],
  detailed: [
    "cookie.domain",
    "cookie.path",
    "cookie.name",
    "context.partition_key",
  ],
};

function scenario(id, origin, name, { stored = true } = {}) {
  return {
    id,
    tiers: ["portable_smoke"],
    applicability: {
      engines: ["chromium", "firefox"],
      platforms: [process.platform],
    },
    origin,
    operations: [
      {
        phase: "initial",
        name,
        value: stored ? id : "stale",
        path: "/",
        max_age: stored ? 3600 : 0,
        same_site: "Lax",
      },
    ],
    expected: { stored, same_site: { chromium: 1, firefox: 1 } },
  };
}

function corpus() {
  return {
    schema_version: 1,
    default_tiers: ["portable_smoke"],
    tiers: {
      portable_smoke: {},
      deep: {},
      stress: {},
    },
    origins: {
      primary: { hostname: "127.0.0.1", included_by_domain_filter: true },
      decoy: { hostname: "localhost", included_by_domain_filter: false },
    },
    identities,
    context_expectations: {
      chromium: {
        top_frame_site_key: null,
        has_cross_site_ancestor: false,
        source_scheme: "@source_scheme",
        source_port: "@source_port",
        is_persistent: "@is_persistent",
        origin_attributes: null,
        user_context_id: null,
        partition_key: null,
        private_browsing_id: null,
      },
    },
    scenarios: [
      scenario("primary", "primary", "rookie_primary"),
      scenario("decoy", "decoy", "rookie_decoy"),
      scenario("deleted", "primary", "rookie_deleted", { stored: false }),
    ],
  };
}

test("tier and applicability selection is declarative", () => {
  const declaration = corpus();
  assert.deepEqual(selectedTiers(declaration, {}), ["portable_smoke"]);
  assert.equal(
    applicableScenarios(
      declaration,
      "chromium",
      ["portable_smoke"],
      process.platform,
    ).length,
    3,
  );
  assert.throws(
    () => selectedTiers(declaration, { ROOKIE_E2E_CORPUS_TIERS: "unknown" }),
    /unknown cookie corpus tier/,
  );
});

test("value-repeat expansion is deterministic", () => {
  assert.equal(expandedValue({ value_repeat: { text: "ab", count: 3 } }), "ababab");
});

test("manifest separates filtered, unfiltered, and detailed exact sets", () => {
  const declaration = corpus();
  const observedCookies = [
    {
      domain: "127.0.0.1",
      path: "/",
      name: "rookie_primary",
      value: "primary",
      secure: false,
      httpOnly: false,
      sameSite: "Lax",
      expires: 4_102_444_800,
    },
    {
      domain: "localhost",
      path: "/",
      name: "rookie_decoy",
      value: "decoy",
      secure: false,
      httpOnly: false,
      sameSite: "Lax",
      expires: 4_102_444_800,
    },
  ];
  const manifest = buildExpectedManifest({
    corpus: declaration,
    engine: "chromium",
    tiers: ["portable_smoke"],
    platform: process.platform,
    baseUrl: "http://127.0.0.1:8765/set",
    observedCookies,
    browserVersion: "unit-test",
    userAgent: "unit-test",
  });
  assert.equal(manifest.expected.filtered_flat.length, 1);
  assert.equal(manifest.expected.unfiltered_flat.length, 2);
  assert.equal(manifest.expected.detailed.length, 2);
  assert.equal(manifest.expected.detailed[0].context.source_port, 8765);
  assert.equal(manifest.expected.detailed[0].context.is_persistent, true);
  assert.deepEqual(manifest.excluded, [
    { scenario_id: "deleted", reason: "expected_not_stored" },
  ]);
});

test("unexpected browser cookies cannot silently enter expected output", () => {
  const declaration = corpus();
  assert.throws(
    () =>
      buildExpectedManifest({
        corpus: declaration,
        engine: "chromium",
        tiers: ["portable_smoke"],
        platform: process.platform,
        baseUrl: "http://127.0.0.1:8765/set",
        observedCookies: [
          {
            domain: "other.test",
            path: "/",
            name: "not_declared",
            value: "secret",
            secure: false,
            httpOnly: false,
            sameSite: "Lax",
            expires: 4_102_444_800,
          },
        ],
        browserVersion: "unit-test",
        userAgent: "unit-test",
      }),
    /expected exactly one accepted browser cookie/,
  );
});
