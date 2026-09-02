// Drives the Node binding against the cross-language isolation collision
// corpus in `tests/isolation_corpus/`.
//
// The corpus is the shared oracle: `corpus.json` names the stores, the
// contexts, and the exact answer each context must produce, and Rust, Python,
// the CLI, and this file all assert against that one file. A collision that
// this binding decided differently from the core would show up here as a
// failing case rather than as a silent per-language dialect. Nothing in this
// file recomputes an expectation -- every assertion reads its expected value
// out of the corpus.
//
// The SQLite stores are the same bytes `build_isolation_corpus.py` writes,
// committed as base64 next to this file so the suite needs no Python at test
// time. `tests/isolation_corpus/test_build_isolation_corpus.py` is what pins
// those fixtures to a fresh generation.
import test from "ava";
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import rookieCookies from "../index.js";

const execFileAsync = promisify(execFile);

const corpus = JSON.parse(
  readFileSync(new URL("../../../tests/isolation_corpus/corpus.json", import.meta.url), "utf8"),
);

// The committed base64 store per corpus store name, plus the on-disk filename
// each engine's sniffer expects.
//
// `build_isolation_corpus.py --write-node-fixtures` emits the three isolated
// stores; the two `*_plain` fixtures were generated the same way from the same
// corpus and are needed here because the jar verdicts are per store, and the
// plain stores are the ones that must succeed. Until `NODE_FIXTURE_STORES` in
// that generator lists them too, `test_build_isolation_corpus.py` does not
// re-check them against a fresh build -- the "every corpus store has a
// committed Node fixture" test below is what keeps this map honest in the
// meantime.
const STORE_FIXTURES = {
  chromium_isolated: { fixture: "isolation-corpus-chromium.sqlite.base64", file: "Cookies" },
  chromium_plain: { fixture: "isolation-corpus-chromium-plain.sqlite.base64", file: "Cookies" },
  firefox_isolated: { fixture: "isolation-corpus-firefox.sqlite.base64", file: "cookies.sqlite" },
  firefox_unknown_attr: {
    fixture: "isolation-corpus-firefox-unknown-attr.sqlite.base64",
    file: "cookies.sqlite",
  },
  firefox_plain: { fixture: "isolation-corpus-firefox-plain.sqlite.base64", file: "cookies.sqlite" },
};

// Every omission reason `SendOmissions::entries()` yields, corpus spelling to
// the binding's camelCase field. A reason a case does not list is asserted to
// be zero, so the whole shape is pinned rather than only the parts a case
// happened to mention.
const OMISSION_FIELDS = {
  expired: "expired",
  not_applicable: "notApplicable",
  same_site: "sameSite",
  partition: "partition",
  ancestor_chain_unknown: "ancestorChainUnknown",
  unparsable_partition_key: "unparsablePartitionKey",
  origin: "origin",
};

// The corpus writes `SendContext` keys in the crate's snake_case; the binding
// takes camelCase, and spells the clock override `nowEpochSeconds` rather than
// `now` because it is an epoch-second count, not a JS `Date`.
const CONTEXT_KEYS = {
  url: "url",
  top_level_site: "topLevelSite",
  resource: "resource",
  method: "method",
  user_context_id: "userContextId",
  private_browsing_id: "privateBrowsingId",
  ancestor_chain: "ancestorChain",
  first_party_domain: "firstPartyDomain",
  gecko_view_session_context_id: "geckoViewSessionContextId",
  origin_attributes: "originAttributes",
  now: "nowEpochSeconds",
};

// Cases where the corpus and the core disagree, each with the ADR 0006
// sentence that settles which one is wrong.
//
// An entry here is a reported corpus defect, never a way to quiet a real
// binding bug: this binding does not implement matching at all -- `sendView`
// hands the context straight to `ReadResult::send_view` -- so a disagreement
// here is always between the corpus and the core. `tests/isolation_corpus/`
// is owned outside this binding, so the defect is excluded and reported
// rather than edited away. Both entries below should shrink to nothing once
// the corpus is corrected.
const EXCLUDED_CASES = new Map([
  [
    "chromium_site_ipv4_exact_host_equality_required",
    // The case's request URL, `https://7.198.51.100.7/`, is not a URL. A host
    // whose last label is all-digits is parsed as an IPv4 address, and five
    // dotted parts is not one, so WHATWG host parsing rejects it -- `new
    // URL()` in this very process rejects it identically to the `url` crate.
    // Every language therefore answers `invalid_url` here, and no
    // implementation can produce the selection the case expects.
    //
    // ADR 0006, Decision 1: "IP literals are exempt from the subdomain rule.
    // When either the request host or the top-level site host is an IPv4 or
    // IPv6 literal, site membership is exact host equality, never a subdomain
    // check". The exemption is real and is already proven by the IPv6 twin
    // `chromium_site_ipv6_exact_host_equality_required`, which passes; only
    // this case's chosen IPv4 spelling is unrealizable.
    "the request URL is unparseable under WHATWG host parsing, so every language answers invalid_url",
  ],
  [
    "firefox_unknown_attr_partitioned_row_survives_raw_selector",
    // ADR 0006, Decision 1: a partitioned Firefox row "matches when `site ==
    // top_level_site`, `port == derived top-level port`, and `f ==
    // (same_site_context && ancestor_chain == CrossSite)`".
    //
    // The case sends a same-site (subdomain) request with an explicit
    // `ancestor_chain: cross_site`, against a stored `partitionKey` of
    // `(https,rookie-a.test)` -- no `f`. The core resolves the expected `f` as
    // `sites_match && ancestor == CrossSite`, which is `true` here, so the row
    // is omitted under `partition` rather than selected.
    //
    // The corpus's own `firefox_foreign_true_requires_explicit_cross_site_ancestor`
    // needs that same reading to pass, and does pass: read literally, the
    // ADR's first term (`same_site_context`) is false whenever
    // `ancestor_chain == CrossSite`, making the conjunction constant-false and
    // a stored `,f` row unreachable from any context. The two cases cannot
    // both hold, so this one is the defect.
    "expects a stored f=false partition to match a request whose derived f is true",
  ],
]);

function toContext(context) {
  const converted = {};
  for (const [key, value] of Object.entries(context)) {
    const camel = CONTEXT_KEYS[key];
    if (!camel) {
      throw new Error(`corpus case uses an unmapped SendContext key: ${key}`);
    }
    converted[camel] = value;
  }
  return converted;
}

function expectedOmissions(omitted) {
  const expected = {};
  for (const [snake, camel] of Object.entries(OMISSION_FIELDS)) {
    expected[camel] = omitted[snake] ?? 0;
  }
  for (const key of Object.keys(omitted)) {
    if (!OMISSION_FIELDS[key]) {
      throw new Error(`corpus case uses an unmapped omission reason: ${key}`);
    }
  }
  return expected;
}

function observedOmissions(omitted) {
  const observed = {};
  for (const camel of Object.values(OMISSION_FIELDS)) {
    observed[camel] = omitted[camel];
  }
  return observed;
}

function installStore(directory, storeName) {
  const { fixture, file } = STORE_FIXTURES[storeName];
  const path = join(directory, file);
  const encoded = readFileSync(new URL(`fixtures/${fixture}`, import.meta.url), "ascii").replace(
    /\s/g,
    "",
  );
  writeFileSync(path, Buffer.from(encoded, "base64"));
  return path;
}

// `includeExpired: true` so every row the corpus counted reaches the snapshot:
// the corpus's `omitted` totals cover every row in the store, and a row dropped
// by read-time expiry would never reach the send view to be counted at all.
// Send-time expiry still applies inside `sendView` regardless of this flag.
function snapshotOptions(storeName, path) {
  const options = { path, includeExpired: true };
  if (corpus.stores[storeName].engine === "chromium") {
    // The corpus writes plaintext values and no `encrypted_value`, so there is
    // no key to fetch -- and asking for one would reach the host's real
    // keychain/credential store from a unit test.
    options.plaintextOnly = true;
    options.appBound = "disabled";
  }
  return options;
}

async function openStore(directory, storeName) {
  const path = installStore(directory, storeName);
  return rookieCookies.fromPath(snapshotOptions(storeName, path));
}

async function withTempDirectory(prefix, body) {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  try {
    await body(directory);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("every corpus store has a committed Node fixture", (t) => {
  t.deepEqual(Object.keys(STORE_FIXTURES).sort(), Object.keys(corpus.stores).sort());
});

test("the corpus is the shape this file assumes", (t) => {
  t.is(corpus.kind, "isolation-collision-corpus");
  t.is(corpus.schema_version, 1);
  t.true(corpus.cases.length > 0);

  // An exclusion that no longer names a real case is an exclusion that has
  // outlived its defect: it must be deleted, not left silently matching
  // nothing while a genuinely failing case slips through under the same name.
  const ids = new Set(corpus.cases.map((entry) => entry.id));
  for (const id of EXCLUDED_CASES.keys()) {
    t.true(ids.has(id), `excluded case ${id} is no longer in the corpus; drop the exclusion`);
  }
});

test("ancestorChain accepts the two corpus spellings and rejects anything else", async (t) => {
  await withTempDirectory("rookie-node-corpus-ancestor-chain-", async (directory) => {
    const snapshot = await openStore(directory, "chromium_plain");
    const base = { url: "https://rookie-a.test/", topLevelSite: "https://rookie-a.test" };

    for (const ancestorChain of ["same_site", "cross_site"]) {
      t.notThrows(() => snapshot.sendView({ ...base, ancestorChain }), ancestorChain);
    }
    // Not silently ignored, and not coerced: the two spellings select
    // different partitioned rows, so a typo that fell back to the derived
    // chain would quietly answer a different question than the caller asked.
    for (const ancestorChain of ["same-site", "SameSite", "crosssite", ""]) {
      const error = t.throws(() => snapshot.sendView({ ...base, ancestorChain }), undefined, ancestorChain);
      t.is(error.code, "InvalidArg", ancestorChain);
      t.regex(error.message, /unknown ancestor chain/, ancestorChain);
    }
  });
});

for (const [storeName, store] of Object.entries(corpus.stores)) {
  const cases = corpus.cases.filter((entry) => entry.store === storeName);

  test(`${storeName}: sendView answers every corpus case`, async (t) => {
    await withTempDirectory(`rookie-node-corpus-${storeName}-`, async (directory) => {
      const snapshot = await openStore(directory, storeName);

      for (const entry of cases) {
        if (EXCLUDED_CASES.has(entry.id)) {
          continue;
        }
        const context = toContext(entry.context);

        if (entry.expect.error) {
          // A send-selection failure is synchronous: the snapshot is already
          // loaded, so there is no I/O left to await.
          const viewError = t.throws(() => snapshot.sendView(context), undefined, entry.id);
          t.is(viewError.kind, "request", entry.id);
          t.is(viewError.rookieCode, entry.expect.error.code, entry.id);
          t.deepEqual(viewError.required, entry.expect.error.required, entry.id);

          // `header` must fail identically: it renders from `sendView` rather
          // than repeating the match, and this is what pins that.
          const headerError = t.throws(() => snapshot.header(context), undefined, entry.id);
          t.is(headerError.rookieCode, entry.expect.error.code, entry.id);
          t.deepEqual(headerError.required, entry.expect.error.required, entry.id);
          continue;
        }

        const view = snapshot.sendView(context);
        t.deepEqual(
          view.cookies.map(({ cookie }) => cookie.value),
          entry.expect.selected,
          `${entry.id}: selected records, in header order`,
        );
        t.is(view.header, entry.expect.header, `${entry.id}: header`);
        t.deepEqual(
          observedOmissions(view.omitted),
          expectedOmissions(entry.expect.omitted),
          `${entry.id}: omission counts`,
        );
        t.is(snapshot.header(context), view.header, `${entry.id}: header === sendView().header`);
      }
    });
  });

  // Every store's `jar` verdict is the same predicate `sendView` reports as
  // `incomplete_send_context`: the demanded-token list for the whole snapshot.
  // A store whose jar refuses must therefore demand exactly the tokens the
  // refusal names, from a context that supplies none of them.
  test(`${storeName}: the jar verdict and the demanded selectors agree`, async (t) => {
    await withTempDirectory(`rookie-node-corpus-jar-tokens-${storeName}-`, async (directory) => {
      const snapshot = await openStore(directory, storeName);
      const bare = { url: "https://rookie-a.test/", nowEpochSeconds: corpus.clock_epoch_seconds };

      if (store.jar.expect === "ok") {
        t.notThrows(() => snapshot.sendView(bare), "an unisolated store demands no selector");
        return;
      }
      const error = t.throws(() => snapshot.sendView(bare));
      t.is(error.rookieCode, "incomplete_send_context");
      t.deepEqual(error.required, store.jar.expect.error.required);
    });
  });
}

// `jar` reads a discovered browser profile, not a path, so it is exercised
// against the Firefox corpus stores planted in a synthetic Firefox home. The
// Chromium stores have no equivalent: reaching them through `jar` would mean
// standing up a Chrome profile whose decryption path reads the host keychain.
// Their refusal predicate is covered by the token-agreement test above, which
// asserts the very list `isolation_loss_refused` would carry.
const FIREFOX_JAR_STORES = Object.entries(corpus.stores).filter(
  ([, store]) => store.engine === "firefox",
);

function firefoxFixtureRoot(temp) {
  if (process.platform === "win32") {
    return {
      root: join(temp, "Roaming", "Mozilla", "Firefox"),
      environment: { APPDATA: join(temp, "Roaming"), LOCALAPPDATA: join(temp, "Local") },
    };
  }
  if (process.platform === "darwin") {
    return {
      root: join(temp, "Library", "Application Support", "Firefox"),
      environment: { HOME: temp },
    };
  }
  return { root: join(temp, ".mozilla", "firefox"), environment: { HOME: temp } };
}

for (const [storeName, store] of FIREFOX_JAR_STORES) {
  test.serial(`${storeName}: jar honours the corpus verdict`, async (t) => {
    const temp = mkdtempSync(join(tmpdir(), `rookie-node-corpus-jar-${storeName}-`));
    try {
      const fixture = firefoxFixtureRoot(temp);
      const profile = join(fixture.root, "Profiles", "corpus");
      mkdirSync(profile, { recursive: true });
      installStore(profile, storeName);
      writeFileSync(
        join(fixture.root, "profiles.ini"),
        "[InstallTest]\nDefault=Profiles/corpus\n\n" +
          "[Profile0]\nName=corpus\nIsRelative=1\nPath=Profiles/corpus\nDefault=1\n",
      );

      // A child process, not this worker: AVA may run the test in a worker
      // whose `process.env` edits are invisible to N-API's background thread,
      // and browser discovery reads the environment on that thread.
      const { stdout } = await execFileAsync(
        process.execPath,
        [fileURLToPath(new URL("isolation-corpus-jar-child.mjs", import.meta.url))],
        { env: { ...process.env, ...fixture.environment } },
      );
      const observed = JSON.parse(stdout);

      if (store.jar.expect === "ok") {
        t.deepEqual(observed.refused, observed.cookies, "an unisolated jar refuses nothing");
      } else {
        t.is(observed.refused.error.kind, "request");
        t.is(observed.refused.error.rookieCode, "isolation_loss_refused");
        t.deepEqual(observed.refused.error.required, store.jar.expect.error.required);
      }

      // The opt-in never changes what a successful call contains -- only
      // whether the call can fail. Byte-for-byte `read(...).cookies`.
      t.deepEqual(observed.allowed, observed.cookies);
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
}
