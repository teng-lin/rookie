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
// `build_isolation_corpus.py --write-node-fixtures` emits one fixture per
// store, and `test_build_isolation_corpus.py` re-checks each against a fresh
// build, so these bytes cannot drift from `corpus.json`. The "every corpus
// store has a committed Node fixture" test below is what keeps this map in
// step when the corpus gains a store.
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

// How the corpus says this store must be opened.
//
// `include_expired` is a per-store fact, not a convenience: `firefox_plain`
// declares it so its already-expired row reaches the snapshot and is counted
// under `omitted.expired`, which is the corpus's way of stating that send-time
// expiry applies even to a row an inventory deliberately retained. Opening a
// store that does not declare it with `includeExpired: true` would be just as
// wrong -- the omission totals cover exactly the rows the store was opened
// with.
function snapshotOptions(storeName, path) {
  const store = corpus.stores[storeName];
  const options = { path, includeExpired: store.include_expired === true };
  if (store.engine === "chromium") {
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

  // Every case runs. There is no exclusion list: this binding does not
  // implement matching -- `sendView` hands the context straight to
  // `ReadResult::send_view` -- so a case this file cannot answer is a defect
  // in the corpus or the core, to be fixed there rather than skipped here.
  const cased = new Set(corpus.cases.map((entry) => entry.store));
  t.deepEqual([...cased].sort(), Object.keys(corpus.stores).sort(), "every store has cases");
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
      const error = t.throws(
        () => snapshot.sendView({ ...base, ancestorChain }),
        undefined,
        ancestorChain,
      );
      t.is(error.code, "InvalidArg", ancestorChain);
      t.regex(error.message, /unknown ancestor chain/, ancestorChain);
      // Deliberately only `code`. This rejection happens while converting the
      // argument, before the core is asked anything, so it is not a classified
      // `rookie_cookies::Error` and carries none of the structured attributes
      // -- the same shape `resource`/`method` have had since 0.6. The
      // asynchronous jobs differ: their loader wrapper decorates every
      // rejection, so `kind` is always present there. Pinned here so the
      // distinction is a decision rather than something a caller discovers.
      t.is(error.kind, undefined, ancestorChain);
      t.is(error.rookieCode, undefined, ancestorChain);
      t.is(error.required, undefined, ancestorChain);
    }
  });
});

test("a send-selection fault that is not a missing selector demands nothing", async (t) => {
  await withTempDirectory("rookie-node-corpus-required-empty-", async (directory) => {
    const snapshot = await openStore(directory, "chromium_plain");

    // `required` is a demand list, not a general diagnostic slot. A caller
    // branching on `error.required.length` to decide whether to supply
    // selectors must not be sent looking for one when the URL is simply
    // malformed.
    for (const [label, context] of [
      ["a malformed URL", "not a url"],
      ["a malformed top-level site", { url: "https://rookie-a.test/", topLevelSite: "nope" }],
    ]) {
      const error = t.throws(() => snapshot.sendView(context), undefined, label);
      t.is(error.kind, "request", label);
      t.is(error.code, "InvalidArg", label);
      t.deepEqual(error.required, [], label);
    }
  });
});

// The clock override is the one `SendContext` field with no observable effect
// in the corpus cases, which all share one epoch at which nothing has expired.
// Without this, `nowEpochSeconds` could stop being forwarded to
// `SendContext::now` -- falling back to the real wall clock -- and every
// corpus case would still pass.
for (const storeName of ["chromium_plain", "firefox_plain"]) {
  test(`${storeName}: nowEpochSeconds moves the send-time expiry boundary`, async (t) => {
    await withTempDirectory(`rookie-node-corpus-clock-${storeName}-`, async (directory) => {
      const snapshot = await openStore(directory, storeName);
      const url = "https://rookie-a.test/";

      const live = snapshot.sendView({ url, nowEpochSeconds: corpus.clock_epoch_seconds });
      t.is(live.cookies.length, 1, "the corpus clock selects the live row");

      // The boundary is read off the selected row rather than restated here,
      // so the test still means what it says if the corpus moves the expiry --
      // and it names the row by selection rather than by index, since a store
      // may also hold rows that were already expired at the corpus clock.
      const { expires } = live.cookies[0].cookie;
      t.is(typeof expires, "number", "the selected row must be persistent");
      t.true(expires > corpus.clock_epoch_seconds, "and must outlive the corpus clock");

      // Send-time expiry applies to a row the snapshot deliberately retained:
      // keeping an expired cookie in an inventory is not a licence to send it.
      // Counted relatively, so a store that already had expired rows at the
      // corpus clock asserts the same thing as one that had none.
      const stale = snapshot.sendView({ url, nowEpochSeconds: expires + 1 });
      t.is(stale.cookies.length, 0);
      t.is(stale.header, "");
      t.is(stale.omitted.expired, live.omitted.expired + 1);
    });
  });
}

for (const [storeName, store] of Object.entries(corpus.stores)) {
  const cases = corpus.cases.filter((entry) => entry.store === storeName);

  test(`${storeName}: sendView answers every corpus case`, async (t) => {
    await withTempDirectory(`rookie-node-corpus-${storeName}-`, async (directory) => {
      const snapshot = await openStore(directory, storeName);

      for (const entry of cases) {
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
      t.is(error.kind, "request");
      t.is(error.code, "InvalidArg");
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
        [
          fileURLToPath(new URL("isolation-corpus-jar-child.mjs", import.meta.url)),
          String(store.include_expired === true),
        ],
        { env: { ...process.env, ...fixture.environment } },
      );
      const observed = JSON.parse(stdout);

      if (store.jar.expect === "ok") {
        t.deepEqual(observed.refused, observed.cookies, "an unisolated jar refuses nothing");
      } else {
        t.is(observed.refused.error.kind, "request");
        t.is(observed.refused.error.code, "InvalidArg");
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
