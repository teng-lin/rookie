import test from "ava";
import { execFile, spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { runInNewContext } from "node:vm";
import rookieCookies, {
  firefoxBased,
  safari,
  toNetscape,
  version,
} from "../index.js";

const execFileAsync = promisify(execFile);

// The cross-language isolation oracle. `__test__/isolation-corpus.spec.mjs`
// drives the whole thing; the one case here reads its selector-token list from
// the same file so the two cannot drift.
const corpus = JSON.parse(
  readFileSync(new URL("../../../tests/isolation_corpus/corpus.json", import.meta.url), "utf8"),
);

// Every function the loader (bindings/node/index.js) is expected to export
// after patch-loader.js runs, per bindings/node/index.d.ts. Required native
// functions are validated while the facade is constructed; this list also
// guards against the documented facade and its smoke test drifting apart.
const EXPECTED_EXPORTS = [
  "CancellationHandle",
  "version",
  "toNetscape",
  "anyBrowser",
  "extractFromPath",
  "cookiesFromPath",
  "chromiumCookiesFromPath",
  "chromiumCookiesFromPathDetailed",
  "firefox",
  "zen",
  "librewolf",
  "cachy",
  "chrome",
  "brave",
  "arc",
  "edge",
  "opera",
  "operaGx",
  "chromium",
  "vivaldi",
  "load",
  "firefoxProfiles",
  "firefoxProfile",
  "firefoxBased",
  "firefoxBasedDetailed",
  "octoBrowser",
  "internetExplorer",
  "safari",
  "chromiumBased",
  "chromiumBasedDetailed",
  "supportedBrowsers",
  "browserProfiles",
  "chromeProfiles",
  "chromeProfile",
  "browserReport",
  "loadReport",
  "ReadResult",
  "read",
  "jar",
  "profiles",
  "report",
  "fromPath",
];

// The generic report APIs, and the object declarations they return. napi-rs
// emits these after `load`, which is exactly where a naive slice in
// patch-loader.js used to discard everything that followed.
const REPORT_FUNCTIONS = [
  "supportedBrowsers",
  "browserProfiles",
  "chromeProfiles",
  "chromeProfile",
  "browserReport",
  "loadReport",
];

const REPORT_INTERFACES = [
  "CookieContextObject",
  "DetailedCookieObject",
  "BrowserCapabilitiesObject",
  "BrowserDescriptorObject",
  "ProfileIdentityObject",
  "CookieSourceDescriptorObject",
  "CookieSourceIdentityObject",
  "ProfileDescriptorObject",
  "ExtractionStatsObject",
  "ReportStatsObject",
  "ExtractionIssueObject",
  "SourceExtractionObject",
  "ProfileExtractionObject",
  "ExtractionReportObject",
];

function constructFacade(platform, omittedNativeExport) {
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const facadeStart = loader.indexOf("function requiredNative(");
  if (facadeStart === -1) {
    throw new Error("generated loader has no validated export facade");
  }

  const nativeFunctions = Object.fromEntries(
    EXPECTED_EXPORTS.map((name) => [name, () => []]),
  );
  nativeFunctions.testWorkerPanic = undefined;
  nativeFunctions[omittedNativeExport] = undefined;

  const module = { exports: {} };
  runInNewContext(loader.slice(facadeStart), {
    ...nativeFunctions,
    module,
    platform,
    Promise,
    Error,
    TypeError,
  });
  return module.exports;
}

test("index.js exports every documented function", (t) => {
  for (const name of EXPECTED_EXPORTS) {
    t.is(
      typeof rookieCookies[name],
      "function",
      `expected module.exports.${name} to be a function`,
    );
  }
});

test("version returns a non-empty string", (t) => {
  const v = version();
  t.is(typeof v, "string");
  t.true(v.length > 0);
});

test("the generated facade validates required native exports", (t) => {
  t.throws(() => constructFacade("linux", "CancellationHandle"), {
    message: /native binding function: CancellationHandle/,
  });
  t.throws(() => constructFacade("linux", "version"), {
    message: /native binding function: version/,
  });
  t.throws(() => constructFacade("linux", "toNetscape"), {
    message: /native binding function: toNetscape/,
  });
  t.throws(() => constructFacade("linux", "chrome"), {
    message: /native binding function: chrome/,
  });
});

test("platform exports are required only on their supported OS", async (t) => {
  t.throws(() => constructFacade("linux", "cachy"), {
    message: /native binding function: cachy/,
  });
  t.throws(() => constructFacade("darwin", "operaGx"), {
    message: /native binding function: operaGx/,
  });
  t.throws(() => constructFacade("win32", "operaGx"), {
    message: /native binding function: operaGx/,
  });
  t.throws(() => constructFacade("win32", "octoBrowser"), {
    message: /native binding function: octoBrowser/,
  });
  t.throws(() => constructFacade("darwin", "safari"), {
    message: /native binding function: safari/,
  });

  const linux = constructFacade("linux", "octoBrowser");
  await t.throwsAsync(linux.octoBrowser(), {
    message: /only available on Windows/,
  });
  await t.throwsAsync(constructFacade("darwin", "cachy").cachy(), {
    message: /only available on Linux/,
  });
  await t.throwsAsync(constructFacade("linux", "operaGx").operaGx(), {
    message: /only available on macOS and Windows/,
  });
});

test("all packages advertise the supported Node.js engine range", (t) => {
  const expected = ">=22";
  const manifests = [
    ["root", new URL("../package.json", import.meta.url)],
    ["darwin-arm64", new URL("../npm/darwin-arm64/package.json", import.meta.url)],
    ["darwin-x64", new URL("../npm/darwin-x64/package.json", import.meta.url)],
    ["linux-arm64-gnu", new URL("../npm/linux-arm64-gnu/package.json", import.meta.url)],
    ["linux-x64-gnu", new URL("../npm/linux-x64-gnu/package.json", import.meta.url)],
    ["win32-x64-msvc", new URL("../npm/win32-x64-msvc/package.json", import.meta.url)],
  ];

  for (const [name, url] of manifests) {
    const manifest = JSON.parse(readFileSync(url, "utf8"));
    t.is(manifest.engines.node, expected, `${name} engine range`);
  }
});

test("toNetscape escapes malicious fields byte-exactly", (t) => {
  const output = toNetscape([{
    domain: "#HttpOnly_.exa\tmple\r.test",
    path: "/line\npath",
    secure: false,
    expires: undefined,
    name: "na\tme",
    value: "safe\n.evil.test\tTRUE\t/\tTRUE\t1\tforged\tvalue\r",
    httpOnly: true,
    sameSite: 0,
  }]);

  t.is(
    output,
    "# Netscape HTTP Cookie File\n" +
      `# Generated by rookie-cookies ${version()}\n` +
      "# Edit at your own risk.\n\n" +
      "#HttpOnly_%23HttpOnly_.exa%09mple%0D.test\tFALSE\t/line%0Apath\tFALSE\t0\t" +
      "na%09me\tsafe%0A.evil.test%09TRUE%09/%09TRUE%091%09forged%09value%0D\n",
  );
  t.is(output.split("\n").length - 1, 5);
});

test("firefoxBased throws on a missing db path", async (t) => {
  await t.throwsAsync(firefoxBased("/nonexistent/rookie/cookies.sqlite"));
});

test("firefoxBased throws on a non-sqlite file", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-"));
  const dbPath = join(dir, "cookies.sqlite");
  writeFileSync(dbPath, "this is not a sqlite database");
  await t.throwsAsync(firefoxBased(dbPath));
});

test("firefoxBasedDetailed preserves colliding container identities", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-detailed-"));
  const dbPath = join(dir, "cookies.sqlite");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/firefox-context.sqlite.base64", import.meta.url),
    );

    const records = await rookieCookies.firefoxBasedDetailed(dbPath);
    t.is(records.length, 2);
    t.deepEqual(
      Object.fromEntries(records.map(({ cookie, context }) => [
        cookie.value,
        {
          topFrameSiteKey: context.topFrameSiteKey,
          partitionKey: context.partitionKey,
          userContextId: context.userContextId,
        },
      ])),
      {
        work: {
          topFrameSiteKey: null,
          partitionKey: "(https,work.example)",
          userContextId: 2,
        },
        personal: {
          topFrameSiteKey: null,
          partitionKey: "(https,personal.example)",
          userContextId: 1,
        },
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cookiesFromPath classifies Firefox and applies domain filters", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-canonical-firefox-"));
  const dbPath = join(dir, "cookies.sqlite");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    );
    const cookies = await rookieCookies.cookiesFromPath(dbPath, ["example.test"]);
    t.is(cookies.length, 1);
    t.is(cookies[0].name, "selected");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("extractFromPath is the canonical flat path-extract job", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-extract-from-path-"));
  try {
    // No credential selector at all: sniffed from signature/schema, same as
    // the deprecated cookiesFromPath's default behavior.
    const firefoxPath = join(dir, "firefox-cookies.sqlite");
    installDatabaseFixture(
      firefoxPath,
      new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    );
    const sniffed = await rookieCookies.extractFromPath(firefoxPath, {
      domains: ["example.test"],
    });
    t.deepEqual(sniffed.map(({ name }) => name), ["selected"]);

    // Chromium credential selectors and appBound compose the same way
    // chromiumCookiesFromPath's options did.
    const chromiumPath = join(dir, "Cookies");
    installDatabaseFixture(
      chromiumPath,
      new URL("fixtures/chromium-plaintext.sqlite.base64", import.meta.url),
    );
    const plaintext = await rookieCookies.extractFromPath(chromiumPath, {
      domains: ["example.test"],
      plaintextOnly: true,
      appBound: "disabled",
    });
    t.deepEqual(plaintext.map(({ name }) => name), ["plain"]);

    await t.throwsAsync(
      rookieCookies.extractFromPath(chromiumPath, {
        browserId: "chrome",
        plaintextOnly: true,
      }),
      { message: /mutually exclusive/ },
    );

    // N-API would coerce each of these into the native u32 deadline rather
    // than reject it, turning -1 into roughly 49 days and NaN into 0. A
    // silently different deadline is worse than a rejected request.
    for (const timeoutMs of [-1, Number.NaN, Number.POSITIVE_INFINITY, 1.5, 4294967296]) {
      await t.throwsAsync(
        rookieCookies.extractFromPath(chromiumPath, { timeoutMs }),
        { message: /timeoutMs must be an integer/ },
        `timeoutMs ${timeoutMs} must be rejected, not coerced`,
      );
    }
    // 0 is a legal integer and reaches the job, where it means an already
    // expired deadline -- a timeout, not a malformed request. Pinning the
    // distinction keeps the validator from tightening into a range check that
    // rejects a value the deadline layer defines.
    await t.throwsAsync(
      rookieCookies.extractFromPath(chromiumPath, { timeoutMs: 0 }),
      { message: /timed out/ },
      "timeoutMs 0 is a deadline, not a validation error",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ReadResult.header exposes structured synchronous request errors", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-header-error-"));
  const dbPath = join(dir, "cookies.sqlite");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    );
    const snapshot = await rookieCookies.fromPath({ path: dbPath, includeExpired: true });
    const error = t.throws(() => snapshot.header("not a url"));
    t.is(error.kind, "request");
    t.is(error.code, "InvalidArg");
    t.is(error.rookieCode, "invalid_url");
    t.is(error.stopReason, null);
    t.deepEqual(error.profileIds, []);
    t.deepEqual(error.required, [], "a malformed URL demands no selector");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a synchronous incomplete_send_context names the selectors it wants", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-header-required-"));
  const dbPath = join(dir, "cookies.sqlite");
  try {
    // The isolation corpus store: every row carries a Firefox origin-attribute
    // or partition identity, so a bare URL cannot say which one it means.
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/isolation-corpus-firefox.sqlite.base64", import.meta.url),
    );
    const snapshot = await rookieCookies.fromPath({ path: dbPath, includeExpired: true });

    // The token list, its spelling, and its order are the corpus's, not this
    // file's: `required` is a vocabulary a caller branches on, and the same
    // list reaches Rust, Python, and the CLI.
    const expected =
      corpus.stores.firefox_isolated.jar.expect.error.required;

    for (const call of [() => snapshot.header("https://attrs.rookie-a.test/"),
                        () => snapshot.sendView("https://attrs.rookie-a.test/")]) {
      const error = t.throws(call);
      t.is(error.kind, "request");
      t.is(error.code, "InvalidArg");
      t.is(error.rookieCode, "incomplete_send_context");
      t.deepEqual(error.required, expected);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CancellationHandle tracks its own cancelled state", (t) => {
  const handle = new rookieCookies.CancellationHandle();
  t.false(handle.isCancelled);
  t.true(handle.cancel(), "the first cancel() call takes effect");
  t.true(handle.isCancelled);
  t.false(handle.cancel(), "a handle already cancelled stays cancelled");
});

test("cookiesFromPath rejects once its timeout budget expires", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-timeout-"));
  const dbPath = join(dir, "cookies.sqlite");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    );
    const error = await t.throwsAsync(rookieCookies.cookiesFromPath(dbPath, null, 0), {
      message: /operation timed out/,
    });
    t.is(error.kind, "stopped");
    t.is(error.code, "GenericFailure");
    t.is(error.rookieCode, "timed_out");
    t.is(error.stopReason, "timed_out");
    t.deepEqual(error.profileIds, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cookiesFromPath rejects when handed an already-cancelled handle", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-cancelled-"));
  const dbPath = join(dir, "cookies.sqlite");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    );
    const handle = new rookieCookies.CancellationHandle();
    handle.cancel();
    const error = await t.throwsAsync(
      rookieCookies.cookiesFromPath(dbPath, null, undefined, handle),
      { message: /operation was cancelled/ },
    );
    t.is(error.kind, "stopped");
    t.is(error.code, "Cancelled");
    t.is(error.rookieCode, "cancelled");
    t.is(error.stopReason, "cancelled");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a migrated single-browser export honors timeoutMs like cookiesFromPath", async (t) => {
  // Every async_named_browser_fn!-generated export (firefox, chrome, safari,
  // ...) shares one macro body, so this stands in for the whole family: the
  // deadline checkpoint runs before any real profile discovery -- proven at
  // the Rust level by zero_timeout_stops_extraction_before_any_browser_lookup
  // -- so this needs no installed-browser fixture to be deterministic.
  await t.throwsAsync(rookieCookies.firefox(null, 0), {
    message: /operation timed out/,
  });
});

test("canonical Chromium paths support flat, detailed, and domain projections", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-canonical-chromium-"));
  const dbPath = join(dir, "Cookies");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/chromium-plaintext.sqlite.base64", import.meta.url),
    );
    const options = { domains: ["example.test"], plaintextOnly: true };
    const cookies = await rookieCookies.chromiumCookiesFromPath(dbPath, options);
    t.deepEqual(cookies.map(({ name }) => name), ["plain"]);

    // chromiumCookiesFromPathDetailed no longer supports domain filtering:
    // detailed path extraction routes through fromPath, which -- like read --
    // never URL/domain-slices its snapshot. It rejects rather than silently
    // ignoring `domains`.
    await t.throwsAsync(rookieCookies.chromiumCookiesFromPathDetailed(dbPath, options), {
      message: /no longer supports domain filtering/,
    });

    const detailed = await rookieCookies.chromiumCookiesFromPathDetailed(dbPath, {
      plaintextOnly: true,
    });
    const plain = detailed.find(({ cookie }) => cookie.name === "plain");
    t.truthy(
      plain,
      "the domain-filtered flat cookie must also appear in the unfiltered detailed list",
    );
    t.is(plain.context.topFrameSiteKey, "https://top.example");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Chromium path options accept plain records from another realm", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-canonical-cross-realm-"));
  const dbPath = join(dir, "Cookies");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/chromium-plaintext.sqlite.base64", import.meta.url),
    );
    const options = runInNewContext("({ plaintextOnly: true })");
    const cookies = await rookieCookies.chromiumCookiesFromPath(dbPath, options);
    t.is(cookies.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("plaintextOnly rejects a mixed database as a whole request", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-canonical-mixed-"));
  const dbPath = join(dir, "Cookies");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/chromium-mixed.sqlite.base64", import.meta.url),
    );
    await t.throwsAsync(
      rookieCookies.chromiumCookiesFromPath(dbPath, {
        domains: ["example.test"],
        plaintextOnly: true,
      }),
      { message: /no browser key identity/ },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Chromium path option validation rejects asynchronously before database I/O", async (t) => {
  const missing = join(tmpdir(), "rookie-node-missing-canonical-Cookies");
  const invalidOptions = [
    [],
    new Date(),
    new Map(),
    { unknown: true },
    { [Symbol("unknown")]: true },
    { allowProcessShutdown: true },
    { shutdown: true },
    { domains: "example.test" },
    { domains: ["example.test", 1] },
    { browserId: 1 },
    { localStatePath: 1 },
    { plaintextOnly: 1 },
    { browserId: "chrome", plaintextOnly: true },
    { localStatePath: "Local State", plaintextOnly: true },
  ];

  for (const options of invalidOptions) {
    for (const extract of [
      rookieCookies.chromiumCookiesFromPath,
      rookieCookies.chromiumCookiesFromPathDetailed,
    ]) {
      let promise;
      t.notThrows(() => {
        promise = extract(missing, options);
      });
      t.true(promise instanceof Promise);
      await t.throwsAsync(promise, { instanceOf: TypeError });
    }
  }
});

test("fromPath rejects credential conflicts asynchronously before database I/O", async (t) => {
  const missing = join(tmpdir(), "rookie-node-missing-from-path-Cookies");
  const invalidOptions = [
    { path: missing, browserId: "chrome", localStatePath: "Local State" },
    { path: missing, browserId: "chrome", plaintextOnly: true },
    { path: missing, localStatePath: "Local State", plaintextOnly: true },
    {
      path: missing,
      browserId: "chrome",
      localStatePath: "Local State",
      plaintextOnly: true,
    },
  ];

  for (const options of invalidOptions) {
    let promise;
    t.notThrows(() => {
      promise = rookieCookies.fromPath(options);
    });
    t.true(promise instanceof Promise);
    const error = await t.throwsAsync(promise, {
      message: /mutually exclusive/,
    });
    t.is(error.code, "InvalidArg");
    t.is(error.kind, "request");
    t.is(error.rookieCode, null);
    t.is(error.stopReason, null);
    t.deepEqual(error.profileIds, []);
    t.is(error.sourceKind, null);
    t.is(error.targetOs, null);
    t.false(error.pathRedacted);
  }
});

test("facade Chromium option conflicts receive structured diagnostic defaults", async (t) => {
  const missing = join(tmpdir(), "rookie-node-missing-canonical-conflict-Cookies");
  const error = await t.throwsAsync(
    rookieCookies.chromiumCookiesFromPath(missing, {
      browserId: "chrome",
      plaintextOnly: true,
    }),
    { instanceOf: TypeError, message: /mutually exclusive/ },
  );

  t.is(error.code, undefined, "a facade TypeError must not invent an N-API status");
  t.is(error.kind, "request");
  t.is(error.rookieCode, null);
  t.is(error.stopReason, null);
  t.deepEqual(error.profileIds, []);
  t.is(error.sourceKind, null);
  t.is(error.targetOs, null);
  t.false(error.pathRedacted);
});

test("N-API conversion errors receive request diagnostic defaults", async (t) => {
  const error = await t.throwsAsync(rookieCookies.browserProfiles(42));

  t.is(error.code, "StringExpected");
  t.is(error.kind, "request");
  t.is(error.rookieCode, null);
  t.is(error.stopReason, null);
  t.deepEqual(error.profileIds, []);
});

test("null, false, and empty Chromium selectors retain their distinct meanings", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-canonical-selectors-"));
  const dbPath = join(dir, "Cookies");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/chromium-plaintext.sqlite.base64", import.meta.url),
    );
    for (const options of [
      { plaintextOnly: true },
      { plaintextOnly: true, domains: null },
    ]) {
      const cookies = await rookieCookies.chromiumCookiesFromPath(dbPath, options);
      t.is(cookies.length, 2);
    }

    if (process.platform !== "win32") {
      for (const options of [undefined, null, {}, { plaintextOnly: false }]) {
        const cookies = await rookieCookies.chromiumCookiesFromPath(dbPath, options);
        t.is(cookies.length, 2);
      }
    }

    for (const options of [{ browserId: "" }, { localStatePath: "" }]) {
      let error;
      try {
        await rookieCookies.chromiumCookiesFromPath(dbPath, options);
      } catch (caught) {
        error = caught;
      }
      t.truthy(error, "an empty selected credential must reach core validation");
      t.false(error instanceof TypeError, "empty strings are not facade shape errors");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("identity-less encrypted Chromium paths reject explicitly on Unix", async (t) => {
  if (process.platform === "win32") {
    t.pass();
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), "rookie-node-identity-"));
  const dbPath = join(dir, "Cookies");
  try {
    installDatabaseFixture(
      dbPath,
      new URL("fixtures/chromium-encrypted.sqlite.base64", import.meta.url),
    );

    await t.throwsAsync(rookieCookies.chromiumBased(dbPath), {
      message: /no browser key identity.*browser_id/s,
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("explicit Chromium browser IDs are registry identities, not profile selectors", async (t) => {
  if (process.platform === "win32") {
    t.pass();
    return;
  }
  const missingDb = join(tmpdir(), "rookie-node-missing-key-identity-Cookies");
  const profileLikeId = "0".repeat(64);
  const invalidIdentities = [
    ["definitely-not-a-browser", /unknown browser id "definitely-not-a-browser"/],
    ["firefox", /browser id "firefox" resolves to the gecko engine, not Chromium/],
    [profileLikeId, new RegExp(`unknown browser id "${profileLikeId}"`)],
  ];

  for (const [browserId, message] of invalidIdentities) {
    for (const extract of [
      rookieCookies.chromiumBased,
      rookieCookies.chromiumBasedDetailed,
    ]) {
      await t.throwsAsync(extract(missingDb, undefined, browserId), { message });
    }
  }
});

test("bad async API arguments reject instead of throwing synchronously", async (t) => {
  const invalidCalls = [
    ["anyBrowser", () => rookieCookies.anyBrowser(42)],
    ["extractFromPath", () => rookieCookies.extractFromPath(42)],
    ["cookiesFromPath", () => rookieCookies.cookiesFromPath(42)],
    ["chromiumCookiesFromPath", () => rookieCookies.chromiumCookiesFromPath(42)],
    [
      "chromiumCookiesFromPathDetailed",
      () => rookieCookies.chromiumCookiesFromPathDetailed(42),
    ],
    ["firefox", () => rookieCookies.firefox(42)],
    ["firefoxProfile", () => rookieCookies.firefoxProfile(42)],
    ["firefoxBased", () => rookieCookies.firefoxBased(42)],
    ["firefoxBasedDetailed", () => rookieCookies.firefoxBasedDetailed(42)],
    ["zen", () => rookieCookies.zen(42)],
    ["librewolf", () => rookieCookies.librewolf(42)],
    ["cachy", () => rookieCookies.cachy(42)],
    ["chrome", () => rookieCookies.chrome(42)],
    ["brave", () => rookieCookies.brave(42)],
    ["arc", () => rookieCookies.arc(42)],
    ["edge", () => rookieCookies.edge(42)],
    ["opera", () => rookieCookies.opera(42)],
    ["operaGx", () => rookieCookies.operaGx(42)],
    ["chromium", () => rookieCookies.chromium(42)],
    ["vivaldi", () => rookieCookies.vivaldi(42)],
    ["load", () => rookieCookies.load(42)],
    ["octoBrowser", () => rookieCookies.octoBrowser(42)],
    ["internetExplorer", () => rookieCookies.internetExplorer(42)],
    ["safari", () => rookieCookies.safari(42)],
    ["chromiumBased", () => rookieCookies.chromiumBased(42)],
    ["chromiumBasedDetailed", () => rookieCookies.chromiumBasedDetailed(42)],
    ["browserProfiles", () => rookieCookies.browserProfiles(42)],
    ["chromeProfile", () => rookieCookies.chromeProfile(42)],
    ["browserReport", () => rookieCookies.browserReport(42)],
    // Every `LoadReportOptions` field is optional, so a bare non-object
    // primitive silently duck-types as "no options" instead of rejecting;
    // an invalid field value is what actually triggers a napi conversion
    // error here.
    ["loadReport", () => rookieCookies.loadReport({ domains: 42 })],
    ["jar", () => rookieCookies.jar({ browser: 42 })],
  ];

  for (const [name, call] of invalidCalls) {
    let promise;
    t.notThrows(() => {
      promise = call();
    }, `${name} must not throw before returning`);
    t.true(promise instanceof Promise, `${name} must return a Promise`);
    await t.throwsAsync(promise, undefined, `${name} must reject`);
  }
});

test("allowIsolationLoss is rejected on the jobs that cannot honour it", async (t) => {
  // `read` and `fromPath` return a snapshot that keeps every isolated
  // identity, so there is nothing for the flag to allow. Accepting and
  // ignoring it would be exactly the silent flatten the fail-closed jar was
  // introduced to remove, and it would fail invisibly: the caller believes
  // they opted in, and every call still succeeds. It is rejected by name,
  // before any I/O -- so this test needs no browser and no fixture.
  const rejected = [
    ["read", () => rookieCookies.read({ browser: "firefox", allowIsolationLoss: true })],
    ["fromPath", () => rookieCookies.fromPath({ path: "/nonexistent", allowIsolationLoss: false })],
  ];

  for (const [name, call] of rejected) {
    let promise;
    t.notThrows(() => {
      promise = call();
    }, `${name} must reject rather than throw synchronously`);
    const error = await t.throwsAsync(promise, undefined, `${name} must reject`);
    t.is(error.kind, "request", name);
    t.is(error.code, "InvalidArg", name);
    // The fault is in the call, not in anything the core classified, so there
    // is no rookieCode -- the same shape an unknown `extractFromPath` option
    // produces.
    t.is(error.rookieCode, null, name);
    t.deepEqual(error.required, [], name);
    t.regex(error.message, /allowIsolationLoss/, name);
    t.regex(error.message, /jar/, name);
  }

  // Present-but-false is still present: a caller who wrote it on the wrong
  // job has the same misconception either way, and silently accepting the
  // "harmless" spelling teaches them the option belongs there.
  await t.throwsAsync(rookieCookies.read({ browser: "firefox", allowIsolationLoss: false }));

  // Nothing else changed about these jobs: an ordinary options object still
  // reaches the native layer and fails on its own merits.
  const ordinary = await t.throwsAsync(rookieCookies.read({ browser: "no-such-browser" }));
  t.is(ordinary.rookieCode, "unknown_browser");
});

test("jar rejects a non-boolean allowIsolationLoss instead of coercing it", async (t) => {
  // N-API converts `JarOptions` before the task is scheduled, so a truthy
  // string never reaches the isolation-loss decision. That matters: `"yes"`
  // coerced to `true` would turn a typo into a silent opt-in to flattening
  // scoped credentials.
  const error = await t.throwsAsync(
    rookieCookies.jar({ browser: "firefox", allowIsolationLoss: "yes" }),
  );
  t.is(error.kind, "request");
  t.is(error.code, "BooleanExpected");
});

test.serial("Firefox profiles can be listed and selected asynchronously", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-firefox-"));
  const fixture = firefoxFixtureRoot(temp);
  const defaultProfile = join(fixture.root, "Profiles", "default-release");
  const workProfile = join(fixture.root, "Profiles", "work");
  mkdirSync(defaultProfile, { recursive: true });
  mkdirSync(workProfile, { recursive: true });
  writeFileSync(
    join(fixture.root, "profiles.ini"),
    `[InstallTest]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/work
`,
  );
  installDatabaseFixture(
    join(defaultProfile, "cookies.sqlite"),
    new URL("fixtures/firefox-empty.sqlite.base64", import.meta.url),
  );
  installDatabaseFixture(
    join(workProfile, "cookies.sqlite"),
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
  );

  try {
    // AVA may run this test inside a worker whose process.env changes are not
    // visible to N-API's background thread. A child with an inherited fixture
    // environment exercises the same production discovery path reliably.
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("firefox-profile-child.mjs", import.meta.url))],
      {
        env: { ...process.env, ...fixture.environment },
      },
    );
    const { profiles, cookies, jarCookies } = JSON.parse(stdout);
    t.deepEqual(
      profiles.map(({ name, isDefault }) => ({ name, isDefault })),
      [
        { name: "default-release", isDefault: true },
        { name: "work", isDefault: false },
      ],
    );
    t.true(profiles.every(({ path }) => typeof path === "string"));

    t.is(cookies.length, 1);
    t.deepEqual(cookies[0], {
      domain: ".example.test",
      path: "/",
      secure: false,
      expires: 1700000000,
      name: "selected",
      value: "secondary",
      httpOnly: false,
      sameSite: 0,
    });
    t.deepEqual(jarCookies, cookies, "jar is read(...).cookies projection sugar");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("generated Firefox profile exports and declarations survive patching", (t) => {
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  t.is((loader.match(/function requiredNative\(/g) || []).length, 1);
  t.is((loader.match(/function platformNative\(/g) || []).length, 1);
  t.regex(types, /export interface FirefoxProfileObject/);
  t.regex(types, /export declare function firefoxProfiles\(/);
  t.regex(types, /export declare function firefoxProfile\(/);
  t.is((types.match(/firefoxProfiles\(/g) || []).length, 1);
  t.is((types.match(/firefoxProfile\(/g) || []).length, 1);
  t.false(types.includes("testWorkerPanic"));
});

test("finite profile selections stay finite in generated declarations", (t) => {
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  const readOptions = types.match(/export interface ReadOptions \{[\s\S]*?\n\}/)?.[0];
  const reportOptions = types.match(/export interface ReportOptions \{[\s\S]*?\n\}/)?.[0];
  // JarOptions repeats every ReadOptions field, so it repeats this one too.
  // napi-rs sees a plain Option<String> and emits `select?: string` for each
  // of them independently; a retype added for one interface and forgotten for
  // another is invisible at run time and only shows up as a consumer's `"all"`
  // typechecking against a job that always rejects it.
  const jarOptions = types.match(/export interface JarOptions \{[\s\S]*?\n\}/)?.[0];
  t.truthy(readOptions);
  t.truthy(reportOptions);
  t.truthy(jarOptions);
  t.true(readOptions.includes("select?: 'legacy_first'"));
  t.true(jarOptions.includes("select?: 'legacy_first'"));
  t.true(reportOptions.includes("select?: 'legacy_first' | 'all'"));
  t.false(readOptions.includes("select?: string"));
  t.false(jarOptions.includes("select?: string"));
  t.false(reportOptions.includes("select?: string"));

  // The one field that must NOT be repeated: a `read` caller who passes it
  // has misunderstood what the flag does, and the type surface is where they
  // should find that out.
  t.true(jarOptions.includes("allowIsolationLoss?: boolean"));
  t.false(readOptions.includes("allowIsolationLoss"));
});

test("canonical direct-path declarations and compatibility deprecations are exact", (t) => {
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  t.regex(
    types,
    /export interface ChromiumPathOptions \{\n  domains\?: string\[\] \| null\n  browserId\?: string \| null\n  localStatePath\?: string \| null\n  plaintextOnly\?: boolean \| null\n  appBound\?: AppBoundPolicy \| null\n\}/,
  );
  t.regex(
    types,
    /export interface ExtractFromPathOptions \{\n  domains\?: Array<string>\n  browserId\?: string\n  localStatePath\?: string\n  plaintextOnly\?: boolean\n  timeoutMs\?: number\n  appBound\?: AppBoundPolicy\n\}/,
  );
  t.true(
    types.includes(
      "export declare function extractFromPath(path: string, options?: ExtractFromPathOptions | undefined | null, cancellation?: CancellationHandle | undefined | null): Promise<Array<CookieObject>>",
    ),
  );
  t.true(
    types.includes(
      "export declare function cookiesFromPath(path: string, domains?: string[] | null, timeoutMs?: number | null, cancellation?: CancellationHandle | null): Promise<CookieObject[]>",
    ),
  );
  t.true(
    types.includes(
      "export declare function chromiumCookiesFromPath(path: string, options?: ChromiumPathOptions | null, timeoutMs?: number | null, cancellation?: CancellationHandle | null): Promise<CookieObject[]>",
    ),
  );
  t.true(
    types.includes(
      "export declare function chromiumCookiesFromPathDetailed(path: string, options?: ChromiumPathOptions | null, timeoutMs?: number | null, cancellation?: CancellationHandle | null): Promise<DetailedCookieObject[]>",
    ),
  );
  // cookiesFromPath / chromiumCookiesFromPath / chromiumCookiesFromPathDetailed
  // / anyBrowser / firefoxBased / chromiumBased / chromiumBasedDetailed are all
  // deprecated onto the canonical extractFromPath or fromPath(...).detailedCookies
  // -- never onto each other, so there is no deprecated-pointing-to-deprecated
  // chain for a caller to follow twice.
  t.is(
    (types.match(/@deprecated Use `extractFromPath`\. Earliest removal is 0\.7\./g) || []).length,
    4,
    "cookiesFromPath, chromiumCookiesFromPath, anyBrowser, and firefoxBased all point at extractFromPath",
  );
  t.is(
    (
      types.match(/@deprecated Use `fromPath\(\.\.\.\)\.detailedCookies`\. Earliest removal is 0\.7\./g)
      || []
    ).length,
    1,
    "chromiumCookiesFromPathDetailed points at fromPath(...).detailedCookies",
  );
  t.is(
    (types.match(/@deprecated Use extractFromPath\. Earliest removal is 0\.7\./g) || []).length,
    2,
    "both chromiumBased platform declarations point at extractFromPath",
  );
  t.is(
    (
      types.match(/@deprecated Use fromPath\(\.\.\.\)\.detailedCookies\. Earliest removal is 0\.7\./g)
      || []
    ).length,
    2,
    "both chromiumBasedDetailed platform declarations point at fromPath(...).detailedCookies",
  );
  t.regex(types, /export interface RookieError extends Error/);
  t.regex(types, /code\?: string/);
  t.regex(types, /rookieCode: string \| null/);
  t.regex(types, /stopReason: string \| null/);
  t.regex(
    types,
    /export interface ReadWarningObject \{[\s\S]*?countersSaturated: boolean/,
  );
  t.false(
    /@deprecated[^\n]*\nexport declare function firefoxBasedDetailed/.test(types),
    "detailed Firefox remains supported",
  );
  t.false(types.includes("allowProcessShutdown"));
});

test("supportedBrowsers describes registered browsers in camelCase", async (t) => {
  const browsers = await rookieCookies.supportedBrowsers();

  t.true(Array.isArray(browsers));
  t.true(browsers.length > 0, "the running OS must register at least one browser");

  for (const browser of browsers) {
    t.is(typeof browser.id, "string");
    t.is(typeof browser.displayName, "string");
    t.is(typeof browser.engine, "string");
    t.true(Array.isArray(browser.aliases));
    for (const tiers of Object.values(browser.capabilities)) {
      t.true(Array.isArray(tiers));
      t.true(tiers.every((tier) => typeof tier === "string"));
    }
    t.deepEqual(Object.keys(browser.capabilities).sort(), [
      "availableDecryptionTiers",
      "declaredDecryptionTiers",
      "persistentFormats",
      "sessionFormats",
    ]);
  }

  const firefox = browsers.find(({ id }) => id === "firefox");
  t.truthy(firefox, "firefox must be registered on every supported OS");
  t.deepEqual(firefox.capabilities.persistentFormats, ["mozilla_sqlite"]);
});

test("unknown browser identifiers reject rather than resolving empty", async (t) => {
  const profiles = await t.throwsAsync(rookieCookies.browserProfiles("not_a_browser"));
  const report = await t.throwsAsync(
    rookieCookies.browserReport({ browserId: "not_a_browser" }),
  );
  for (const error of [profiles, report]) {
    t.is(error.kind, "request");
    t.is(error.code, "InvalidArg");
    t.is(error.rookieCode, "unknown_browser");
    t.is(error.stopReason, null);
    t.deepEqual(error.profileIds, []);
  }
});

test("direct-path source errors expose redacted structured metadata", async (t) => {
  const missing = join(tmpdir(), "rookie-node-structured-missing", "cookies.sqlite");
  const error = await t.throwsAsync(rookieCookies.cookiesFromPath(missing));

  t.is(error.kind, "source");
  t.is(error.code, "InvalidArg");
  t.is(error.rookieCode, "not_a_regular_file");
  t.is(error.stopReason, null);
  t.is(error.pathRedacted, true);
  t.is(error.sourceKind, null);
  t.is(error.targetOs, null);
  t.false(error.message.includes(missing), "the path must stay redacted");
});

test.serial("ambiguous profile errors preserve opaque candidate IDs", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-ambiguous-profile-"));
  const fixture = firefoxFixtureRoot(temp);
  writeFirefoxProfileTree(fixture.root, 2, "shared");

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("ambiguous-error-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment } },
    );
    const details = JSON.parse(stdout);
    t.is(details.kind, "request");
    t.is(details.code, "InvalidArg");
    t.is(details.rookieCode, "ambiguous_profile");
    t.is(details.stopReason, null);
    t.is(details.profileIds.length, 2);
    t.true(details.profileIds.every((id) => /^[0-9a-f]{64}$/.test(id)));
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test.serial("registry-only browsers are reachable through browserReport", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-registry-only-"));
  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("registry-only-child.mjs", import.meta.url))],
      {
        env: {
          ...process.env,
          HOME: temp,
          USERPROFILE: temp,
          APPDATA: join(temp, "AppData", "Roaming"),
          LOCALAPPDATA: join(temp, "AppData", "Local"),
          XDG_CONFIG_HOME: join(temp, ".config"),
        },
      },
    );
    const results = JSON.parse(stdout);
    const expectedBrowsers =
      process.platform === "win32"
        ? ["coccoc", "duckduckgo", "yandex"]
        : process.platform === "darwin"
          ? ["coccoc", "yandex"]
          : [];
    t.deepEqual(Object.keys(results).sort(), expectedBrowsers);
    for (const [browser, status] of Object.entries(results)) {
      t.is(status, "no_sources", browser);
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test.serial("loadReport resolves a report whose counters are plain numbers", async (t) => {
  // Sandboxed to a synthetic home: unlike the other report calls in this file,
  // loadReport enumerates every registered browser, so against the real
  // environment it would read whatever is actually installed on the host.
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-load-"));
  const fixture = firefoxFixtureRoot(temp);
  writeFirefoxProfileTree(fixture.root, 2);

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("load-report-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment, XDG_CONFIG_HOME: join(temp, ".config") } },
    );
    const report = JSON.parse(stdout);

    t.is(typeof report.status, "string");
    t.true(
      report.summary.registeredBrowsers > 0,
      "every registered browser is summarized even when absent",
    );
    t.is(report.profileCount, 2, "the synthetic home must be the only source");

    for (const [name, observed] of Object.entries(report.summaryTypes)) {
      const expected = name === "countersSaturated" ? "boolean" : "number";
      // A u64 binding would arrive as a BigInt, which JSON.stringify rejects
      // and no existing consumer of this package handles. Types are captured
      // in the child, before serialization could disguise one.
      t.is(observed, expected, `summary.${name} must be a ${expected}`);
    }

    t.true(report.serializes, "the report must survive JSON.stringify");
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test.serial("report APIs expose per-source cookie provenance", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-report-"));
  const fixture = firefoxFixtureRoot(temp);
  const defaultProfile = join(fixture.root, "Profiles", "default-release");
  const workProfile = join(fixture.root, "Profiles", "work");
  mkdirSync(defaultProfile, { recursive: true });
  mkdirSync(workProfile, { recursive: true });
  writeFileSync(
    join(fixture.root, "profiles.ini"),
    `[InstallTest]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/work
`,
  );
  installDatabaseFixture(
    join(defaultProfile, "cookies.sqlite"),
    new URL("fixtures/firefox-empty.sqlite.base64", import.meta.url),
  );
  installDatabaseFixture(
    join(workProfile, "cookies.sqlite"),
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
  );

  try {
    // As with the legacy Firefox profile test, a child process carries the
    // fixture environment into N-API's background thread reliably.
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("report-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment } },
    );
    const { profiles, report, leafTypes } = JSON.parse(stdout);

    t.deepEqual(
      profiles.map(({ profile, isDefault }) => ({
        displayName: profile.displayName,
        isDefault,
      })),
      [
        { displayName: "default-release", isDefault: true },
        { displayName: "work", isDefault: false },
      ],
    );
    const work = profiles.find(
      ({ profile }) => profile.displayName === "work",
    );
    t.regex(work.profile.profileId, /^[0-9a-f]{64}$/);
    t.regex(work.profile.installationId, /^[0-9a-f]{64}$/);
    t.false(work.profile.pathLossy);
    t.deepEqual(
      work.sources.map(({ role, format, precedence }) => ({
        role,
        format,
        precedence,
      })),
      [{ role: "persistent", format: "mozilla_sqlite", precedence: 10 }],
    );

    t.is(report.schemaVersion, 1);
    t.is(report.status, "complete");
    t.is(report.termination, "completed");
    t.deepEqual(report.issues, []);
    t.is(report.profiles.length, 1, "profileId must restrict the report");
    const [extracted] = report.profiles;
    t.is(extracted.profile.profileId, work.profile.profileId);
    t.is(extracted.sources.length, 1);

    const [source] = extracted.sources;
    t.true(source.selected);
    t.is(source.status, "succeeded");
    t.is(source.source.role, "persistent");
    t.is(typeof source.acquisitionStrategy, "string");
    t.deepEqual(source.cookies, [
      {
        domain: ".example.test",
        path: "/",
        secure: false,
        expires: 1700000000,
        name: "selected",
        value: "secondary",
        httpOnly: false,
        sameSite: 0,
      },
    ]);
    t.deepEqual(source.stats, {
      rowsSeen: 1,
      cookiesEmitted: 1,
      rowsSkipped: 0,
      rowsRejected: 0,
      providerFailures: 0,
      acquisitionAttempts: 1,
      countersSaturated: false,
    });
    t.is(report.summary.cookiesEmitted, 1);
    t.is(report.summary.sourcesFailed, 0);

    // Collected inside the child, before serialization could hide a BigInt.
    t.deepEqual(leafTypes, ["boolean", "number", "string"]);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

function loadErrorDecorator() {
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const start = loader.indexOf("const structuredErrorPrefix =");
  const end = loader.indexOf("function asyncNative(");
  if (start === -1 || end === -1 || end < start) {
    throw new Error("generated loader has no structured-error decorator");
  }
  const scope = { TypeError, Error, Set, Array, JSON, decorateNativeError: undefined };
  runInNewContext(`${loader.slice(start, end)}\nthis.decorateNativeError = decorateNativeError`, scope);
  return scope.decorateNativeError;
}

test("a structured payload without a message keeps the native text", (t) => {
  const decorateNativeError = loadErrorDecorator();

  // A payload this loader version does not fully understand must never cost
  // the caller their diagnostic. Assigning `details.message` unguarded would
  // let the Error setter coerce `undefined` into the string "undefined", and
  // the parse succeeded so the catch branch cannot recover it.
  const partial = new Error(`__ROOKIE_ERROR_V1__${JSON.stringify({ rookieCode: "timed_out" })}`);
  decorateNativeError(partial);
  t.is(partial.message, '__ROOKIE_ERROR_V1__{"rookieCode":"timed_out"}');
  t.not(partial.message, "undefined");
  t.is(partial.rookieCode, "timed_out", "the rest of the payload is still applied");

  // A non-string `message` is the same hazard wearing a different type.
  const wrongType = new Error(`__ROOKIE_ERROR_V1__${JSON.stringify({ message: 42 })}`);
  decorateNativeError(wrongType);
  t.is(wrongType.message, '__ROOKIE_ERROR_V1__{"message":42}');

  // The ordinary case still replaces the prefixed blob with the real text.
  const complete = new Error(
    `__ROOKIE_ERROR_V1__${JSON.stringify({ message: "operation deadline expired", kind: "engine" })}`,
  );
  decorateNativeError(complete);
  t.is(complete.message, "operation deadline expired");
  t.is(complete.kind, "engine");
});

test("generated report exports and declarations survive patching", (t) => {
  const loader = readFileSync(new URL("../index.js", import.meta.url), "utf8");
  const types = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");

  const destructure = loader.match(/^const \{ .*\bversion\b.*\} = nativeBinding$/m);
  t.truthy(destructure, "the patched loader must destructure the native binding");

  const facadeIndex = types.indexOf("/** rookie-cookies cross-platform facade */");
  t.not(facadeIndex, -1, "the types facade marker must survive patching");
  t.false(
    types.slice(0, facadeIndex).endsWith("@deprecated Use `fromPath(...).detailedCookies`. Earliest removal is 0.7. */\n"),
    "stripped platform declarations must not leave orphaned JSDoc",
  );

  for (const name of REPORT_FUNCTIONS) {
    t.regex(destructure[0], new RegExp(`\\b${name}\\b`), `${name} must be destructured`);
    t.is(
      (loader.match(new RegExp(`^module\\.exports\\.${name} = `, "gm")) || []).length,
      1,
      `${name} must be exported exactly once`,
    );

    const declaration = `export declare function ${name}(`;
    t.true(types.includes(declaration), `${name} must be declared`);
    t.true(
      types.indexOf(declaration) < facadeIndex,
      `${name} must be declared ahead of the appended facade`,
    );
  }

  for (const name of REPORT_INTERFACES) {
    t.is(
      (types.match(new RegExp(`^export interface ${name} \\{$`, "gm")) || []).length,
      1,
      `${name} must be declared exactly once`,
    );
  }

  // Counters are declared u32 precisely so no report field becomes a BigInt.
  t.false(types.includes("bigint"), "no declaration may use BigInt");
  t.regex(types, /export type JsCancellationHandle = CancellationHandle/);
  t.regex(types, /export type JsReadResult = ReadResult/);
});

// Executes the real scripts/patch-loader.js against a disposable copy of the
// generated artifacts, so the guards inside it are exercised rather than merely
// inspected. The committed files are never touched.
function runPatchLoader(mutate = (sources) => sources) {
  const dir = mkdtempSync(join(tmpdir(), "rookie-patch-loader-"));
  try {
    // patch-loader.js reads browser_registry.json from a fixed position relative
    // to itself (repo_root/rookie-rs/...), so the disposable copy has to mirror
    // that layout -- not just drop the script in a bare scripts/ directory --
    // for the registry read to resolve to a real file.
    const nodeDir = join(dir, "bindings", "node");
    mkdirSync(join(nodeDir, "scripts"), { recursive: true });
    mkdirSync(join(dir, "rookie-rs"), { recursive: true });
    const sources = mutate({
      loader: readFileSync(new URL("../index.js", import.meta.url), "utf8"),
      types: readFileSync(new URL("../index.d.ts", import.meta.url), "utf8"),
    });
    writeFileSync(join(nodeDir, "index.js"), sources.loader);
    writeFileSync(join(nodeDir, "index.d.ts"), sources.types);
    copyFileSync(
      fileURLToPath(new URL("../scripts/patch-loader.js", import.meta.url)),
      join(nodeDir, "scripts", "patch-loader.js"),
    );
    copyFileSync(
      fileURLToPath(
        new URL("../../../rookie-rs/browser_registry.json", import.meta.url),
      ),
      join(dir, "rookie-rs", "browser_registry.json"),
    );

    const result = spawnSync(
      process.execPath,
      [join(nodeDir, "scripts", "patch-loader.js")],
      { encoding: "utf8" },
    );
    return {
      status: result.status,
      stderr: result.stderr,
      loader: readFileSync(join(nodeDir, "index.js"), "utf8"),
      types: readFileSync(join(nodeDir, "index.d.ts"), "utf8"),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("patch-loader reproduces the committed artifacts exactly", (t) => {
  const result = runPatchLoader();

  t.is(result.status, 0, result.stderr);
  t.is(
    result.loader,
    readFileSync(new URL("../index.js", import.meta.url), "utf8"),
    "committed index.js must be exactly what patch-loader produces",
  );
  t.is(
    result.types,
    readFileSync(new URL("../index.d.ts", import.meta.url), "utf8"),
    "committed index.d.ts must be exactly what patch-loader produces",
  );
});

test("patch-loader normalizes target-dependent declaration spacing", (t) => {
  const result = runPatchLoader(({ loader, types }) => {
    const chrome = types.match(/^export declare function chrome\([^\n]*$/m)?.[0];
    if (!chrome) throw new Error("generated declarations have no chrome export");
    return {
      loader,
      types: types.replace(`${chrome}\n\n`, `${chrome}\n\n\n\n`),
    };
  });

  t.is(result.status, 0, result.stderr);
  t.is(
    result.types,
    readFileSync(new URL("../index.d.ts", import.meta.url), "utf8"),
  );
});

test("patch-loader rejects generated declarations that arrive incomplete", (t) => {
  const result = runPatchLoader(({ loader, types }) => ({
    loader,
    types: types.slice(
      0,
      types.indexOf("export declare function supportedBrowsers("),
    ),
  }));

  t.not(result.status, 0, "patch-loader must fail rather than emit a short file");
  t.regex(result.stderr, /Generated declarations were truncated: missing .*\bsupportedBrowsers\b/);
});

test("patch-loader rejects the historical slice-at-load regression", (t) => {
  // Slicing the generated types at a common declaration such as `load`
  // discarded every API generated after it. napi-rs v3 sorts declarations by
  // name, so supportedBrowsers is a stable post-load sentinel for that loss.
  const result = runPatchLoader(({ loader, types }) => {
    const load = types.indexOf("export declare function load(");
    return { loader, types: types.slice(0, types.indexOf("\n", load) + 1) };
  });

  t.not(result.status, 0);
  t.regex(result.stderr, /Generated declarations were truncated/);
  t.regex(result.stderr, /\bsupportedBrowsers\b/);
});

test("patch-loader rejects patching that would drop a declaration", (t) => {
  // The other direction: the input is complete, but the rewrite loses part of
  // it. An early facade marker makes the slice cut before the report APIs,
  // which is the failure the hand-maintained list used to miss for any
  // declaration nobody had added to it.
  const result = runPatchLoader(({ loader, types }) => ({
    loader,
    types: types.replace(
      "export declare function supportedBrowsers(",
      "/** rookie-cookies cross-platform facade */\nexport declare function supportedBrowsers(",
    ),
  }));

  t.not(result.status, 0, "patch-loader must not silently emit a short file");
  t.regex(result.stderr, /Patching dropped generated declarations:/);
  t.regex(result.stderr, /\bsupportedBrowsers\b/);
});

test("patch-loader rejects an unrecognized napi destructure line", (t) => {
  const result = runPatchLoader(({ loader, types }) => ({
    loader: loader.replace(
      /^const \{ .*\bversion\b.*\} = nativeBinding$/m,
      "const { renamed } = nativeBinding",
    ),
    types,
  }));

  t.not(result.status, 0);
  t.regex(result.stderr, /could not find the napi-generated/);
});

test("patch-loader rejects a registry/#[cfg(...)] platform mismatch on fresh napi output", (t) => {
  const result = runPatchLoader(({ loader, types }) => {
    const facadeIndex = types.indexOf("/** rookie-cookies cross-platform facade */");
    let rawTypes = types.slice(0, facadeIndex === -1 ? types.length : facadeIndex);
    // browser_registry.json only registers `cachy` on Linux. Simulate the
    // Rust #[cfg(...)] gate having drifted out of sync with that: on Linux,
    // as if it stopped compiling there; everywhere else, as if it started
    // compiling somewhere it shouldn't.
    if (process.platform === "linux") {
      rawTypes = rawTypes.replace(/^export declare function cachy\([^\n]*\n/m, "");
    } else {
      rawTypes +=
        "export declare function cachy(domains?: Array<string> | undefined | null): Promise<Array<CookieObject>>\n";
    }
    return { loader, types: rawTypes };
  });

  t.not(result.status, 0);
  t.regex(result.stderr, /'cachy' disagrees with bindings\/node\/src\/lib\.rs/);
});

test.serial("report extraction runs off the event loop", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-loop-"));
  const fixture = firefoxFixtureRoot(temp);
  // The settle order is the discriminating signal: a synchronous binding
  // resolves its promise as an already-settled microtask, which drains ahead of
  // the timer macrotask, so `winner` becomes "report". The tick count only
  // corroborates -- it can still be non-zero under a blocking call, since the
  // loop catches up once the call returns. Enough profiles that extraction
  // outlasts the timer on any plausible machine.
  const profileCount = 200;
  writeFirefoxProfileTree(fixture.root, profileCount);

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("event-loop-child.mjs", import.meta.url))],
      { env: { ...process.env, ...fixture.environment } },
    );
    const { winner, ticks, durationMs, profiles, cookiesEmitted } =
      JSON.parse(stdout);

    t.is(profiles, profileCount, "the fixture must produce real extraction work");
    t.is(cookiesEmitted, profileCount);
    t.is(
      winner,
      "timer",
      `a concurrent timer must settle before the report (report took ${durationMs}ms)`,
    );
    t.true(
      ticks > 0,
      `the event loop must advance during extraction (ticks=${ticks}, ${durationMs}ms)`,
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test.serial("report objects use camelCase keys at every depth", async (t) => {
  const temp = mkdtempSync(join(tmpdir(), "rookie-node-issues-"));
  const fixture = firefoxFixtureRoot(temp);
  const healthy = join(fixture.root, "Profiles", "default-release");
  const corrupt = join(fixture.root, "Profiles", "work");
  mkdirSync(healthy, { recursive: true });
  mkdirSync(corrupt, { recursive: true });
  writeFileSync(
    join(fixture.root, "profiles.ini"),
    `[InstallTest]
Default=Profiles/default-release

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/default-release
Default=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/work
`,
  );
  installDatabaseFixture(
    join(healthy, "cookies.sqlite"),
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
  );
  writeFileSync(join(corrupt, "cookies.sqlite"), "this is not a sqlite database");

  try {
    const { stdout } = await execFileAsync(
      process.execPath,
      [fileURLToPath(new URL("issues-child.mjs", import.meta.url))],
      {
        env: {
          ...process.env,
          ...fixture.environment,
          // Keep Chromium-family roots inside the fixture so the absent-browser
          // half of this test cannot discover a real installation.
          XDG_CONFIG_HOME: join(temp, ".config"),
        },
      },
    );
    const observed = JSON.parse(stdout);

    t.deepEqual(observed.reportKeys, [
      "schemaVersion",
      "status",
      "termination",
      "summary",
      "profiles",
      "issues",
    ]);

    for (const key of [...observed.firefoxKeys, ...observed.absentKeys]) {
      t.false(key.includes("_"), `report key ${key} must be camelCase`);
    }
    for (const key of [
      "pathLossy",
      "acquisitionStrategy",
      "countersSaturated",
      "rowsRejected",
      "providerFailures",
    ]) {
      t.true(observed.firefoxKeys.includes(key), `expected key ${key}`);
    }

    // ExtractionIssueObject is the only report DTO with optional fields, so its
    // key set is pinned exactly. Unset context fields must be present and null,
    // matching Python's None and the CLI's serde null -- napi's default would
    // drop the keys and make Node the only surface where they vanish.
    const issueKeys = [
      "code",
      "stage",
      "severity",
      "cause",
      "provider",
      "tier",
      "retryability",
      "occurrences",
      "samples",
      "browserId",
      "installationId",
      "profileId",
      "message",
    ];

    // A failing source proves the nested issue objects are converted too.
    t.truthy(observed.sourceIssue, "the corrupt profile must produce a source issue");
    t.deepEqual(observed.sourceIssueKeys, issueKeys);
    t.is(observed.sourceIssue.severity, "error");
    t.is(typeof observed.sourceIssue.occurrences, "number");
    // Every issue carries its browser since #154 attributed issue context, so
    // this is a populated field rather than the null-vs-absent case. The
    // request-scoped assertions below still cover unset context arriving as
    // null rather than being dropped, which is the napi-specific risk.
    t.is(observed.sourceIssue.browserId, "firefox");

    // browserId is the rename most at risk, so it needs its own scenario.
    t.is(observed.absentStatus, "no_sources");
    t.truthy(observed.requestIssue, "an absent browser must report an issue");
    t.deepEqual(observed.requestIssueKeys, issueKeys);
    t.is(observed.requestIssue.browserId, "chrome");
    t.is(observed.requestIssue.cause, "browser_not_detected");
    t.is(observed.requestIssue.provider, null);
    t.is(observed.requestIssue.tier, null);
    t.is(observed.requestIssue.retryability, "unknown");
    t.is(observed.requestIssue.installationId, null);
    t.is(observed.requestIssue.profileId, null);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});

test("public JavaScript examples await async extraction APIs", (t) => {
  const documents = [
    ["README.md", new URL("../../../README.md", import.meta.url), true],
    ["bindings/node/README.md", new URL("../README.md", import.meta.url), true],
    [
      "examples/javascript/simple.js",
      new URL("../../../examples/javascript/simple.js", import.meta.url),
      false,
    ],
    [
      "examples/javascript/fetch.js",
      new URL("../../../examples/javascript/fetch.js", import.meta.url),
      false,
    ],
    [
      "examples/javascript/from_path.mjs",
      new URL("../../../examples/javascript/from_path.mjs", import.meta.url),
      false,
    ],
  ];
  const asyncApis = [
    "anyBrowser",
    "extractFromPath",
    "cookiesFromPath",
    "chromiumCookiesFromPath",
    "chromiumCookiesFromPathDetailed",
    "firefox",
    "firefoxProfiles",
    "firefoxProfile",
    "zen",
    "librewolf",
    "cachy",
    "chrome",
    "brave",
    "arc",
    "edge",
    "opera",
    "operaGx",
    "chromium",
    "vivaldi",
    "firefoxBased",
    "firefoxBasedDetailed",
    "load",
    "octoBrowser",
    "internetExplorer",
    "safari",
    "chromiumBased",
    "chromiumBasedDetailed",
    "read",
    "jar",
    "fromPath",
    "profiles",
    "report",
    ...REPORT_FUNCTIONS,
  ];
  const callPattern = new RegExp(`\\b(?:${asyncApis.join("|")})\\s*\\(`, "g");
  let checkedCalls = 0;

  for (const [name, url, markdown] of documents) {
    const source = readFileSync(url, "utf8");
    const examples = markdown
      ? [...source.matchAll(/```(?:js|javascript|typescript)([^\n]*)\n([\s\S]*?)```/g)]
          .filter((match) => !/\bhistorical\b/i.test(match[1]))
          .map((match) => match[2])
      : [source];

    for (const example of examples) {
      for (const line of example.split("\n")) {
        const calls = [...line.matchAll(callPattern)];
        checkedCalls += calls.length;
        for (const call of calls) {
          t.true(
            line.slice(0, call.index).includes("await"),
            `${name} must await this async API call: ${line.trim()}`,
          );
        }
      }
    }
  }

  t.true(checkedCalls >= 8, "the doc test must cover the public examples");
});

test("safari reports an unsupported platform outside macOS", async (t) => {
  if (process.platform === "darwin") {
    t.pass();
    return;
  }

  const error = await t.throwsAsync(safari());
  t.regex(error.message, /safari is only available on macOS/);
});

function firefoxFixtureRoot(temp) {
  if (process.platform === "win32") {
    const roaming = join(temp, "Roaming");
    const local = join(temp, "Local");
    return {
      root: join(roaming, "Mozilla", "Firefox"),
      environment: { APPDATA: roaming, LOCALAPPDATA: local },
    };
  }
  if (process.platform === "darwin") {
    return {
      root: join(temp, "Library", "Application Support", "Firefox"),
      environment: { HOME: temp },
    };
  }
  return {
    root: join(temp, ".mozilla", "firefox"),
    environment: { HOME: temp },
  };
}

function writeFirefoxProfileTree(root, count, displayName) {
  const encoded = readFileSync(
    new URL("fixtures/firefox-selected.sqlite.base64", import.meta.url),
    "ascii",
  ).replace(/\s/g, "");
  const database = Buffer.from(encoded, "base64");

  let ini = "[InstallTest]\nDefault=Profiles/p0\n\n";
  for (let index = 0; index < count; index += 1) {
    const directory = join(root, "Profiles", `p${index}`);
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "cookies.sqlite"), database);
    ini += `[Profile${index}]\nName=${displayName ?? `p${index}`}\nIsRelative=1\nPath=Profiles/p${index}\n`;
    ini += index === 0 ? "Default=1\n\n" : "\n";
  }
  writeFileSync(join(root, "profiles.ini"), ini);
}

function installDatabaseFixture(path, fixtureUrl) {
  const encoded = readFileSync(fixtureUrl, "ascii").replace(/\s/g, "");
  writeFileSync(path, Buffer.from(encoded, "base64"));
}
