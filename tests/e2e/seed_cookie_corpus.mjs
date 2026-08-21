// Shared declarative browser seeder. This module intentionally depends only
// on Playwright's BrowserContext/Page shape, so its manifest construction can
// be unit-tested without launching a browser.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const MANIFEST_FILENAME = "rookie-e2e-cookie-manifest.json";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const defaultCorpusPath = join(moduleDir, "cookie_corpus.json");

export function expandedValue(operation) {
  if (Object.hasOwn(operation, "value")) return String(operation.value);
  const repeat = operation.value_repeat;
  if (!repeat) throw new Error("cookie operation must define value or value_repeat");
  return String(repeat.text).repeat(Number(repeat.count));
}

export function selectedTiers(corpus, environment = process.env) {
  const configured = environment.ROOKIE_E2E_CORPUS_TIERS;
  const tiers = configured
    ? configured.split(",").map((value) => value.trim()).filter(Boolean)
    : corpus.default_tiers;
  for (const tier of tiers) {
    if (!Object.hasOwn(corpus.tiers, tier)) {
      throw new Error(`unknown cookie corpus tier '${tier}'`);
    }
  }
  if (tiers.length === 0) throw new Error("cookie corpus must select at least one tier");
  return [...new Set(tiers)];
}

export function applicableScenarios(corpus, engine, tiers, platform = process.platform) {
  return corpus.scenarios.filter(
    (scenario) =>
      scenario.applicability.engines.includes(engine) &&
      scenario.applicability.platforms.includes(platform) &&
      scenario.tiers.some((tier) => tiers.includes(tier)),
  );
}

function finalOperation(scenario) {
  return scenario.operations.at(-1);
}

function cookieMatchesScenario(cookie, scenario, corpus) {
  const operation = finalOperation(scenario);
  const hostname = corpus.origins[scenario.origin].hostname;
  const cookieDomain = cookie.domain.replace(/^\./, "").toLowerCase();
  const domainMatches =
    hostname === cookieDomain || hostname.endsWith(`.${cookieDomain}`);
  return (
    domainMatches &&
    cookie.name === operation.name &&
    cookie.path === (operation.path ?? "/")
  );
}

function observedExpiry(cookie) {
  return cookie.expires == null || cookie.expires <= 0
    ? null
    : Math.trunc(cookie.expires);
}

function validateBrowserObservation(cookie, scenario) {
  const operation = finalOperation(scenario);
  const expectedValue = expandedValue(operation);
  const mismatches = [];
  if (cookie.value !== expectedValue) mismatches.push(`value=${JSON.stringify(cookie.value)}`);
  if (cookie.path !== (operation.path ?? "/")) mismatches.push(`path=${JSON.stringify(cookie.path)}`);
  if (cookie.secure !== Boolean(operation.secure)) mismatches.push(`secure=${cookie.secure}`);
  if (cookie.httpOnly !== Boolean(operation.http_only)) mismatches.push(`httpOnly=${cookie.httpOnly}`);
  if (operation.same_site && cookie.sameSite !== operation.same_site) {
    mismatches.push(`sameSite=${JSON.stringify(cookie.sameSite)}`);
  }
  if (Object.hasOwn(operation, "max_age") && operation.max_age > 0 && observedExpiry(cookie) == null) {
    mismatches.push("expires=session");
  }
  if (
    !Object.hasOwn(operation, "max_age") &&
    !Object.hasOwn(operation, "expires") &&
    observedExpiry(cookie) != null
  ) {
    mismatches.push(`expires=${cookie.expires}`);
  }
  if (mismatches.length > 0) {
    throw new Error(
      `browser observation for scenario '${scenario.id}' disagrees with the declarative seed: ${mismatches.join(", ")}`,
    );
  }
}

function flatExpectation(cookie, scenario, engine) {
  const operation = finalOperation(scenario);
  return {
    domain: cookie.domain,
    path: operation.path ?? "/",
    secure: Boolean(operation.secure),
    expires: observedExpiry(cookie),
    name: operation.name,
    value: expandedValue(operation),
    http_only: Boolean(operation.http_only),
    same_site: scenario.expected.same_site[engine],
  };
}

function contextExpectation(corpus, engine, operation, baseUrl) {
  const template = corpus.context_expectations[engine];
  const parsed = new URL(baseUrl);
  const sourceScheme = parsed.protocol === "https:" ? 2 : 1;
  const sourcePort = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  const persistent =
    (Object.hasOwn(operation, "max_age") && operation.max_age > 0) ||
    Object.hasOwn(operation, "expires");
  return Object.fromEntries(
    Object.entries(template).map(([key, value]) => {
      if (value === "@source_scheme") return [key, sourceScheme];
      if (value === "@source_port") return [key, sourcePort];
      if (value === "@is_persistent") return [key, persistent];
      return [key, value];
    }),
  );
}

export function buildExpectedManifest({
  corpus,
  engine,
  tiers,
  platform = process.platform,
  baseUrl,
  observedCookies,
  browserVersion,
  userAgent,
}) {
  const scenarios = applicableScenarios(corpus, engine, tiers, platform);
  const unmatched = new Set(observedCookies.map((_cookie, index) => index));
  const filteredFlat = [];
  const unfilteredFlat = [];
  const detailed = [];
  const excluded = [];
  const scenarioObservations = [];

  for (const scenario of scenarios) {
    const matches = observedCookies
      .map((cookie, index) => ({ cookie, index }))
      .filter(({ cookie }) => cookieMatchesScenario(cookie, scenario, corpus));
    if (!scenario.expected.stored) {
      if (matches.length !== 0) {
        throw new Error(`deleted/rejected scenario '${scenario.id}' remained in the browser cookie jar`);
      }
      excluded.push({ scenario_id: scenario.id, reason: "expected_not_stored" });
      scenarioObservations.push({ scenario_id: scenario.id, stored: false });
      continue;
    }
    if (matches.length !== 1) {
      throw new Error(
        `scenario '${scenario.id}' expected exactly one accepted browser cookie, observed ${matches.length}`,
      );
    }
    const { cookie, index } = matches[0];
    unmatched.delete(index);
    validateBrowserObservation(cookie, scenario);
    const flat = flatExpectation(cookie, scenario, engine);
    const origin = corpus.origins[scenario.origin];
    unfilteredFlat.push(flat);
    if (origin.included_by_domain_filter) filteredFlat.push(flat);
    const operation = finalOperation(scenario);
    detailed.push({
      cookie: flat,
      context: contextExpectation(corpus, engine, operation, baseUrl),
    });
    scenarioObservations.push({
      scenario_id: scenario.id,
      stored: true,
      domain: cookie.domain,
      expires: flat.expires,
    });
  }

  if (unmatched.size > 0) {
    const unexpected = [...unmatched].map((index) => {
      const cookie = observedCookies[index];
      return `${cookie.domain}${cookie.path}:${cookie.name}`;
    });
    throw new Error(`fresh browser profile contained unexpected cookies: ${unexpected.join(", ")}`);
  }

  return {
    schema_version: 1,
    corpus_schema_version: corpus.schema_version,
    engine,
    platform,
    tiers,
    browser: {
      version: browserVersion,
      user_agent: userAgent,
    },
    domain_filter: corpus.origins.primary.hostname,
    identities: corpus.identities,
    expected: {
      filtered_flat: filteredFlat,
      unfiltered_flat: unfilteredFlat,
      detailed,
    },
    excluded,
    observations: scenarioObservations,
  };
}

function routeUrl(baseUrl, corpus, originName, phase, engine, tiers) {
  const url = new URL(baseUrl);
  url.hostname = corpus.origins[originName].hostname;
  url.pathname = `/corpus/${phase}`;
  url.search = new URLSearchParams({ engine, tiers: tiers.join(",") }).toString();
  return url.href;
}

export async function seedCookieCorpus({ context, page, engine, profileDir, baseUrl }) {
  const corpusPath = process.env.ROOKIE_E2E_COOKIE_CORPUS || defaultCorpusPath;
  const corpus = JSON.parse(await readFile(corpusPath, "utf8"));
  const tiers = selectedTiers(corpus);
  const scenarios = applicableScenarios(corpus, engine, tiers);
  const routes = [];
  for (const phase of corpus.phase_order) {
    for (const originName of Object.keys(corpus.origins)) {
      const needed = scenarios.some(
        (scenario) =>
          scenario.origin === originName &&
          scenario.operations.some((operation) => operation.phase === phase),
      );
      if (needed) routes.push(routeUrl(baseUrl, corpus, originName, phase, engine, tiers));
    }
  }
  for (const route of routes) {
    await page.goto(route, { waitUntil: "networkidle" });
  }

  const userAgent = await page.evaluate(() => navigator.userAgent);
  const manifest = buildExpectedManifest({
    corpus,
    engine,
    tiers,
    baseUrl,
    observedCookies: await context.cookies(),
    browserVersion: context.browser()?.version() ?? "unknown",
    userAgent,
  });
  const manifestPath =
    process.env.ROOKIE_E2E_COOKIE_MANIFEST || join(profileDir, MANIFEST_FILENAME);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  return { manifest, manifestPath, userAgent };
}
