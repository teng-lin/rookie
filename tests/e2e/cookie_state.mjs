import process from "node:process";

export function stateFromEnvironment(defaultName, defaultValue) {
  const required = process.env.ROOKIE_E2E_REQUIRED_COOKIES_JSON
    ? JSON.parse(process.env.ROOKIE_E2E_REQUIRED_COOKIES_JSON)
    : { [defaultName]: defaultValue };
  const forbidden = JSON.parse(
    process.env.ROOKIE_E2E_FORBIDDEN_COOKIES_JSON ?? "[]",
  );
  if (
    required === null ||
    Array.isArray(required) ||
    typeof required !== "object" ||
    !Object.entries(required).every(
      ([name, value]) => typeof name === "string" && typeof value === "string",
    )
  ) {
    throw new Error(
      "ROOKIE_E2E_REQUIRED_COOKIES_JSON must be a JSON object of strings",
    );
  }
  if (
    !Array.isArray(forbidden) ||
    !forbidden.every((name) => typeof name === "string")
  ) {
    throw new Error(
      "ROOKIE_E2E_FORBIDDEN_COOKIES_JSON must be a JSON array of strings",
    );
  }
  for (const name of forbidden) {
    if (Object.hasOwn(required, name)) {
      throw new Error(`required and forbidden cookie names overlap: ${name}`);
    }
  }
  return { required, forbidden };
}

export function assertCookieState(cookies, required, forbidden, surface) {
  for (const [name, value] of Object.entries(required)) {
    const matches = cookies.filter((cookie) => cookie.name === name);
    if (matches.length !== 1) {
      throw new Error(
        `${surface}: expected exactly one '${name}', got ${matches.length}`,
      );
    }
    if (matches[0].value !== value) {
      throw new Error(
        `${surface}: '${name}' expected '${value}', got '${matches[0].value}'`,
      );
    }
  }
  for (const name of forbidden) {
    const matches = cookies.filter((cookie) => cookie.name === name);
    if (matches.length > 0) {
      throw new Error(
        `${surface}: forbidden/deleted cookie '${name}' remained (${matches.length} row(s))`,
      );
    }
  }
  if (process.env.ROOKIE_E2E_EXACT_COOKIE_STATE === "1") {
    const actualNames = cookies.map((cookie) => cookie.name);
    const expectedNames = Object.keys(required);
    if (
      cookies.length !== expectedNames.length ||
      actualNames.some((name) => !Object.hasOwn(required, name))
    ) {
      throw new Error(
        `${surface}: exact active-writer set mismatch; expected ${JSON.stringify(expectedNames.sort())}, got ${JSON.stringify(actualNames.sort())}`,
      );
    }
  }
}
