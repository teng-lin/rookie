// Node adapter for the independent Python exact-set verifier. Keeping the
// comparison implementation outside the Node binding under test prevents a
// shared native projection bug from becoming its own expected value.

import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const MANIFEST_FILENAME = "rookie-e2e-cookie-manifest.json";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const verifier = join(moduleDir, "verify_cookie_manifest.py");
const workspaceRoot = dirname(dirname(moduleDir));

function pythonExecutable() {
  if (process.env.ROOKIE_E2E_PYTHON) return process.env.ROOKIE_E2E_PYTHON;
  const venv =
    process.platform === "win32"
      ? join(workspaceRoot, ".venv", "Scripts", "python.exe")
      : join(workspaceRoot, ".venv", "bin", "python");
  if (existsSync(venv)) return venv;
  return process.platform === "win32" ? "python" : "python3";
}

export function findManifest(profileOrDb, expectedName = "rookie_ci") {
  if (process.env.ROOKIE_E2E_COOKIE_MANIFEST) {
    return process.env.ROOKIE_E2E_COOKIE_MANIFEST;
  }
  if (!profileOrDb || expectedName !== "rookie_ci") return null;
  let current = resolve(profileOrDb);
  if (!existsSync(join(current, MANIFEST_FILENAME))) current = dirname(current);
  while (true) {
    const candidate = join(current, MANIFEST_FILENAME);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

export function recordsForVerifier(projection, records) {
  return records.map((record) => {
    const cookie = projection === "detailed" ? record?.cookie : record;
    if (!cookie || typeof cookie !== "object" || cookie.expires !== undefined) {
      return record;
    }
    // The Node binding intentionally exposes Option<timestamp> as an optional
    // property. JSON.stringify drops an undefined property, while the shared
    // semantic manifest represents a session cookie as expires: null.
    const normalizedCookie = { ...cookie, expires: null };
    return projection === "detailed"
      ? { ...record, cookie: normalizedCookie }
      : normalizedCookie;
  });
}

export function verifyCookieRecords(
  manifestPath,
  projection,
  records,
  surface,
) {
  const completed = spawnSync(
    pythonExecutable(),
    [
      verifier,
      "--manifest",
      manifestPath,
      "--projection",
      projection,
      "--surface",
      surface,
    ],
    {
      input: JSON.stringify(recordsForVerifier(projection, records)),
      encoding: "utf8",
      env: process.env,
    },
  );
  if (completed.error) throw completed.error;
  if (completed.status !== 0) {
    throw new Error(
      completed.stderr.trim() ||
        completed.stdout.trim() ||
        `${surface}: cookie manifest verifier exited ${completed.status}`,
    );
  }
  if (completed.stdout.trim()) console.log(completed.stdout.trim());
}
