// Node adapter for the declarative browser-coverage contract. The Python and
// Node assert scripts resolve browser-specific convenience functions from the
// same manifest, so neither binding's dispatch table can drift away from the
// declared matrix without failing tests/e2e/test_browser_coverage.py.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const coveragePath = join(moduleDir, "browser_coverage.json");

export function loadCoverage() {
  return JSON.parse(readFileSync(coveragePath, "utf8"));
}

export function platformId(system = process.platform) {
  if (system === "win32") return "windows";
  if (system === "darwin") return "macos";
  return "linux";
}

// Resolve whatever ROOKIE_E2E_TARGET_BROWSER carries — a registry canonical ID
// or one of its declared aliases — onto the convenience contract for it.
// Anything the manifest does not claim throws, which keeps an unrecognised
// target browser a hard failure rather than a silently skipped surface.
export function convenienceFunction(
  browserName,
  dispatch,
  document,
  platform = platformId(),
) {
  const coverage = document ?? loadCoverage();
  const wanted = browserName.trim().toLowerCase();
  for (const [browserId, entry] of Object.entries(
    coverage.convenience_functions,
  )) {
    if (wanted !== browserId && !entry.aliases.includes(wanted)) continue;
    if (entry.dispatch !== dispatch) {
      throw new Error(
        `${browserId} declares the '${entry.dispatch}' dispatch family, not '${dispatch}'`,
      );
    }
    if (!entry.platforms.includes(platform)) {
      throw new Error(
        `${browserId} declares no convenience function on ${platform}`,
      );
    }
    return { browserId, ...entry };
  }
  throw new Error(
    `no convenience function is declared for browser '${browserName}'`,
  );
}
