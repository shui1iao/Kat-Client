import { pathToFileURL } from "node:url";

/**
 * Shared Playwright loader for UI browser tests.
 * Uses KAT_PLAYWRIGHT_CORE (absolute path to playwright-core/index.mjs) when
 * provided, otherwise falls back to standard Node resolution of playwright-core.
 */
export async function loadPlaywright() {
  const override = process.env.KAT_PLAYWRIGHT_CORE?.trim();
  const target = override ? pathToFileURL(override).href : "playwright-core";
  return import(target);
}
