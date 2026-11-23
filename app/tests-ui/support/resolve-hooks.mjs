// Node test-runner resolver for app sources: the app is bundled by Vite, so its
// relative imports are extensionless ("./yaml"). Map them to the .ts/.tsx file.
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
export async function resolve(specifier, context, next) {
  if ((specifier.startsWith('./') || specifier.startsWith('../')) && context.parentURL?.startsWith('file:') && !/\.[cm]?[jt]sx?$|\.json$|\.css$/.test(specifier)) {
    for (const ext of ['.ts', '.tsx', '/index.ts']) {
      const url = new URL(specifier + ext, context.parentURL);
      if (existsSync(fileURLToPath(url))) return next(url.href, context);
    }
  }
  return next(specifier, context);
}
