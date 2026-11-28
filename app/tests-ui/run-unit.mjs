import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const appDir = fileURLToPath(new URL("..", import.meta.url));
const suite = [
  "tests-ui/architecture-gate.test.ts",
  "tests-ui/audit-20261123.test.ts",
  "tests-ui/c16-network.test.ts",
  "tests-ui/comprehensive.test.ts",
  "tests-ui/dns-cache.test.ts",
  "tests-ui/dns-input.test.ts",
  "tests-ui/document.test.ts",
  "tests-ui/import.test.ts",
  "tests-ui/installed-handoff.test.ts",
  "tests-ui/k3.test.ts",
  "tests-ui/operations.test.ts",
  "tests-ui/overview.test.ts",
  "tests-ui/polish.test.ts",
  "tests-ui/quick-import-retention.test.ts",
  "tests-ui/r10.test.ts",
  "tests-ui/r2-display.test.ts",
  "tests-ui/rules.test.ts",
  "tests-ui/selection.test.ts",
  "tests-ui/settings.test.ts",
  "tests-ui/sidebar.test.ts",
  "tests-ui/smart-probe.test.ts",
  "tests-ui/source-group.test.ts",
  "tests-ui/subscription-round2b.test.ts",
  "tests-ui/subscription.test.ts",
  "tests-ui/tun-029.test.ts",
  "tests-ui/uncertain.test.ts",
  "tests-ui/white-errors.test.ts",
  "tests-ui/yaml.test.ts",
  "tests-ui/ipc-null-fuzz.test.ts",
  "tests-ui/net-addr-format.test.ts",
  "tests-ui/controlled-input-and-race.test.ts",
  "tests-ui/round2-recheck-regressions.test.ts",
];

const res = spawnSync(
  process.execPath,
  [
    "--experimental-transform-types",
    "--import",
    "./tests-ui/support/register.mjs",
    "--test",
    ...suite,
  ],
  { cwd: appDir, stdio: "inherit" },
);
process.exit(res.status ?? 1);
