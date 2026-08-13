import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const args = [
  resolve(root, "apps/cli/src/index.js"),
  "analyze",
  "--artifact", process.env.INPUT_ARTIFACT,
  "--out", process.env.INPUT_OUTPUT || "vulntruth-artifacts",
];

for (const [flag, value] of [
  ["--trivy", process.env.INPUT_TRIVY],
  ["--grype", process.env.INPUT_GRYPE],
  ["--osv", process.env.INPUT_OSV],
  ["--kev", process.env.INPUT_KEV],
  ["--fail-on", process.env.INPUT_FAIL_ON === "none" ? null : process.env.INPUT_FAIL_ON],
]) {
  if (value) args.push(flag, value);
}

const result = spawnSync(process.execPath, args, { stdio: "inherit" });
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
