#!/usr/bin/env node
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseScanner } from "../../../packages/adapters/src/index.js";
import { analyzeObservations } from "../../../packages/engine/src/index.js";
import { renderMarkdown, renderStepSummary } from "../../../packages/report/src/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function options(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    if (!args[index].startsWith("--")) continue;
    parsed[args[index].slice(2)] = args[index + 1];
    index += 1;
  }
  return parsed;
}

async function json(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

async function execute(configuration) {
  const observations = [];
  for (const scanner of ["trivy", "grype", "osv"]) {
    if (configuration[scanner]) observations.push(...parseScanner(scanner, await json(configuration[scanner])));
  }
  if (observations.length === 0) throw new Error("Provide at least one of --trivy, --grype, or --osv");
  const kevDocument = configuration.kev ? await json(configuration.kev) : { vulnerabilities: [] };
  const report = analyzeObservations({
    artifact: configuration.artifact ?? "unknown-artifact",
    observations,
    kevDocument,
  });
  const output = resolve(configuration.out ?? "artifacts");
  await mkdir(output, { recursive: true });
  await Promise.all([
    writeFile(resolve(output, "vulntruth-report.json"), `${JSON.stringify(report, null, 2)}\n`),
    writeFile(resolve(output, "vulntruth-report.md"), renderMarkdown(report)),
    writeFile(resolve(output, "github-step-summary.md"), renderStepSummary(report)),
  ]);
  const stepSummary = renderStepSummary(report);
  process.stdout.write(stepSummary);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, stepSummary);
  }
  process.stdout.write(`Reports written to ${output}\n`);
  if (configuration["fail-on"] === "patch-now" && report.summary.immediateDecisions > 0) {
    process.exitCode = 2;
  }
  return report;
}

async function main() {
  const [command = "help", ...args] = process.argv.slice(2);
  if (command === "demo") {
    await execute({
      artifact: "vulntruth/demo-api@sha256:deterministic",
      trivy: resolve(root, "fixtures/trivy.json"),
      grype: resolve(root, "fixtures/grype.json"),
      osv: resolve(root, "fixtures/osv.json"),
      kev: resolve(root, "fixtures/kev.json"),
      out: resolve(root, "artifacts"),
    });
    return;
  }
  if (command === "analyze") {
    await execute(options(args));
    return;
  }
  process.stdout.write("Usage: vulntruth analyze --trivy FILE --grype FILE --osv FILE [--kev FILE] [--artifact ID] [--out DIR] [--fail-on patch-now]\n       vulntruth demo\n");
}

main().catch((error) => {
  process.stderr.write(`VulnTruth failed: ${error.message}\n`);
  process.exitCode = 1;
});
