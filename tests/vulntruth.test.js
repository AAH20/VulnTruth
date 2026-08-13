import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseGrype, parseOsv, parseTrivy } from "../packages/adapters/src/index.js";
import { analyzeObservations } from "../packages/engine/src/index.js";
import { renderMarkdown } from "../packages/report/src/index.js";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile as readOutput } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

async function fixture(name) {
  return JSON.parse(await readFile(new URL(`../fixtures/${name}`, import.meta.url), "utf8"));
}

test("normalizes three scanner formats without losing provenance", async () => {
  const observations = [
    ...parseTrivy(await fixture("trivy.json")),
    ...parseGrype(await fixture("grype.json")),
    ...parseOsv(await fixture("osv.json")),
  ];
  assert.equal(observations.length, 8);
  assert.deepEqual([...new Set(observations.map((item) => item.scanner))].sort(), ["grype", "osv", "trivy"]);
});

test("explains scanner coverage, severity, and fix disagreements", async () => {
  const observations = [
    ...parseTrivy(await fixture("trivy.json")),
    ...parseGrype(await fixture("grype.json")),
    ...parseOsv(await fixture("osv.json")),
  ];
  const report = analyzeObservations({
    artifact: "demo",
    observations,
    kevDocument: await fixture("kev.json"),
  });
  assert.equal(report.summary.rawObservations, 8);
  assert.equal(report.summary.distinctFindings, 4);
  assert.equal(report.summary.consensusFindings, 1);
  assert.equal(report.summary.knownExploitedFindings, 2);
  assert.equal(report.summary.immediateDecisions, 1);
  const curl = report.findings.find((item) => item.vulnerabilityId === "CVE-2024-0002");
  assert.deepEqual(curl.disagreementReasons, ["scanner-coverage", "fix-availability"]);
});

test("renders a board-readable report with an explicit interpretation boundary", async () => {
  const report = analyzeObservations({
    artifact: "demo",
    observations: parseTrivy(await fixture("trivy.json")),
    kevDocument: await fixture("kev.json"),
  });
  const markdown = renderMarkdown(report);
  assert.match(markdown, /Decision summary/);
  assert.match(markdown, /Scanner absence is not proof/);
  assert.match(markdown, /A2Z SOC Productized Services/);
});

test("returns a distinct policy exit code while still writing evidence", async () => {
  const output = await mkdtemp(join(tmpdir(), "vulntruth-"));
  const result = spawnSync(process.execPath, [
    resolve("apps/cli/src/index.js"), "analyze",
    "--artifact", "demo",
    "--trivy", resolve("fixtures/trivy.json"),
    "--grype", resolve("fixtures/grype.json"),
    "--osv", resolve("fixtures/osv.json"),
    "--kev", resolve("fixtures/kev.json"),
    "--out", output,
    "--fail-on", "patch-now",
  ], { encoding: "utf8" });
  assert.equal(result.status, 2);
  const report = JSON.parse(await readOutput(join(output, "vulntruth-report.json"), "utf8"));
  assert.equal(report.summary.immediateDecisions, 1);
});
