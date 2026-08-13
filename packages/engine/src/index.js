import { findingKey, highestSeverity } from "../../schema/src/index.js";

function kevIndex(document) {
  const entries = document.vulnerabilities ?? document.catalogVersion?.vulnerabilities ?? [];
  return new Map(entries.map((entry) => [String(entry.cveID).toUpperCase(), entry]));
}

function explainDisagreement(observations, scannerCount) {
  const reasons = [];
  const scanners = new Set(observations.map((item) => item.scanner));
  const severities = new Set(observations.map((item) => item.severity));
  const fixedVersions = new Set(observations.map((item) => item.fixedVersion ?? "none"));
  if (scanners.size < scannerCount) reasons.push("scanner-coverage");
  if (severities.size > 1) reasons.push("severity-source");
  if (fixedVersions.size > 1) reasons.push("fix-availability");
  return reasons;
}

function decide({ isKev, scannerAgreement, disagreementReasons }) {
  if (isKev && scannerAgreement >= 2 && !disagreementReasons.includes("fix-availability")) {
    return "patch-now";
  }
  if (isKev) return "validate-urgent";
  if (scannerAgreement >= 2) return "plan-remediation";
  return "investigate";
}

export function analyzeObservations({ artifact, observations, kevDocument = { vulnerabilities: [] } }) {
  const scanners = [...new Set(observations.map((item) => item.scanner))].sort();
  const groups = new Map();
  for (const item of observations) {
    const key = findingKey(item);
    const existing = groups.get(key) ?? [];
    existing.push(item);
    groups.set(key, existing);
  }

  const knownExploited = kevIndex(kevDocument);
  const findings = [...groups.entries()].map(([key, items]) => {
    const scannerNames = [...new Set(items.map((item) => item.scanner))].sort();
    const vulnerabilityId = items[0].vulnerabilityId.toUpperCase();
    const kev = knownExploited.get(vulnerabilityId) ?? null;
    const disagreementReasons = explainDisagreement(items, scanners.length);
    return {
      key,
      vulnerabilityId,
      packageName: items[0].packageName,
      installedVersion: items[0].installedVersion,
      purl: items.find((item) => item.purl)?.purl ?? null,
      scanners: scannerNames,
      scannerAgreement: scannerNames.length,
      severity: highestSeverity(items.map((item) => item.severity)),
      severities: Object.fromEntries(items.map((item) => [item.scanner, item.severity])),
      fixedVersions: Object.fromEntries(items.map((item) => [item.scanner, item.fixedVersion])),
      isKev: Boolean(kev),
      kev: kev ? {
        dateAdded: kev.dateAdded ?? null,
        dueDate: kev.dueDate ?? null,
        requiredAction: kev.requiredAction ?? null,
      } : null,
      disagreementReasons,
      decision: decide({
        isKev: Boolean(kev),
        scannerAgreement: scannerNames.length,
        disagreementReasons,
      }),
    };
  }).sort((left, right) => {
    if (left.isKev !== right.isKev) return left.isKev ? -1 : 1;
    return right.scannerAgreement - left.scannerAgreement;
  });

  const rawByScanner = Object.fromEntries(scanners.map((scanner) => [
    scanner,
    observations.filter((item) => item.scanner === scanner).length,
  ]));
  const consensus = findings.filter((item) => item.scannerAgreement === scanners.length).length;
  const disputed = findings.filter((item) => item.disagreementReasons.length > 0).length;
  return {
    schemaVersion: "0.1.0",
    generatedAt: new Date().toISOString(),
    artifact,
    scanners,
    summary: {
      rawObservations: observations.length,
      rawByScanner,
      distinctFindings: findings.length,
      consensusFindings: consensus,
      disputedFindings: disputed,
      knownExploitedFindings: findings.filter((item) => item.isKev).length,
      immediateDecisions: findings.filter((item) => item.decision === "patch-now").length,
      agreementRate: findings.length === 0 ? 0 : Number((consensus / findings.length).toFixed(4)),
    },
    findings,
    limitations: [
      "Scanner absence is not proof of vulnerability absence.",
      "Agreement is corroboration, not proof of reachability or exploitability.",
      "Business loss and control effectiveness require organization-provided evidence.",
    ],
  };
}
