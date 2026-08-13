function escapeCell(value) {
  return String(value ?? "—").replaceAll("|", "\\|").replaceAll("\n", " ");
}

export function renderMarkdown(report) {
  const { summary } = report;
  const lines = [
    "# VulnTruth Scanner Reality Report",
    "",
    `**Artifact:** \`${report.artifact}\`  `,
    `**Generated:** ${report.generatedAt}`,
    "",
    "## Decision summary",
    "",
    `- Raw observations: **${summary.rawObservations}**`,
    `- Normalized distinct findings: **${summary.distinctFindings}**`,
    `- Findings reported by every scanner: **${summary.consensusFindings}**`,
    `- Findings with a disagreement: **${summary.disputedFindings}**`,
    `- CISA KEV matches: **${summary.knownExploitedFindings}**`,
    `- Immediate patch decisions: **${summary.immediateDecisions}**`,
    `- Full-scanner agreement rate: **${(summary.agreementRate * 100).toFixed(1)}%**`,
    "",
    "## Scanner observations",
    "",
    "| Scanner | Raw observations |",
    "| --- | ---: |",
    ...Object.entries(summary.rawByScanner).map(([scanner, count]) => `| ${scanner} | ${count} |`),
    "",
    "## Disagreement matrix",
    "",
    "| Vulnerability | Package | Severity | Scanners | KEV | Disagreement | Decision |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...report.findings.map((finding) => `| ${escapeCell(finding.vulnerabilityId)} | ${escapeCell(finding.packageName)} | ${finding.severity} | ${finding.scanners.join(", ")} | ${finding.isKev ? "yes" : "no"} | ${finding.disagreementReasons.join(", ") || "none"} | **${finding.decision}** |`),
    "",
    "## Interpretation boundary",
    "",
    ...report.limitations.map((limitation) => `- ${limitation}`),
    "",
    "## Get implementation support",
    "",
    "Need private scanner adjudication, air-gapped deployment, cyber-risk quantification, or verified remediation? Visit [A2Z SOC Productized Services](https://a2zsoc.com/productized-services) or [book a consultation](https://a2zsoc.com/consultation).",
    "",
  ];
  return lines.join("\n");
}

export function renderStepSummary(report) {
  return [
    "## VulnTruth",
    "",
    `**${report.summary.distinctFindings}** distinct findings from **${report.scanners.length}** scanners`,
    "",
    `- ${report.summary.knownExploitedFindings} CISA KEV matches`,
    `- ${report.summary.disputedFindings} scanner disagreements`,
    `- ${report.summary.immediateDecisions} immediate patch decisions`,
    `- ${(report.summary.agreementRate * 100).toFixed(1)}% full-scanner agreement`,
    "",
    "VulnTruth measures evidence agreement; it does not prove the absence of risk.",
    "",
  ].join("\n");
}
