import { normalizeSeverity } from "../../schema/src/index.js";

function observation(scanner, input) {
  return {
    scanner,
    vulnerabilityId: String(input.vulnerabilityId),
    packageName: String(input.packageName ?? "unknown"),
    installedVersion: String(input.installedVersion ?? "unknown"),
    fixedVersion: input.fixedVersion ? String(input.fixedVersion) : null,
    severity: normalizeSeverity(input.severity),
    ecosystem: String(input.ecosystem ?? "unknown").toLowerCase(),
    purl: input.purl ? String(input.purl) : null,
    target: input.target ? String(input.target) : null,
    source: input.source ? String(input.source) : null,
  };
}

export function parseTrivy(document) {
  const observations = [];
  for (const result of document.Results ?? []) {
    for (const finding of result.Vulnerabilities ?? []) {
      observations.push(observation("trivy", {
        vulnerabilityId: finding.VulnerabilityID,
        packageName: finding.PkgName,
        installedVersion: finding.InstalledVersion,
        fixedVersion: finding.FixedVersion,
        severity: finding.Severity,
        ecosystem: result.Type,
        purl: finding.PkgIdentifier?.PURL,
        target: result.Target,
        source: finding.DataSource?.Name,
      }));
    }
  }
  return observations;
}

export function parseGrype(document) {
  return (document.matches ?? []).map((match) => observation("grype", {
    vulnerabilityId: match.vulnerability?.id,
    packageName: match.artifact?.name,
    installedVersion: match.artifact?.version,
    fixedVersion: match.vulnerability?.fix?.versions?.[0],
    severity: match.vulnerability?.severity,
    ecosystem: match.artifact?.type,
    purl: match.artifact?.purl,
    target: document.source?.target?.userInput,
    source: match.vulnerability?.dataSource,
  }));
}

export function parseOsv(document) {
  const observations = [];
  for (const result of document.results ?? []) {
    for (const pkg of result.packages ?? []) {
      for (const vulnerability of pkg.vulnerabilities ?? []) {
        observations.push(observation("osv", {
          vulnerabilityId: vulnerability.id,
          packageName: pkg.package?.name,
          installedVersion: pkg.package?.version,
          fixedVersion: vulnerability.fixed_version,
          severity: vulnerability.database_specific?.severity,
          ecosystem: pkg.package?.ecosystem,
          purl: pkg.package?.purl,
          source: "osv.dev",
        }));
      }
    }
  }
  return observations;
}

export function parseScanner(scanner, document) {
  const parsers = { trivy: parseTrivy, grype: parseGrype, osv: parseOsv };
  if (!parsers[scanner]) throw new Error(`Unsupported scanner: ${scanner}`);
  return parsers[scanner](document);
}
