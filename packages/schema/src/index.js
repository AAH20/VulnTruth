export const SEVERITY_ORDER = Object.freeze({
  unknown: 0,
  negligible: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
});

export function normalizeSeverity(value) {
  const normalized = String(value ?? "unknown").toLowerCase();
  return Object.hasOwn(SEVERITY_ORDER, normalized) ? normalized : "unknown";
}

export function findingKey(finding) {
  const vulnerability = finding.vulnerabilityId.toUpperCase();
  const packageIdentity = finding.purl || `${finding.ecosystem}:${finding.packageName}`;
  return `${vulnerability}|${packageIdentity}`.toLowerCase();
}

export function highestSeverity(values) {
  return values
    .map(normalizeSeverity)
    .sort((left, right) => SEVERITY_ORDER[right] - SEVERITY_ORDER[left])[0] ?? "unknown";
}
