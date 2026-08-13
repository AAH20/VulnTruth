# VulnTruth

**Stop counting CVEs. Start testing whether scanner conclusions deserve confidence.**

VulnTruth compares vulnerability reports for the same artifact, preserves each
scanner's provenance, explains disagreements, enriches findings with CISA Known
Exploited Vulnerabilities (KEV), and emits a reproducible decision report.

It is not another vulnerability scanner and it does not claim that scanner
agreement proves safety. It is an independent evidence layer between discovery
and remediation.

## Sixty-second demo

Requires Node.js 20 or newer and has no runtime dependencies.

```bash
cd VulnTruth
npm run demo
```

The demo processes deterministic Trivy, Grype and OSV fixtures and writes:

- `artifacts/vulntruth-report.json`
- `artifacts/vulntruth-report.md`
- `artifacts/github-step-summary.md`

Analyze your own exported reports:

```bash
node apps/cli/src/index.js analyze \
  --artifact ghcr.io/acme/api@sha256:abc \
  --trivy ./trivy.json \
  --grype ./grype.json \
  --osv ./osv.json \
  --kev ./known_exploited_vulnerabilities.json \
  --out ./artifacts
```

Use `--fail-on patch-now` when CI should return exit code `2` for a CISA KEV
reported by at least two scanners without a fix-version conflict. The complete
GitHub Action example is in `examples/github-workflow.yml`.

Inputs are read locally. VulnTruth does not scan targets, execute exploits, or
upload evidence.

## What the decision means

| Decision | Deterministic rule in v0.1 |
| --- | --- |
| `patch-now` | CISA KEV and at least two scanners agree |
| `validate-urgent` | CISA KEV with only one scanner, or scanners disagree on fix state |
| `plan-remediation` | At least two scanners agree, with no KEV match |
| `investigate` | Only one scanner reports the finding |

These rules are transparent policy defaults, not universal risk truth. Business
criticality, reachability, control effectiveness and loss magnitude must be
provided by the adopting organization before making a production risk decision.

## Monorepo

```text
apps/cli                 local CLI and demo runner
packages/schema          normalized evidence contract
packages/adapters        Trivy, Grype and OSV parsers
packages/engine          entity resolution and decision policy
packages/report          JSON and board-readable Markdown output
fixtures                 deterministic scanner and KEV evidence
tests                    contract and end-to-end tests
```

## Commercial implementation

Need private registry support, OpenVAS/Nmap/Nuclei/commercial-scanner adapters,
air-gapped deployment, custom cyber-risk quantification, or verified remediation?
See [A2Z SOC Productized Services](https://a2zsoc.com/productized-services) or
[book a consultation](https://a2zsoc.com/consultation).

## Safety and limitations

- Run scanners only against systems and artifacts you are authorized to assess.
- Scanner absence is not proof that a vulnerability is absent.
- Agreement is corroboration, not proof of exploitability.
- KEV is a prioritization input, not a complete risk score.
- No monetary risk is invented from technical findings.
- v0.1 supports JSON exports from Trivy, Grype and OSV-Scanner.
