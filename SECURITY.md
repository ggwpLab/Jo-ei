# Security Policy

Jōei is a security tool — it sits between your package managers and upstream
registries and enforces supply-chain policy. We take vulnerabilities in Jōei
itself seriously and appreciate responsible disclosure.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** and fill in the advisory form.

You can expect an acknowledgement within **7 days**. We will keep you informed
as we triage, develop a fix, and coordinate a release. Please give us a
reasonable window to ship a fix before disclosing publicly; we will credit you
in the advisory unless you prefer otherwise.

When reporting, include as much of the following as you can:

- Affected component (proxy data path, admin console/API, a registry adapter,
  a scanner integration, the Docker image, …)
- Reproduction steps or a proof of concept
- Impact assessment (what an attacker gains)
- Affected version or commit

## Supported Versions

Jōei is pre-1.0. Security fixes land on `main` and ship in the next release;
only the **latest release** is supported. Once 1.0 is published, this policy
will be revisited.

## Scope Notes

Reports we consider in scope include (non-exhaustive):

- Bypass of a gate (supply-chain min-age, CVE, malware, Trivy image scan,
  denylist) that lets a blocked artifact reach a client
- Cache poisoning or serving an artifact different from the verified one
- Authentication or authorization flaws in the admin console/API
- Path traversal, SSRF, or injection in the proxy or console

Out of scope: vulnerabilities in upstream registries, in scanned packages
themselves, or in third-party scanners (ClamAV, Trivy, osv.dev) — report those
to the respective projects.
