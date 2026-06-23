// Package dockerproxy implements a pull-through Docker Registry V2 proxy that
// gates images on Trivy (CVE/secrets) and ClamAV (signature malware) before
// serving them. It is isolated from proxy.Handler and reuses Jōei's existing
// policy, supply-chain, cache, and telemetry subsystems via their interfaces.
package dockerproxy
