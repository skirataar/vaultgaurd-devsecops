#!/usr/bin/env bash
# ==============================================================================
# VaultGuard DevSecOps: Phase 5 Security Scanning Orchestrator
# Runs Semgrep AST SAST and Trivy Container & Supply-Chain Audits
# ==============================================================================
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "========================================================================"
echo "🛡️  VaultGuard DevSecOps: Phase 5 Multi-Scanner Security Suite"
echo "    1. Semgrep Custom AST SAST (BOLA, SQLi, SSRF)"
echo "    2. Trivy Container Misconfiguration Audit (Dockerfile vs Dockerfile.vulnerable)"
echo "    3. Trivy Secret & Filesystem Dependency Scan"
echo "========================================================================"
echo ""

# ------------------------------------------------------------------------------
# STEP 1: Custom Semgrep SAST Scan
# ------------------------------------------------------------------------------
echo "========================================================================"
echo "▶ STEP 1: Running Custom Semgrep SAST Rules (.semgrep/vaultguard-rules.yml)"
echo "========================================================================"
if command -v semgrep &>/dev/null; then
  semgrep scan --config .semgrep/vaultguard-rules.yml src/ --jobs 1 || true
else
  echo "⚠️ Semgrep binary not found in PATH. Install via 'pip install semgrep'."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 2: Trivy Dockerfile Misconfiguration Audit
# ------------------------------------------------------------------------------
echo "========================================================================"
echo "▶ STEP 2: Running Trivy Container Misconfiguration Audit"
echo "========================================================================"
if command -v trivy &>/dev/null; then
  echo "Auditing Dockerfiles for CIS Benchmarks and container hardening rules..."
  trivy config --config trivy.yaml . || true
else
  echo "⚠️ Trivy binary not found in PATH. Install via 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ~/.local/bin'."
fi
echo ""

# ------------------------------------------------------------------------------
# STEP 3: Trivy Filesystem & Secret Scan
# ------------------------------------------------------------------------------
echo "========================================================================"
echo "▶ STEP 3: Running Trivy Secret & Dependency Vulnerability Scan"
echo "========================================================================"
if command -v trivy &>/dev/null; then
  echo "Auditing codebase for embedded credentials, API tokens, and supply-chain vulnerabilities..."
  trivy fs --config trivy.yaml --scanners secret,vuln . || true
else
  echo "⚠️ Trivy binary not found in PATH."
fi
echo ""

echo "========================================================================"
echo "✨ Phase 5 Local Security Scans Complete!"
echo "========================================================================"
