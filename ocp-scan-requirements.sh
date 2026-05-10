#!/usr/bin/env bash
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${OUT_DIR:-ocp-cis-prereq-$TS}"
REPORT="$OUT_DIR/prereq-report.md"

mkdir -p "$OUT_DIR"

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

PASS=0
WARN=0
FAIL=0

section(){ echo -e "\n${BLUE}== $1 ==${NC}"; }
ok(){ echo -e "${GREEN}[OK]${NC} $1"; PASS=$((PASS+1)); }
warn(){ echo -e "${YELLOW}[WARN]${NC} $1"; WARN=$((WARN+1)); }
fail(){ echo -e "${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }

record() {
  echo "$1" >> "$OUT_DIR/checks.txt"
}

check_cmd() {
  if command -v "$1" >/dev/null 2>&1; then
    ok "$1 found: $(command -v "$1")"
    record "PASS,$1 found,$(command -v "$1")"
  else
    fail "$1 not found"
    record "FAIL,$1 not found,"
  fi
}

section "Local Tooling"

check_cmd oc
check_cmd jq

if ! command -v oc >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo
  fail "Required local tools are missing"
  exit 1
fi

section "OpenShift Login and Permissions"

if oc whoami >/dev/null 2>&1; then
  USER="$(oc whoami)"
  CLUSTER="$(oc whoami --show-server)"
  ok "Logged in as $USER"
  ok "Cluster API: $CLUSTER"
else
  fail "oc login required"
  exit 1
fi

if oc auth can-i '*' '*' >/dev/null 2>&1; then
  ok "User has cluster-admin-like permission"
else
  fail "User does not have cluster-admin-like permission"
fi

section "Cluster Version and Health"

oc get clusterversion version -o yaml > "$OUT_DIR/clusterversion.yaml" 2>/dev/null || true
oc get co > "$OUT_DIR/clusteroperators.txt" 2>/dev/null || true
oc get nodes -o wide > "$OUT_DIR/nodes.txt" 2>/dev/null || true
oc get nodes -o json > "$OUT_DIR/nodes.json" 2>/dev/null || true

OCP_VERSION="$(oc get clusterversion version -o jsonpath='{.status.desired.version}' 2>/dev/null || echo unknown)"
ok "OpenShift version: $OCP_VERSION"

NOT_AVAILABLE="$(oc get co --no-headers 2>/dev/null | awk '$3!="True" {print $1}' | tr '\n' ' ' || true)"
DEGRADED="$(oc get co --no-headers 2>/dev/null | awk '$4=="True" {print $1}' | tr '\n' ' ' || true)"
PROGRESSING="$(oc get co --no-headers 2>/dev/null | awk '$5=="True" {print $1}' | tr '\n' ' ' || true)"

if [[ -n "$NOT_AVAILABLE" ]]; then
  fail "Some ClusterOperators are not Available: $NOT_AVAILABLE"
else
  ok "All ClusterOperators are Available"
fi

if [[ -n "$DEGRADED" ]]; then
  fail "Some ClusterOperators are Degraded: $DEGRADED"
else
  ok "No degraded ClusterOperators"
fi

if [[ -n "$PROGRESSING" ]]; then
  warn "Some ClusterOperators are Progressing: $PROGRESSING"
else
  ok "No progressing ClusterOperators"
fi

section "Node Pressure and Readiness"

NOT_READY="$(oc get nodes --no-headers 2>/dev/null | awk '$2!="Ready" {print $1}' | tr '\n' ' ' || true)"
if [[ -n "$NOT_READY" ]]; then
  fail "Some nodes are not Ready: $NOT_READY"
else
  ok "All nodes are Ready"
fi

if jq -e '.items[] | select(.status.conditions[] | select(.type=="DiskPressure" and .status=="True"))' "$OUT_DIR/nodes.json" >/dev/null; then
  fail "At least one node has DiskPressure"
else
  ok "No node DiskPressure"
fi

if jq -e '.items[] | select(.status.conditions[] | select(.type=="MemoryPressure" and .status=="True"))' "$OUT_DIR/nodes.json" >/dev/null; then
  fail "At least one node has MemoryPressure"
else
  ok "No node MemoryPressure"
fi

if jq -e '.items[] | select(.status.conditions[] | select(.type=="PIDPressure" and .status=="True"))' "$OUT_DIR/nodes.json" >/dev/null; then
  fail "At least one node has PIDPressure"
else
  ok "No node PIDPressure"
fi

section "Recent Problem Pods"

oc get pods -A > "$OUT_DIR/pods-all.txt" 2>/dev/null || true

BAD_PODS="$(oc get pods -A --no-headers 2>/dev/null | awk '$4 ~ /Error|Evicted|CrashLoopBackOff|ImagePullBackOff|ContainerStatusUnknown|CreateContainerConfigError|Pending/ {print $1"/"$2":"$4}' | head -20 | tr '\n' ' ' || true)"

if [[ -n "$BAD_PODS" ]]; then
  warn "Some pods are unhealthy or pending. Review $OUT_DIR/pods-all.txt"
  echo "$BAD_PODS" > "$OUT_DIR/problem-pods.txt"
else
  ok "No obvious failed/pending pods detected"
fi

section "OLM and OperatorHub"

if oc get ns openshift-marketplace >/dev/null 2>&1; then
  ok "openshift-marketplace namespace exists"
else
  fail "openshift-marketplace namespace missing"
fi

if oc get catalogsource redhat-operators -n openshift-marketplace >/dev/null 2>&1; then
  ok "redhat-operators CatalogSource exists"
else
  fail "redhat-operators CatalogSource missing"
fi

CATALOG_READY="$(oc get catalogsource redhat-operators -n openshift-marketplace -o jsonpath='{.status.connectionState.lastObservedState}' 2>/dev/null || true)"
if [[ "$CATALOG_READY" == "READY" ]]; then
  ok "redhat-operators CatalogSource is READY"
else
  warn "redhat-operators CatalogSource state: ${CATALOG_READY:-unknown}"
fi

if oc get packagemanifest compliance-operator -n openshift-marketplace >/dev/null 2>&1; then
  ok "Compliance Operator PackageManifest is visible"
else
  fail "Compliance Operator PackageManifest not visible"
fi

oc get packagemanifest compliance-operator -n openshift-marketplace -o yaml > "$OUT_DIR/compliance-operator-packagemanifest.yaml" 2>/dev/null || true

section "Storage and Metrics"

if oc adm top node >/dev/null 2>&1; then
  ok "Metrics API is available"
  oc adm top node > "$OUT_DIR/top-node.txt" 2>/dev/null || true
else
  warn "Metrics API not available; live CPU/memory usage check skipped"
fi

PVCS_PENDING="$(oc get pvc -A --no-headers 2>/dev/null | awk '$3=="Pending" {print $1"/"$2}' | tr '\n' ' ' || true)"
if [[ -n "$PVCS_PENDING" ]]; then
  warn "Some PVCs are Pending: $PVCS_PENDING"
else
  ok "No pending PVCs detected"
fi

section "Existing Compliance Operator Footprint"

oc get subscription -A | grep -i compliance > "$OUT_DIR/existing-compliance-subscriptions.txt" 2>/dev/null || true
oc get csv -A | grep -i compliance > "$OUT_DIR/existing-compliance-csvs.txt" 2>/dev/null || true
oc get ns | grep -i compliance > "$OUT_DIR/existing-compliance-namespaces.txt" 2>/dev/null || true

if [[ -s "$OUT_DIR/existing-compliance-subscriptions.txt" || -s "$OUT_DIR/existing-compliance-csvs.txt" ]]; then
  warn "Existing Compliance Operator resources found. Review $OUT_DIR/existing-compliance-*.txt"
else
  ok "No existing Compliance Operator subscription/CSV detected"
fi

section "Result"

cat > "$REPORT" <<EOF
# OpenShift CIS Prerequisite Check

Generated: $(date)

| Item | Value |
|---|---|
| Cluster | \`${CLUSTER:-unknown}\` |
| User | \`${USER:-unknown}\` |
| OpenShift version | \`${OCP_VERSION:-unknown}\` |
| Output directory | \`$OUT_DIR\` |

## Summary

| Status | Count |
|---|---:|
| PASS | $PASS |
| WARN | $WARN |
| FAIL | $FAIL |

## Decision

EOF

if [[ "$FAIL" -eq 0 ]]; then
  ok "Prerequisite check passed"
  echo "✅ Prerequisite check PASSED. You can run the CIS scan script." >> "$REPORT"
else
  fail "Prerequisite check failed"
  echo "❌ Prerequisite check FAILED. Fix failed checks before running the CIS scan script." >> "$REPORT"
fi

cat >> "$REPORT" <<EOF

## Important Files

- \`clusteroperators.txt\`
- \`nodes.txt\`
- \`pods-all.txt\`
- \`problem-pods.txt\`
- \`existing-compliance-subscriptions.txt\`
- \`existing-compliance-csvs.txt\`
- \`compliance-operator-packagemanifest.yaml\`

EOF

echo
echo "Report: $REPORT"
echo "Output: $OUT_DIR"

if [[ "$FAIL" -eq 0 ]]; then
  exit 0
else
  exit 1
fi