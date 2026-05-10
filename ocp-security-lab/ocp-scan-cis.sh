#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-compliance-cis-$(date +%Y%m%d-%H%M%S)}"
SCAN_NAME="${SCAN_NAME:-cis-scan-$(date +%Y%m%d-%H%M%S)}"
CHANNEL="${CHANNEL:-stable}"
INSTALL_APPROVAL="${INSTALL_APPROVAL:-Manual}"
OUT_DIR="${OUT_DIR:-cis-results-$(date +%Y%m%d-%H%M%S)}"

GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"
BLUE="\033[0;34m"; BOLD="\033[1m"; NC="\033[0m"

PLATFORM_PROFILE=""
NODE_PROFILE=""

mkdir -p "$OUT_DIR"/{debug,manifests,categories}

section(){ echo -e "\n${BLUE}${BOLD}== $1 ==${NC}"; }
ok(){ echo -e "${GREEN}[OK]${NC} $1"; }
warn(){ echo -e "${YELLOW}[INFO]${NC} $1"; }
risk(){ echo -e "${RED}[ERROR]${NC} $1"; }

ask_yes_no() {
  local prompt="$1" default="${2:-Y}" answer
  if [[ "$default" == "Y" ]]; then
    read -r -p "$prompt [Y/n]: " answer
    answer="${answer:-Y}"
  else
    read -r -p "$prompt [y/N]: " answer
    answer="${answer:-N}"
  fi

  case "$answer" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

capture() {
  local cmd="$1" file="$2"
  bash -c "$cmd" > "$file" 2>&1 || true
}

header() {
  clear 2>/dev/null || true
  echo -e "${BLUE}${BOLD}"
  echo "  ____ ___ ____     ____                  "
  echo " / ___|_ _/ ___|   / ___|  ___ __ _ _ __ "
  echo "| |    | |\\___ \\   \\___ \\ / __/ _\` | '_ \\"
  echo "| |___ | | ___) |   ___) | (_| (_| | | | |"
  echo " \\____|___|____/   |____/ \\___\\__,_|_| |_|"
  echo -e "${NC}"
  echo "Safe OpenShift CIS Compliance Scan Runner"
}

require_tools() {
  section "Preflight"

  command -v oc >/dev/null || { risk "oc not found"; exit 1; }
  command -v jq >/dev/null || { risk "jq not found"; exit 1; }

  oc whoami >/dev/null 2>&1 || {
    risk "oc login required"
    exit 1
  }

  if ! oc auth can-i '*' '*' >/dev/null 2>&1; then
    risk "cluster-admin permission required"
    exit 1
  fi

  echo "Cluster: $(oc whoami --show-server)"
  echo "User:    $(oc whoami)"
  oc get clusterversion version -o jsonpath='Version: {.status.desired.version}{"\n"}' 2>/dev/null || true
  echo "Output:  $OUT_DIR"

  capture "oc get nodes -o wide" "$OUT_DIR/debug/nodes.txt"
  capture "oc get co" "$OUT_DIR/debug/clusteroperators.txt"
  capture "oc get subscription -A" "$OUT_DIR/debug/subscriptions-all.txt"
  capture "oc get csv -A" "$OUT_DIR/debug/csvs-all.txt"
  capture "oc get installplan -A" "$OUT_DIR/debug/installplans-all.txt"

  ok "Preflight complete"
}

create_namespace() {
  section "Namespace"

  if oc get ns "$NS" >/dev/null 2>&1; then
    risk "Namespace already exists unexpectedly: $NS"
    exit 1
  fi

  oc create ns "$NS" >/dev/null
  ok "Created fresh namespace: $NS"
  echo "Namespace: $NS" > "$OUT_DIR/namespace.txt"
}

ensure_operatorgroup() {
  cat > "$OUT_DIR/manifests/operatorgroup.yaml" <<EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: compliance-operator
  namespace: $NS
spec:
  targetNamespaces:
  - $NS
EOF

  oc apply -f "$OUT_DIR/manifests/operatorgroup.yaml" >/dev/null
  ok "OperatorGroup created"
}

ensure_subscription() {
  cat > "$OUT_DIR/manifests/subscription.yaml" <<EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: compliance-operator
  namespace: $NS
spec:
  channel: $CHANNEL
  name: compliance-operator
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  installPlanApproval: $INSTALL_APPROVAL
EOF

  oc apply -f "$OUT_DIR/manifests/subscription.yaml" >/dev/null
  ok "Subscription created"
}

approve_installplan_if_needed() {
  [[ "$INSTALL_APPROVAL" == "Manual" ]] || return 0

  section "InstallPlan"

  for i in {1..60}; do
    ip="$(oc get installplan -n "$NS" -o json 2>/dev/null \
      | jq -r '.items[] | select(.spec.approved==false) | .metadata.name' \
      | head -1 || true)"

    if [[ -n "$ip" ]]; then
      oc describe installplan "$ip" -n "$NS" > "$OUT_DIR/debug/installplan-$ip.describe.txt" 2>&1 || true
      warn "InstallPlan requires approval: $ip"
      warn "Details saved: $OUT_DIR/debug/installplan-$ip.describe.txt"

      ask_yes_no "Approve InstallPlan $ip?" "Y" || exit 1
      oc patch installplan "$ip" -n "$NS" --type merge -p '{"spec":{"approved":true}}' >/dev/null
      ok "InstallPlan approved"
      return
    fi

    echo -ne "Waiting for InstallPlan... ${i}/60\r"
    sleep 5
  done

  echo
  risk "InstallPlan was not created"
  exit 1
}

install_operator() {
  section "Compliance Operator"
  ensure_operatorgroup
  ensure_subscription
  approve_installplan_if_needed
}

export_debug() {
  local reason="$1"

  capture "oc get all -n $NS -o wide" "$OUT_DIR/debug/ns-all.txt"
  capture "oc get subscription,csv,installplan,operatorgroup -n $NS -o yaml" "$OUT_DIR/debug/olm.yaml"
  capture "oc get scansetting,scansettingbinding,compliancesuite,compliancescan,profilebundle,profile,compliancecheckresult,complianceremediation -n $NS -o yaml" "$OUT_DIR/debug/compliance-resources.yaml"
  capture "oc get events -n $NS --sort-by=.lastTimestamp" "$OUT_DIR/debug/events.txt"
  capture "oc get pods -n $NS -o wide" "$OUT_DIR/debug/pods.txt"

  risk "$reason. Debug saved under: $OUT_DIR/debug"
}

wait_for_operator() {
  section "Operator Readiness"

  local last=""
  local phase=""

  for i in {1..90}; do
    csv="$(oc get csv -n "$NS" --no-headers 2>/dev/null | awk '/compliance-operator/ {print $1; exit}')"

    if [[ -z "$csv" ]]; then
      line="CSV not created yet"
    else
      phase="$(oc get csv "$csv" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      reason="$(oc get csv "$csv" -n "$NS" -o jsonpath='{.status.reason}' 2>/dev/null || true)"
      line="$csv: ${phase:-unknown} ${reason:-}"
    fi

    if [[ "$line" != "$last" ]]; then
      echo "$line"
      last="$line"
    fi

    if [[ "$phase" == "Succeeded" ]]; then
      ok "Operator ready"
      return
    fi

    sleep 10
  done

  export_debug "Operator did not become ready"
  exit 1
}

wait_for_defaults() {
  section "Compliance Objects"

  local last_count=0
  local stable_count=0

  for i in {1..120}; do
    profiles="$(oc get profiles.compliance -n "$NS" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
    settings="$(oc get scansettings.compliance -n "$NS" --no-headers 2>/dev/null | wc -l | tr -d ' ')"

    echo -ne "Waiting for profiles... profiles=$profiles settings=$settings\r"

    if [[ "$profiles" -eq "$last_count" && "$profiles" -gt 10 ]] && oc get scansetting default -n "$NS" >/dev/null 2>&1; then
      stable_count=$((stable_count + 1))
    else
      stable_count=0
    fi

    if [[ "$stable_count" -ge 3 ]]; then
      echo
      ok "Profiles ready: $profiles profiles"
      return
    fi

    last_count="$profiles"
    sleep 10
  done

  echo
  export_debug "Profiles not ready"
  exit 1
}

select_profiles() {
  section "Profile Selection"

  oc get profiles.compliance -n "$NS" --no-headers \
    | awk '{print $1}' \
    | sort > "$OUT_DIR/debug/profiles.txt"

  echo "Available profiles:"
  nl -w2 -s") " "$OUT_DIR/debug/profiles.txt"
  echo

  echo "Recommended latest CIS:"
  echo "  Platform: ocp4-cis"
  echo "  Node:     ocp4-cis-node"
  echo

  read -r -p "Platform profile number [ocp4-cis]: " pnum
  if [[ -z "$pnum" ]]; then
    PLATFORM_PROFILE="ocp4-cis"
  else
    PLATFORM_PROFILE="$(sed -n "${pnum}p" "$OUT_DIR/debug/profiles.txt")"
  fi

  read -r -p "Node profile number [ocp4-cis-node]: " nnum
  if [[ -z "$nnum" ]]; then
    NODE_PROFILE="ocp4-cis-node"
  else
    NODE_PROFILE="$(sed -n "${nnum}p" "$OUT_DIR/debug/profiles.txt")"
  fi

  [[ -n "$PLATFORM_PROFILE" ]] || { risk "Invalid platform profile selection"; exit 1; }
  [[ -n "$NODE_PROFILE" ]] || { risk "Invalid node profile selection"; exit 1; }

  if ! oc get profile.compliance "$PLATFORM_PROFILE" -n "$NS" >/dev/null 2>&1; then
    risk "Platform profile not found: $PLATFORM_PROFILE"
    exit 1
  fi

  if ! oc get profile.compliance "$NODE_PROFILE" -n "$NS" >/dev/null 2>&1; then
    risk "Node profile not found: $NODE_PROFILE"
    exit 1
  fi

  echo
  ok "Selected:"
  echo "  Platform: $PLATFORM_PROFILE"
  echo "  Node:     $NODE_PROFILE"
}

check_cluster_resources() {
  section "Cluster Resource Check"

  local bad="false"

  if oc get nodes -o json | jq -e '.items[] | select(.status.conditions[] | select(.type=="DiskPressure" and .status=="True"))' >/dev/null; then
    risk "Node DiskPressure detected"
    bad="true"
  fi

  if oc get nodes -o json | jq -e '.items[] | select(.status.conditions[] | select(.type=="MemoryPressure" and .status=="True"))' >/dev/null; then
    risk "Node MemoryPressure detected"
    bad="true"
  fi

  if oc get nodes -o json | jq -e '.items[] | select(.status.conditions[] | select(.type=="PIDPressure" and .status=="True"))' >/dev/null; then
    risk "Node PIDPressure detected"
    bad="true"
  fi

  if [[ "$bad" == "true" ]]; then
    echo
    echo "Cluster is not healthy enough for a reliable CIS scan."
    echo "Debug hints:"
    echo "  oc describe node"
    echo "  oc get pods -A | grep -E 'Evicted|Error|CrashLoopBackOff|ImagePullBackOff|Pending'"
    echo "  oc get events -A --sort-by=.lastTimestamp | tail -100"
    exit 1
  fi

  ok "No node pressure detected"
}

create_scan() {
  section "Start Scan"

  cat > "$OUT_DIR/manifests/scansettingbinding.yaml" <<EOF
apiVersion: compliance.openshift.io/v1alpha1
kind: ScanSettingBinding
metadata:
  name: $SCAN_NAME
  namespace: $NS
profiles:
- name: $PLATFORM_PROFILE
  kind: Profile
  apiGroup: compliance.openshift.io/v1alpha1
- name: $NODE_PROFILE
  kind: Profile
  apiGroup: compliance.openshift.io/v1alpha1
settingsRef:
  name: default
  kind: ScanSetting
  apiGroup: compliance.openshift.io/v1alpha1
EOF

  echo "Namespace: $NS"
  echo "Scan:      $SCAN_NAME"
  echo "Profiles:  $PLATFORM_PROFILE + $NODE_PROFILE"
  echo

  ask_yes_no "Start scan?" "Y" || exit 0

  oc apply -f "$OUT_DIR/manifests/scansettingbinding.yaml" >/dev/null
  ok "Scan started"
}

wait_for_scan() {
  section "Scan Progress"

  local start_ts now_ts elapsed_min status_key last_status_key heartbeat
  start_ts="$(date +%s)"
  last_status_key=""
  heartbeat=0

  echo "Waiting for scan completion."
  echo "Status changes are printed immediately; heartbeat prints every 5 minutes."
  echo

  for i in {1..240}; do
    now_ts="$(date +%s)"
    elapsed_min="$(( (now_ts - start_ts) / 60 ))"

    suite_phase="$(oc get compliancesuite "$SCAN_NAME" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    suite_result="$(oc get compliancesuite "$SCAN_NAME" -n "$NS" -o jsonpath='{.status.result}' 2>/dev/null || true)"

    scan_summary="$(
      oc get compliancescan -n "$NS" --no-headers 2>/dev/null \
        | awk '{print $1":"$2"/"$3}' \
        | tr '\n' ' ' \
        || true
    )"

    bad_pods="$(
      oc get pods -n "$NS" --no-headers 2>/dev/null \
        | awk '$3 ~ /Error|Evicted|CrashLoopBackOff|ImagePullBackOff|ContainerStatusUnknown/ {print $1":"$3}' \
        | tr '\n' ' ' \
        || true
    )"

    if [[ -n "$bad_pods" ]]; then
      echo "elapsed=${elapsed_min}m failed-pods=$bad_pods"
      export_debug "Scan pods failed"
      return 1
    fi

    status_key="suite=${suite_phase:-waiting}/${suite_result:-unknown} scans=${scan_summary:-not-created-yet}"

    if [[ "$status_key" != "$last_status_key" ]]; then
      echo "elapsed=${elapsed_min}m $status_key"
      last_status_key="$status_key"
    elif (( elapsed_min >= heartbeat + 5 )); then
      echo "elapsed=${elapsed_min}m still running..."
      heartbeat="$elapsed_min"
    fi

    case "$suite_phase" in
      DONE|Done)
        ok "Scan completed after ${elapsed_min}m: ${suite_result:-unknown}"
        return 0
        ;;
      ERROR|Error)
        export_debug "Scan ended with error after ${elapsed_min}m"
        return 1
        ;;
    esac

    sleep 30
  done

  export_debug "Scan timeout"
  return 1
}

export_results() {
  section "Results"

  oc get compliancesuite -n "$NS" -o yaml > "$OUT_DIR/compliancesuites.yaml" 2>/dev/null || true
  oc get compliancescan -n "$NS" -o yaml > "$OUT_DIR/compliancescans.yaml" 2>/dev/null || true
  oc get compliancecheckresult -n "$NS" > "$OUT_DIR/checkresults-all.txt" 2>/dev/null || true
  oc get compliancecheckresult -n "$NS" -o yaml > "$OUT_DIR/checkresults-all.yaml" 2>/dev/null || true
  oc get complianceremediation -n "$NS" > "$OUT_DIR/remediations-all.txt" 2>/dev/null || true
  oc get complianceremediation -n "$NS" -o yaml > "$OUT_DIR/remediations-all.yaml" 2>/dev/null || true

  grep -E "^$PLATFORM_PROFILE|^$NODE_PROFILE|^NAME" "$OUT_DIR/checkresults-all.txt" > "$OUT_DIR/checkresults-selected.txt" || true
  grep -E "^$PLATFORM_PROFILE|^$NODE_PROFILE|^NAME" "$OUT_DIR/remediations-all.txt" > "$OUT_DIR/remediations-selected.txt" || true

  grep -E 'FAIL|ERROR' "$OUT_DIR/checkresults-selected.txt" > "$OUT_DIR/categories/failed.txt" || true
  grep -E 'PASS' "$OUT_DIR/checkresults-selected.txt" > "$OUT_DIR/categories/passed.txt" || true
  grep -E 'MANUAL' "$OUT_DIR/checkresults-selected.txt" > "$OUT_DIR/categories/manual.txt" || true
  cp "$OUT_DIR/remediations-selected.txt" "$OUT_DIR/categories/remediations.txt" 2>/dev/null || true

  fail="$(wc -l < "$OUT_DIR/categories/failed.txt" | tr -d ' ')"
  pass="$(wc -l < "$OUT_DIR/categories/passed.txt" | tr -d ' ')"
  manual="$(wc -l < "$OUT_DIR/categories/manual.txt" | tr -d ' ')"
  rem="$(grep -v '^NAME' "$OUT_DIR/categories/remediations.txt" 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')"

  cat > "$OUT_DIR/summary.md" <<EOF
# OpenShift CIS Compliance Scan Summary

Generated: $(date)

| Item | Value |
|---|---|
| Cluster | \`$(oc whoami --show-server)\` |
| User | \`$(oc whoami)\` |
| Namespace | \`$NS\` |
| Scan | \`$SCAN_NAME\` |
| Platform profile | \`$PLATFORM_PROFILE\` |
| Node profile | \`$NODE_PROFILE\` |

## Results

| Category | Count |
|---|---:|
| PASS | $pass |
| FAIL/ERROR | $fail |
| MANUAL | $manual |
| Remediations generated | $rem |

## Safety

No remediations were applied automatically.
EOF

  echo "PASS:          $pass"
  echo "FAIL/ERROR:    $fail"
  echo "MANUAL:        $manual"
  echo "Remediations:  $rem"
  echo
  ok "Results saved to: $OUT_DIR"
  echo "Namespace: $NS"
  echo "Summary:   cat $OUT_DIR/summary.md"
}

main() {
  header
  require_tools

  echo
  warn "This script creates a fresh namespace, installs/configures missing Compliance Operator pieces, and runs a CIS scan."
  warn "It does not apply remediations."
  ask_yes_no "Continue?" "Y" || exit 0

  create_namespace
  install_operator
  wait_for_operator
  wait_for_defaults
  select_profiles
  check_cluster_resources
  create_scan
  wait_for_scan || true
  export_results
}

main "$@"