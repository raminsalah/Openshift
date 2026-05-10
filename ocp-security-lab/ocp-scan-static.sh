#!/usr/bin/env bash
set -euo pipefail

TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${1:-ocp-security-review-$TS}"
BASE="$OUT_DIR/baseline"
FIND="$OUT_DIR/findings"
REPORT="$OUT_DIR/security-findings.md"
FINDINGS_CSV="$FIND/security-findings.csv"
FINDINGS_JSONL="$FIND/security-findings.jsonl"
SUMMARY_JSON="$OUT_DIR/summary.json"

EXCLUDE_NS_REGEX='^(openshift|openshift-.*|kube-.*|default|hostpath-provisioner)$'

mkdir -p "$BASE" "$FIND"

GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; BLUE="\033[0;34m"; NC="\033[0m"

section(){ echo -e "\n${BLUE}============================================================${NC}\n${BLUE}$1${NC}\n${BLUE}============================================================${NC}"; }
ok(){ echo -e "${GREEN}[OK]${NC} $1"; }
warn(){ echo -e "${YELLOW}[REVIEW]${NC} $1"; }
risk(){ echo -e "${RED}[RISK]${NC} $1"; }

require_tools() {
  command -v oc >/dev/null || { echo "ERROR: oc not found"; exit 1; }
  command -v jq >/dev/null || { echo "ERROR: jq not found"; exit 1; }
  oc whoami >/dev/null || { echo "ERROR: oc login required"; exit 1; }
}

run_capture() {
  local desc="$1" cmd="$2" outfile="$3"
  echo "  -> $desc"
  if bash -c "$cmd" > "$outfile" 2>&1; then ok "$desc collected"; else warn "$desc failed; see $outfile"; fi
}

csv_escape() {
  local s="${1:-}"
  s="${s//$'\n'/ }"; s="${s//$'\r'/ }"; s="${s//\"/\"\"}"
  printf '%s' "$s"
}

add_finding() {
  local finding="$1" severity="$2" namespace="$3" name="$4" details="$5" recommendation="$6"

  printf '"%s","%s","%s","%s","%s","%s"\n' \
    "$(csv_escape "$finding")" "$(csv_escape "$severity")" "$(csv_escape "$namespace")" \
    "$(csv_escape "$name")" "$(csv_escape "$details")" "$(csv_escape "$recommendation")" \
    >> "$FINDINGS_CSV"

  jq -cn \
    --arg finding "$finding" \
    --arg severity "$severity" \
    --arg namespace "$namespace" \
    --arg name "$name" \
    --arg details "$details" \
    --arg recommendation "$recommendation" \
    '{finding:$finding,severity:$severity,namespace:$namespace,name:$name,details:$details,recommendation:$recommendation}' \
    >> "$FINDINGS_JSONL"
}

write_app_namespaces() {
  jq -r --arg re "$EXCLUDE_NS_REGEX" '
    .items[].metadata.name
    | select((test($re)) | not)
  ' "$BASE/namespaces.json" | sort -u > "$BASE/app-namespaces.txt"
}

section "OpenShift Security Review - Static Security Checks"
require_tools

CLUSTER="$(oc whoami --show-server)"
USER="$(oc whoami)"
CONTEXT="$(oc config current-context 2>/dev/null || true)"

cat > "$FINDINGS_CSV" <<EOF
finding,severity,namespace,name,details,recommendation
EOF
: > "$FINDINGS_JSONL"

section "Phase 1: Baseline Collection"

echo "Output directory: $OUT_DIR"
echo "User: $USER"
echo "Cluster: $CLUSTER"
echo "Context: ${CONTEXT:-unknown}"

run_capture "Version" "oc version" "$BASE/version.txt"
run_capture "ClusterVersion JSON" "oc get clusterversion -o json" "$BASE/clusterversion.json"
run_capture "ClusterVersion YAML" "oc get clusterversion -o yaml" "$BASE/clusterversion.yaml"
run_capture "Infrastructure JSON" "oc get infrastructure cluster -o json" "$BASE/infrastructure.json"
run_capture "Nodes JSON" "oc get nodes -o json" "$BASE/nodes.json"
run_capture "Nodes wide" "oc get nodes -o wide" "$BASE/nodes-wide.txt"
run_capture "ClusterOperators" "oc get clusteroperators" "$BASE/clusteroperators.txt"
run_capture "Namespaces JSON" "oc get ns -o json" "$BASE/namespaces.json"
run_capture "Projects" "oc get projects" "$BASE/projects.txt"
run_capture "Pods JSON" "oc get pods -A -o json" "$BASE/pods.json"
run_capture "Deployments JSON" "oc get deploy -A -o json" "$BASE/deployments.json"
run_capture "ClusterRoles JSON" "oc get clusterroles -o json" "$BASE/clusterroles.json"
run_capture "ClusterRoleBindings JSON" "oc get clusterrolebindings -o json" "$BASE/clusterrolebindings.json"
run_capture "Roles JSON" "oc get roles -A -o json" "$BASE/roles.json"
run_capture "RoleBindings JSON" "oc get rolebindings -A -o json" "$BASE/rolebindings.json"
run_capture "SCC JSON" "oc get scc -o json" "$BASE/scc.json"
run_capture "ServiceAccounts JSON" "oc get serviceaccounts -A -o json" "$BASE/serviceaccounts.json"
run_capture "NetworkPolicies JSON" "oc get netpol -A -o json" "$BASE/networkpolicies.json"
run_capture "Routes JSON" "oc get routes -A -o json" "$BASE/routes.json"
run_capture "APIServer JSON" "oc get apiserver cluster -o json" "$BASE/apiserver.json"
run_capture "APIServer YAML" "oc get apiserver cluster -o yaml" "$BASE/apiserver.yaml"
run_capture "OAuth JSON" "oc get oauth cluster -o json" "$BASE/oauth.json"
run_capture "Image Config JSON" "oc get image.config.openshift.io cluster -o json" "$BASE/image-config.json"
run_capture "Secrets list only" "oc get secrets -A" "$BASE/secrets-list.txt"

write_app_namespaces
APP_NS_JSON="$(jq -R -s 'split("\n") | map(select(length>0))' "$BASE/app-namespaces.txt")"
ok "Application namespaces written to $BASE/app-namespaces.txt"

section "Phase 2: Security Resource Review"

# kubeadmin
KUBEADMIN_BINDINGS="$(jq -r '
.items[]
| select(.roleRef.name=="cluster-admin")
| .subjects[]?
| select(.kind=="User" and .name=="kubeadmin")
| .name
' "$BASE/clusterrolebindings.json" | wc -l | tr -d ' ')"

if [[ "$KUBEADMIN_BINDINGS" -gt 0 ]]; then
  add_finding \
    "kubeadmin has cluster-admin" \
    "HIGH_IN_PRODUCTION" \
    "cluster" \
    "kubeadmin" \
    "The kubeadmin bootstrap user is bound to cluster-admin." \
    "In production, configure an identity provider, assign named admin users/groups, and remove kubeadmin."
fi

# Non-system cluster-admin subjects
jq -r '
.items[]
| select(.roleRef.name=="cluster-admin")
| .metadata.name as $binding
| .subjects[]?
| select(
    ((.name | startswith("system:")) | not)
    and (((.namespace // "") | startswith("openshift-")) | not)
    and (.name != "kubeadmin")
  )
| [$binding,.kind,.name,(.namespace // "")]
| @tsv
' "$BASE/clusterrolebindings.json" > "$FIND/non-system-cluster-admin.tsv"

while IFS=$'\t' read -r binding kind name ns; do
  [[ -z "${name:-}" ]] && continue
  add_finding \
    "Non-system subject has cluster-admin" \
    "HIGH" \
    "${ns:-cluster}" \
    "$name" \
    "$kind $name is bound to cluster-admin through $binding." \
    "Remove cluster-admin unless explicitly required. Replace with least-privilege roles."
done < "$FIND/non-system-cluster-admin.tsv"

# ClusterRole wildcard permissions, suppressing known platform/generated roles
jq -r '
.items[]
| .metadata.name as $role
| select(($role | startswith("system:")) | not)
| select(($role | startswith("openshift-")) | not)
| select(($role | startswith("cluster-")) | not)
| select(($role | startswith("machine-")) | not)
| select(($role | startswith("olm.")) | not)
| select(($role | startswith("multus")) | not)
| select($role != "packagemanifests-v1-admin")
| select(($role | startswith("compliance-operator.")) | not)
| select(($role | test("^.*\\.compliance\\.openshift\\.io-v1alpha1-.*$")) | not)
| select(($role | test("^(admin|edit|view|cluster-admin|cluster-reader)$")) | not)
| .rules[]?
| select(((.verbs // []) | index("*")) or ((.resources // []) | index("*")) or ((.apiGroups // []) | index("*")))
| [$role, ((.apiGroups // []) | join(";")), ((.resources // []) | join(";")), ((.verbs // []) | join(";"))]
| @tsv
' "$BASE/clusterroles.json" > "$FIND/clusterrole-wildcards.tsv"

while IFS=$'\t' read -r role apigroups resources verbs; do
  [[ -z "${role:-}" ]] && continue
  add_finding \
    "ClusterRole uses wildcard permissions" \
    "HIGH" \
    "cluster" \
    "$role" \
    "Non-platform ClusterRole has wildcard permissions. apiGroups=[$apigroups], resources=[$resources], verbs=[$verbs]." \
    "Replace wildcard permissions with explicit least-privilege rules."
done < "$FIND/clusterrole-wildcards.tsv"

# Application Roles with wildcard permissions
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| select(($app_ns | index($ns)) != null)
| .metadata.name as $role
| .rules[]?
| select(((.verbs // []) | index("*")) or ((.resources // []) | index("*")) or ((.apiGroups // []) | index("*")))
| [$ns, $role, ((.apiGroups // []) | join(";")), ((.resources // []) | join(";")), ((.verbs // []) | join(";"))]
| @tsv
' "$BASE/roles.json" > "$FIND/app-role-wildcards.tsv"

while IFS=$'\t' read -r ns role apigroups resources verbs; do
  [[ -z "${role:-}" ]] && continue
  add_finding \
    "Role uses wildcard permissions" \
    "HIGH" \
    "$ns" \
    "$role" \
    "Application Role has wildcard permissions. apiGroups=[$apigroups], resources=[$resources], verbs=[$verbs]." \
    "Replace wildcard permissions with explicit least-privilege rules."
done < "$FIND/app-role-wildcards.tsv"

# Broad ClusterRoleBindings only when role is powerful/sensitive
jq -r '
.items[]
| .metadata.name as $binding
| .roleRef.kind as $roleKind
| .roleRef.name as $roleName
| .subjects[]?
| select(((.namespace // "") | startswith("openshift-")) | not)
| select(.name=="system:authenticated" or .name=="system:unauthenticated" or .name=="system:anonymous")
| select($binding != "system:oauth-token-deleters")
| select($binding != "system:scope-impersonation")
| select(
    ($roleName=="cluster-admin")
    or ($roleName=="admin")
    or ($roleName=="edit")
    or ($roleName | test("privileged|impersonat|secret|token|oauth"; "i"))
  )
| [$binding,$roleKind,$roleName,.kind,.name]
| @tsv
' "$BASE/clusterrolebindings.json" > "$FIND/broad-clusterrolebindings.tsv"

while IFS=$'\t' read -r binding rolekind rolename subjectkind subjectname; do
  [[ -z "${binding:-}" ]] && continue
  add_finding \
    "Broad system group has sensitive ClusterRoleBinding" \
    "HIGH" \
    "cluster" \
    "$binding" \
    "$subjectkind $subjectname is bound to $rolekind/$rolename." \
    "Avoid granting sensitive roles to broad groups such as system:authenticated, system:unauthenticated, or system:anonymous."
done < "$FIND/broad-clusterrolebindings.tsv"

# Container security checks
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| .metadata.name as $pod
| select(($app_ns | index($ns)) != null)
| select(($ns | startswith("openshift-")) | not)
| .spec.containers[]?
| . as $c
| [
    $ns,
    $pod,
    $c.name,
    ($c.image // ""),
    (
      if $c.securityContext.privileged == true then "privileged_container|CRITICAL|Container is privileged.|Remove privileged mode and use restricted SCC."
      elif $c.securityContext.allowPrivilegeEscalation == true then "allow_privilege_escalation|HIGH|Container allows privilege escalation.|Set allowPrivilegeEscalation=false and drop Linux capabilities."
      elif $c.securityContext.runAsUser == 0 then "runs_as_root_uid_0|HIGH|Container explicitly runs as UID 0.|Run as non-root and rely on OpenShift assigned UID ranges."
      elif (($c.securityContext.capabilities.add // []) | length) > 0 then "capabilities_added|HIGH|Container adds Linux capabilities: \((($c.securityContext.capabilities.add // []) | join(","))).|Remove added capabilities unless strictly required."
      elif (($c.securityContext.capabilities.drop // []) | index("ALL") | not) then "capabilities_not_dropping_all|MEDIUM|Container does not drop all Linux capabilities.|Set securityContext.capabilities.drop=[\"ALL\"]."
      elif (($c.securityContext.runAsNonRoot // false) != true) then "run_as_non_root_not_enforced|MEDIUM|Container does not explicitly enforce runAsNonRoot=true.|Set runAsNonRoot=true where compatible."
      elif (($c.securityContext.readOnlyRootFilesystem // false) != true) then "root_filesystem_not_read_only|MEDIUM|Container root filesystem is not explicitly read-only.|Set readOnlyRootFilesystem=true where compatible."
      elif (($c.securityContext.seccompProfile.type // "") == "") then "seccomp_profile_missing|MEDIUM|Container does not explicitly set a seccomp profile.|Use RuntimeDefault seccomp profile where possible."
      elif (($c.resources.limits // {}) | length == 0) then "resource_limits_missing|LOW|Container has no resource limits.|Define CPU and memory limits."
      elif ($c.image | test(":latest$")) then "image_latest_tag|MEDIUM|Container uses a mutable latest image tag.|Use immutable version tags or image digests."
      elif (($c.image | contains("@sha256:")) | not) then "image_digest_not_used|LOW|Container image is not pinned by digest.|For high-assurance workloads, pin images by digest."
      else empty end
    )
  ]
| select(.[4] != null)
| @tsv
' "$BASE/pods.json" > "$FIND/app-workload-risks.tsv"

while IFS=$'\t' read -r ns pod container image packed; do
  [[ -z "${packed:-}" ]] && continue
  IFS='|' read -r issue sev detail rec <<< "$packed"
  add_finding "$issue" "$sev" "$ns" "$pod/$container" "$detail Image: $image" "$rec"
done < "$FIND/app-workload-risks.tsv"

# Init container checks
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| .metadata.name as $pod
| select(($app_ns | index($ns)) != null)
| .spec.initContainers[]?
| . as $c
| [
    $ns,
    $pod,
    $c.name,
    ($c.image // ""),
    (
      if $c.securityContext.privileged == true then "privileged_init_container|CRITICAL|Init container is privileged.|Remove privileged mode and use restricted SCC."
      elif $c.securityContext.allowPrivilegeEscalation == true then "init_allow_privilege_escalation|HIGH|Init container allows privilege escalation.|Set allowPrivilegeEscalation=false."
      elif $c.securityContext.runAsUser == 0 then "init_runs_as_root_uid_0|HIGH|Init container explicitly runs as UID 0.|Run as non-root where possible."
      elif (($c.securityContext.capabilities.add // []) | length) > 0 then "init_capabilities_added|HIGH|Init container adds Linux capabilities: \((($c.securityContext.capabilities.add // []) | join(","))).|Remove added capabilities unless strictly required."
      elif ($c.image | test(":latest$")) then "init_image_latest_tag|MEDIUM|Init container uses a mutable latest image tag.|Use immutable version tags or image digests."
      else empty end
    )
  ]
| select(.[4] != null)
| @tsv
' "$BASE/pods.json" > "$FIND/app-initcontainer-risks.tsv"

while IFS=$'\t' read -r ns pod container image packed; do
  [[ -z "${packed:-}" ]] && continue
  IFS='|' read -r issue sev detail rec <<< "$packed"
  add_finding "$issue" "$sev" "$ns" "$pod/init:$container" "$detail Image: $image" "$rec"
done < "$FIND/app-initcontainer-risks.tsv"

# Secrets exposed through environment variables
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| .metadata.name as $pod
| select(($app_ns | index($ns)) != null)
| (
    (.spec.containers[]? | {kind:"container", name:.name, env:(.env // [])}),
    (.spec.initContainers[]? | {kind:"initContainer", name:.name, env:(.env // [])}),
    (.spec.ephemeralContainers[]? | {kind:"ephemeralContainer", name:.name, env:(.env // [])})
  )
| . as $c
| $c.env[]?
| select(.valueFrom.secretKeyRef? != null)
| [
    $ns,
    $pod,
    $c.kind,
    $c.name,
    (.name // ""),
    (.valueFrom.secretKeyRef.name // ""),
    (.valueFrom.secretKeyRef.key // "")
  ]
| @tsv
' "$BASE/pods.json" > "$FIND/secret-env-vars.tsv"

while IFS=$'\t' read -r ns pod ckind container envname secretname secretkey; do
  [[ -z "${pod:-}" ]] && continue
  add_finding \
    "secret_exposed_via_env_var" \
    "MEDIUM" \
    "$ns" \
    "$pod/$container" \
    "$ckind environment variable $envname is populated from Secret $secretname key $secretkey." \
    "Prefer mounting Secrets as read-only volumes or using an external secret manager instead of exposing Secrets as environment variables."
done < "$FIND/secret-env-vars.tsv"

# Pod-level securityContext checks
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| .metadata.name as $pod
| select(($app_ns | index($ns)) != null)
| [
    (if .spec.securityContext.runAsUser == 0 then "pod_runs_as_root_uid_0|HIGH|Pod-level securityContext sets runAsUser=0.|Remove pod-level root UID and use OpenShift assigned UID ranges." else empty end),
    (if .spec.securityContext.fsGroup == 0 then "pod_fsgroup_root|MEDIUM|Pod-level securityContext sets fsGroup=0.|Avoid root fsGroup unless strictly required." else empty end),
    (if ((.spec.securityContext.seccompProfile.type // "") == "") then "pod_seccomp_profile_missing|LOW|Pod does not explicitly set seccomp profile at pod level.|Use RuntimeDefault seccomp profile where possible." else empty end)
  ][]
| [$ns,$pod,.]
| @tsv
' "$BASE/pods.json" > "$FIND/app-pod-securitycontext-risks.tsv"

while IFS=$'\t' read -r ns pod packed; do
  [[ -z "${packed:-}" ]] && continue
  IFS='|' read -r issue sev detail rec <<< "$packed"
  add_finding "$issue" "$sev" "$ns" "$pod" "$detail" "$rec"
done < "$FIND/app-pod-securitycontext-risks.tsv"

# Host namespace and hostPath checks
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| .metadata.name as $pod
| select(($app_ns | index($ns)) != null)
| [
    (if .spec.hostNetwork == true then "hostNetwork|HIGH|Pod uses hostNetwork.|Remove hostNetwork unless strictly required." else empty end),
    (if .spec.hostPID == true then "hostPID|CRITICAL|Pod uses hostPID.|Remove hostPID; it exposes host process namespace." else empty end),
    (if .spec.hostIPC == true then "hostIPC|CRITICAL|Pod uses hostIPC.|Remove hostIPC; it exposes host IPC namespace." else empty end),
    (if ([.spec.volumes[]? | select(has("hostPath"))] | length) > 0 then "hostPath|CRITICAL|Pod uses hostPath volume.|Avoid hostPath; use PVC/CSI storage instead." else empty end)
  ][]
| [$ns,$pod,.]
| @tsv
' "$BASE/pods.json" > "$FIND/app-host-risks.tsv"

while IFS=$'\t' read -r ns pod packed; do
  [[ -z "${packed:-}" ]] && continue
  IFS='|' read -r issue sev detail rec <<< "$packed"
  add_finding "$issue" "$sev" "$ns" "$pod" "$detail" "$rec"
done < "$FIND/app-host-risks.tsv"

# ServiceAccount checks
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| .metadata.name as $pod
| select(($app_ns | index($ns)) != null)
| [
    (if ((.spec.serviceAccountName // "default") == "default") then "default_service_account_used|MEDIUM|Pod uses the default ServiceAccount.|Create a dedicated least-privilege ServiceAccount per workload." else empty end),
    (if (.spec.automountServiceAccountToken == true) then "service_account_token_automount_enabled|MEDIUM|Pod explicitly enables ServiceAccount token automount.|Disable automountServiceAccountToken unless Kubernetes API access is needed." else empty end)
  ][]
| [$ns,$pod,.]
| @tsv
' "$BASE/pods.json" > "$FIND/app-serviceaccount-risks.tsv"

while IFS=$'\t' read -r ns pod packed; do
  [[ -z "${packed:-}" ]] && continue
  IFS='|' read -r issue sev detail rec <<< "$packed"
  add_finding "$issue" "$sev" "$ns" "$pod" "$detail" "$rec"
done < "$FIND/app-serviceaccount-risks.tsv"

# Namespaces without NetworkPolicy
jq -r --argjson app_ns "$APP_NS_JSON" '
  $app_ns[] as $ns
  | select(([.items[]? | select(.metadata.namespace == $ns)] | length) == 0)
  | $ns
' "$BASE/networkpolicies.json" > "$FIND/app-ns-without-netpol.txt"

while read -r ns; do
  [[ -z "${ns:-}" ]] && continue
  add_finding \
    "Application namespace has no NetworkPolicy" \
    "MEDIUM" \
    "$ns" \
    "$ns" \
    "No NetworkPolicy exists in this application namespace." \
    "Apply default-deny ingress/egress and explicit allow policies."
done < "$FIND/app-ns-without-netpol.txt"

# Routes without TLS
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| select(($app_ns | index($ns)) != null)
| select((.spec.tls.termination // "") == "")
| [$ns,.metadata.name,(.spec.host // "")]
| @tsv
' "$BASE/routes.json" > "$FIND/app-routes-without-tls.tsv"

while IFS=$'\t' read -r ns route host; do
  [[ -z "${route:-}" ]] && continue
  add_finding \
    "Route without TLS" \
    "HIGH" \
    "$ns" \
    "$route" \
    "Route $host does not define TLS termination." \
    "Enable edge, re-encrypt, or passthrough TLS termination."
done < "$FIND/app-routes-without-tls.tsv"

# Routes allowing insecure traffic
jq -r --argjson app_ns "$APP_NS_JSON" '
.items[]
| .metadata.namespace as $ns
| select(($app_ns | index($ns)) != null)
| select((.spec.tls.insecureEdgeTerminationPolicy // "") == "Allow")
| [$ns,.metadata.name,(.spec.host // ""),(.spec.tls.termination // "")]
| @tsv
' "$BASE/routes.json" > "$FIND/app-routes-insecure-policy.tsv"

while IFS=$'\t' read -r ns route host termination; do
  [[ -z "${route:-}" ]] && continue
  add_finding \
    "Route allows insecure traffic" \
    "MEDIUM" \
    "$ns" \
    "$route" \
    "Route $host has TLS termination=$termination but insecureEdgeTerminationPolicy=Allow." \
    "Use Redirect or disable insecure traffic."
done < "$FIND/app-routes-insecure-policy.tsv"

# API encryption
ENCRYPTION_TYPE="$(jq -r '.spec.encryption.type // ""' "$BASE/apiserver.json" 2>/dev/null || true)"
if [[ "$ENCRYPTION_TYPE" != "aescbc" ]]; then
  add_finding \
    "API/etcd encryption not enabled" \
    "HIGH" \
    "cluster" \
    "apiserver/cluster" \
    "Detected encryption type: ${ENCRYPTION_TYPE:-EMPTY}." \
    "Enable APIServer encryption type aescbc for secrets and sensitive resources."
fi

# OAuth identity providers
IDP_COUNT="$(jq -r '(.spec.identityProviders // []) | length' "$BASE/oauth.json" 2>/dev/null || echo 0)"
if [[ "$IDP_COUNT" -eq 0 ]]; then
  add_finding \
    "No OAuth identity providers configured" \
    "HIGH_IN_PRODUCTION" \
    "cluster" \
    "oauth/cluster" \
    "No identityProviders are configured in oauth/cluster." \
    "Configure enterprise identity provider integration and avoid relying on bootstrap credentials."
fi

# Allowed registries
ALLOWED_REGISTRIES_COUNT="$(jq -r '(.spec.registrySources.allowedRegistries // []) | length' "$BASE/image-config.json" 2>/dev/null || echo 0)"
if [[ "$ALLOWED_REGISTRIES_COUNT" -eq 0 ]]; then
  add_finding \
    "No cluster allowedRegistries policy configured" \
    "LOW" \
    "cluster" \
    "image.config.openshift.io/cluster" \
    "No spec.registrySources.allowedRegistries entries are configured." \
    "Consider restricting image pulls to approved registries for production clusters."
fi

# Risky custom SCC definitions
jq -r '
.items[]
| .metadata.name as $scc
| select([
  "privileged",
  "hostaccess",
  "hostmount-anyuid",
  "hostmount-anyuid-v2",
  "hostnetwork",
  "hostnetwork-v2",
  "node-exporter",
  "nonroot",
  "nonroot-v2",
  "restricted",
  "restricted-v2",
  "restricted-v3",
  "anyuid",
  "anyuid-v2",
  "machine-api-termination-handler"
] | index($scc) | not)
| [
    (if .allowPrivilegedContainer == true then "scc_allows_privileged|HIGH|Custom SCC allows privileged containers." else empty end),
    (if .allowHostNetwork == true then "scc_allows_hostnetwork|HIGH|Custom SCC allows hostNetwork." else empty end),
    (if .allowHostPID == true then "scc_allows_hostpid|HIGH|Custom SCC allows hostPID." else empty end),
    (if .allowHostIPC == true then "scc_allows_hostipc|HIGH|Custom SCC allows hostIPC." else empty end),
    (if ((.volumes // []) | index("hostPath")) then "scc_allows_hostpath|HIGH|Custom SCC allows hostPath volumes." else empty end),
    (if ((.allowedCapabilities // []) | index("*")) then "scc_allows_any_capability|HIGH|Custom SCC allows any Linux capability." else empty end)
  ][]
| [$scc,.]
| @tsv
' "$BASE/scc.json" > "$FIND/scc-risk-settings.tsv"

while IFS=$'\t' read -r scc packed; do
  [[ -z "${scc:-}" ]] && continue
  IFS='|' read -r issue sev detail <<< "$packed"
  add_finding \
    "$issue" \
    "$sev" \
    "cluster" \
    "scc/$scc" \
    "$detail SCC: $scc." \
    "Review custom SCCs and remove host/privileged permissions unless strictly required."
done < "$FIND/scc-risk-settings.tsv"

# Sensitive SCC usage through rolebindings
jq -r '
.items[]
| .metadata.namespace as $ns
| select(($ns | startswith("openshift-")) | not)
| .metadata.name as $binding
| .roleRef.name as $role
| select($role | test("system:openshift:scc:(privileged|anyuid|hostmount-anyuid|hostnetwork|hostaccess)"))
| .subjects[]?
| [$ns,$binding,$role,.kind,.name,(.namespace // "")]
| @tsv
' "$BASE/rolebindings.json" > "$FIND/sensitive-scc-rolebindings.tsv"

while IFS=$'\t' read -r ns binding role kind name subject_ns; do
  [[ -z "${binding:-}" ]] && continue
  add_finding \
    "Sensitive SCC granted by RoleBinding" \
    "HIGH" \
    "$ns" \
    "$binding" \
    "$kind $name ${subject_ns:+in namespace $subject_ns }is granted $role." \
    "Review whether this subject really requires this SCC. Prefer restricted-v2/restricted-v3."
done < "$FIND/sensitive-scc-rolebindings.tsv"

jq -r '
.items[]
| .metadata.name as $binding
| .roleRef.name as $role
| select($role | test("system:openshift:scc:(privileged|anyuid|hostmount-anyuid|hostnetwork|hostaccess)"))
| .subjects[]?
| select(((.namespace // "") | startswith("openshift-")) | not)
| [$binding,$role,.kind,.name,(.namespace // "")]
| @tsv
' "$BASE/clusterrolebindings.json" > "$FIND/sensitive-scc-clusterrolebindings.tsv"

while IFS=$'\t' read -r binding role kind name subject_ns; do
  [[ -z "${binding:-}" ]] && continue
  add_finding \
    "Sensitive SCC granted by ClusterRoleBinding" \
    "HIGH" \
    "cluster" \
    "$binding" \
    "$kind $name ${subject_ns:+in namespace $subject_ns }is granted $role." \
    "Review whether this subject really requires this SCC. Prefer restricted-v2/restricted-v3."
done < "$FIND/sensitive-scc-clusterrolebindings.tsv"

section "Phase 3: Risk Summary"

TOTAL_FINDINGS="$(jq -s 'length' "$FINDINGS_JSONL")"
CRITICAL_COUNT="$(jq -s '[.[] | select(.severity|test("CRITICAL"))] | length' "$FINDINGS_JSONL")"
HIGH_COUNT="$(jq -s '[.[] | select(.severity|test("HIGH"))] | length' "$FINDINGS_JSONL")"
MEDIUM_COUNT="$(jq -s '[.[] | select(.severity|test("MEDIUM"))] | length' "$FINDINGS_JSONL")"
LOW_COUNT="$(jq -s '[.[] | select(.severity|test("LOW"))] | length' "$FINDINGS_JSONL")"

if [[ "$TOTAL_FINDINGS" -gt 0 ]]; then risk "$TOTAL_FINDINGS findings written to $FINDINGS_CSV"; else ok "No risky application/security findings detected"; fi
if [[ "$CRITICAL_COUNT" -gt 0 ]]; then risk "Critical findings: $CRITICAL_COUNT"; else ok "Critical findings: 0"; fi
if [[ "$HIGH_COUNT" -gt 0 ]]; then risk "High findings: $HIGH_COUNT"; else ok "High findings: 0"; fi
if [[ "$MEDIUM_COUNT" -gt 0 ]]; then warn "Medium findings: $MEDIUM_COUNT"; else ok "Medium findings: 0"; fi
if [[ "$LOW_COUNT" -gt 0 ]]; then warn "Low findings: $LOW_COUNT"; else ok "Low findings: 0"; fi

OCP_VERSION="$(jq -r '.items[0].status.desired.version // "unknown"' "$BASE/clusterversion.json" 2>/dev/null || echo unknown)"
CLUSTER_ID="$(jq -r '.status.infrastructureName // "unknown"' "$BASE/infrastructure.json" 2>/dev/null || echo unknown)"
APP_NS_COUNT="$(wc -l < "$BASE/app-namespaces.txt" | tr -d ' ')"

jq -n \
  --arg generated "$(date -Iseconds)" \
  --arg cluster "$CLUSTER" \
  --arg user "$USER" \
  --arg context "${CONTEXT:-unknown}" \
  --arg ocp_version "$OCP_VERSION" \
  --arg cluster_id "$CLUSTER_ID" \
  --argjson app_namespace_count "$APP_NS_COUNT" \
  --argjson total "$TOTAL_FINDINGS" \
  --argjson critical "$CRITICAL_COUNT" \
  --argjson high "$HIGH_COUNT" \
  --argjson medium "$MEDIUM_COUNT" \
  --argjson low "$LOW_COUNT" \
  '{generated:$generated,cluster:$cluster,user:$user,context:$context,ocp_version:$ocp_version,cluster_id:$cluster_id,app_namespace_count:$app_namespace_count,findings:{total:$total,critical:$critical,high:$high,medium:$medium,low:$low}}' \
  > "$SUMMARY_JSON"

cat > "$REPORT" <<EOF
# OpenShift Security Findings - Static Security Review

Generated: $(date)

Cluster: \`$CLUSTER\`  
Context: \`${CONTEXT:-unknown}\`  
User: \`$USER\`  
OpenShift version: \`$OCP_VERSION\`  
Cluster ID/name: \`$CLUSTER_ID\`

## Summary

| Severity | Count |
|---|---:|
| Critical | $CRITICAL_COUNT |
| High | $HIGH_COUNT |
| Medium | $MEDIUM_COUNT |
| Low | $LOW_COUNT |
| Total | $TOTAL_FINDINGS |

Application namespaces evaluated: \`$APP_NS_COUNT\`

## Main Files

\`\`\`text
$FINDINGS_CSV
$FINDINGS_JSONL
$SUMMARY_JSON
\`\`\`

## Checks Included

- kubeadmin bound to cluster-admin
- non-system cluster-admin subjects
- non-platform ClusterRole wildcard permissions
- application Role wildcard permissions
- sensitive broad ClusterRoleBindings
- privileged containers and init containers
- allowPrivilegeEscalation
- secrets exposed through environment variables
- explicit UID 0 at container and pod level
- fsGroup 0 at pod level
- added Linux capabilities
- capabilities not dropping ALL
- runAsNonRoot not enforced
- readOnlyRootFilesystem not enabled
- missing seccomp profile
- missing resource limits
- images using :latest
- images not pinned by digest
- hostNetwork, hostPID, hostIPC
- hostPath volumes
- default ServiceAccount usage
- explicit ServiceAccount token automount
- namespaces without any NetworkPolicy
- routes without TLS
- routes allowing insecure HTTP traffic
- API/etcd encryption type
- OAuth identity provider presence
- cluster image allowedRegistries policy presence
- risky custom SCC definitions
- sensitive SCC grants through RoleBindings and ClusterRoleBindings

## Notes

This is a read-only static review.

Known OpenShift platform roles, generated Operator roles, and expected default system bindings are suppressed where possible to reduce false positives.

Findings should be reviewed in context before remediation.

This script does not replace Compliance Operator scans, vulnerability scans, runtime detection, penetration testing, or manual architecture review.

System namespaces are excluded from application workload checks.
EOF

ok "Report written to $REPORT"
ok "Summary JSON written to $SUMMARY_JSON"
ok "Baseline written to $BASE"
ok "Risk findings CSV written to $FINDINGS_CSV"
ok "Risk findings JSONL written to $FINDINGS_JSONL"

echo
echo "View risky findings:"
echo "cat $FINDINGS_CSV"
echo
echo "View report:"
echo "cat $REPORT"