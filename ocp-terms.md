1. RBAC
    ClusterRole vs Role:
    Same "RBAC" concept as Kubernetes. Role is namespace-scoped; ClusterRole is cluster-wide or reusable across namespaces.
    Same: Role, RoleBinding, ClusterRole, ClusterRoleBinding.

2. SCC SecurityContextConstraints
    control what "pods can do" like running as root, privileged, hostPath, hostNetwork, UID ranges, capabilities, etc
    Same as "PodSecurityPolicy" in K8s
    

3. oc adm
    Admin subcommands for "cluster-level operations" like inspect, must-gather, policy, node, upgrade, catalog, groups.

4. netpol 
    like k3s NetworkPolicy Used to control "pod ingress/egress traffic inside namespaces"

5. Service
    in both are same and expose a set of Pods as an endpoint and allocate to it an IP and DNS name and has different types like ClusterIP/NodePort/LoadBalancer and generally loadbalnce traffics to pods

6. ServiceAccount
     is used for authentication inside the cluster and performs permission via RBAC and pods use it to talk to API server and it includes usually tokens.

7. Routes 
     like "ingress" in k3s exposes a Service externally via OpenShift router/Ingress Controller, often HAProxy-based

8. "Ingress controller" 
     which ocp has "built-in HAProxy" while in k3s "NGINX" or "Traefik"

9. Project 
     like namespace in k3s with additional RBAC+quotas+annotation
     Namespace resources includes Pods, Deployments, Services, ConfigMaps, Secrets
     When we create a Project in openshift, it creates the namespace + adds default RBAC rules, Assigns project admins, Applies SCC and enable quotas if configured

10. ConfigMap: 
     stores non-sensitive configuration like Env Vars or config files and is plain text
        apiVersion: v1
        data:
        master.conf: |-
            dir /data
            # User-supplied master configuration:
            rename-command FLUSHDB ""
        replica.conf: |-
            dir /data
            # User-supplied replica configuration:
            replica-read-only no
            rename-command FLUSHDB ""
            rename-command FLUSHALL ""
        kind: ConfigMap
        metadata:
        annotations:
            meta.helm.sh/release-namespace: superset
        creationTimestamp: "2026-03-16T15:26:49Z"
        labels:
            app: redis
            app.kubernetes.io/instance: redis
            app.kubernetes.io/version: 8.2.3
            release: redis
        name: redis-scripts


11. Secrets: 
    sotres sensitive data like Passwords, Tokens, keys and encoded base64
    apiVersion: v1
    data:
    cloud: CltkZWZhdWx0XQphd3NfYWNjZXNzX2tleV9pZD1HVDNJVlQ2WTk4Q0pKWFhRMFFJSwphd3Nfc2VjcmV0X2FjY2Vzc19rZXk9cWRvR2w2d2lPdndpVjRHTkd6UEpEZFlBSDBzTzZvbGU5d1Z3bnZMNAoK
    kind: Secret
    metadata:
    labels:
        app.kubernetes.io/instance: velero
        app.kubernetes.io/name: velero
        helm.sh/chart: velero-10.0.9
    name: velero
    namespace: velero
    resourceVersion: "85628"
    uid: 3d273bad-7321-42bb-a129-a1be0b247ca4
    type: Opaque
    echo "CltkZWZhdWx0XQphd3NfYWNjZXNzX2tleV9pZD1HVDNJVlQ2WTk4Q0pKWFhRMFFJSwphd3Nfc2VjcmV0X2FjY2Vzc19rZXk9cWRvR2w2d2lPdndpVjRHTkd6UEpEZFlBSDBzTzZvbGU5d1Z3bnZMNAoK" | base64 --decode
    aws_access_key_id=GT3IVT6Y98CJJXXQ0QIK
    aws_secret_access_key=qdoGl6wiOvwiV4GNGzPJDdYAH0sO6ole9wVwnvL4

12. Storage: both has PV and PVC

13. CI/CD integration in ocp has a "built-in pipeline Tekton" while k3s usually uses Argocd

14. Authentication in ocp is done by "built-in OAuth server" while k3s uses usually an external OIDCs

15. Monitoring in ocp is built-in Prometheus, Grafana and Loki

16. S2I out-of-the-box or prefabricated
     OCP has a built-in "dockerfile to image" tool namely S2I and 
     also built-in image registry contrary to K3s which uses usually Nexus
     also built-in "ImageStream tool" which tracks container images over time and supports automatic updates

17. Operator
     ocp has for example a built-in Operator Lifecycle Manager (OLM) which k3s usually use "Helm" or "Kubectl apply Yaml"
     in fact it performs an automatic lifecycle management like install, deploy, scale, update, failover, self-healing...
        apiVersion: v1
        kind: Namespace
        metadata:
        name: my-operator-namespace
        --------------
        apiVersion: mysql.oracle.com/v2
        kind: InnoDBCluster
        metadata:
        name: my-mysql
        namespace: my-operator-namespace
        spec:
        instances: 3
        router:
            instances: 1
        secretName: mysql-root-password
        ---------------

18. RBAC

    $ kubectl get "pod" velero-65c69f465d-mfdkx -n velero   -o jsonpath='{.spec.serviceAccountName}{"\n"}'
    velero-server

    $ kubectl get "serviceaccounts" velero-server -n velero   -o jsonpath='{.metadata.name}{"\n"}{.metadata.namespace}{"\n"}{.automountServiceAccountToken}{"\n"}'
    name: velero-server
    namespace: velero
    automountToken: true

    $ kubectl get "rolebinding" velero-server -n velero -o jsonpath='{.subjects[*].kind}{" "}{.subjects[*].name}{" "}{.subjects[*].namespace}{"\n"}'
    kind: ServiceAccount 
    name: velero-server 
    namespace: velero

    $ kubectl get "role" velero-server -n velero -o jsonpath='{range .rules[*]}apiGroups={.apiGroups} resources={.resources} verbs={.verbs}{"\n"}{end}'
    apiGroups=["*"] resources=["*"] verbs=["*"]

    $ kubectl get "clusterrolebinding" velero-server -o jsonpath='{.metadata.name}{" -> "}{.roleRef.kind}{"/"}{.roleRef.name}{"\n"}'
    velero-server
    kind: ClusterRole
    name: cluster-admin

    $ kubectl get "clusterrole" cluster-admin -o jsonpath='{range .rules[*]}apiGroups={.apiGroups} resources={.resources} verbs={.verbs}{"\n"}{end}'
    apiGroups=["*"] resources=["*"] verbs=["*"]
    apiGroups= resources= verbs=["*"]

    $ kubectl auth can-i delete nodes --as=system:serviceaccount:velero:velero-server
    yes

                         ┌──────────────────────────────┐
                         │  Pod: velero-65c69f465d...   │
                         │  Namespace: velero           │
                         └──────────────┬───────────────┘
                                        │ uses
                                        ▼
                         ┌──────────────────────────────┐
                         │ ServiceAccount: velero-server│
                         │ Identity:                    │
                         │ system:serviceaccount:       │
                         │ velero:velero-server         │
                         └──────────────┬───────────────┘
                                        │ sends token to
                                        ▼
                         ┌──────────────────────────────┐
                         │ Kubernetes API Server        │
                         │ "Can this identity do this?" │
                         └──────────────┬───────────────┘
                                        │ checks all matching bindings
          ┌─────────────────────────────┴─────────────────────────────┐
          │                                                           │
          ▼                                                           ▼
┌──────────────────────────────┐                         ┌──────────────────────────────┐
│ RoleBinding                  │                         │ ClusterRoleBinding           │
│ velero/velero-server         │                         │ velero-server                │
│ subject: velero-server SA    │                         │ subject: velero-server SA    │
└──────────────┬───────────────┘                         └──────────────┬───────────────┘
               │ points to                                              │ points to
               ▼                                                        ▼
┌──────────────────────────────┐                         ┌──────────────────────────────┐
│ Role                         │                         │ ClusterRole                  │
│ velero/velero-server         │                         │ cluster-admin                │
│ apiGroups: *                 │                         │ apiGroups: *                 │
│ resources: *                 │                         │ resources: *                 │
│ verbs: *                     │                         │ verbs: *                     │
│ Scope: namespace velero only │                         │ Scope: whole cluster         │
└──────────────┬───────────────┘                         └──────────────┬───────────────┘
               │                                                        │
               └───────────────────────┬────────────────────────────── ─┘
                                       ▼
                         ┌──────────────────────────────┐
                         │ Final RBAC decision          │
                         │ If ANY rule matches: ALLOW   │
                         │ Else: DENY                   │
                         └──────────────────────────────┘





19. Image tag as latest is insecure since Latest is "mutable". Therefore we must use a specific tag or use image digest.

20. Priviledges containers/Pods can access host-level features and escape the container and break the rule of container isolation

21. Pods using hostnetwork are dangerous:
      pod.spec.hostNetwork == false
      pod.spec.hostPID == false
      pod.spec.hostPath == false   ----> PVC/CSI storage instead


22. Checking roles and clusterroles to remove extra unnecceary permissions.
      Wildcard verbs/resources in Roles/ClusterRoles

23. Namespaces without NetworkPolicy let's pods be broadly reachable.

24. Routes without TLS
      .spec.tls.termination is empty

25. API/etcd encryption check
       $ oc get apiserver cluster -o jsonpath='{.spec.encryption.type}'  ----> aescbc

26. ServiceAccount token automounting

27. Ingress
- The actual application container/pod can be nginx but Pods are temporary/ephemeral and unstable. They die, they restart, they change IPs...
- A Service exposes Pods INSIDE the cluster and gives stable DNS name, stable IP and load balancing to Pods like myapp.security-lab.svc.cluster.local so that Other Pods can access it.
- Route or Ingress exposes the Service OUTSIDE the cluster. 
      - Ingress is a Kubernetes API object that controls external HTTP/HTTPS access to services
      - It acts like an application-aware reverse proxy / traffic router.

            Internet
                ↓
            Ingress Controller  (The Ingress Controller is the actual router/proxy component and usually runs HAProxy pods)
                ↓
            Ingress
                ↓
            Service
                ↓
            Pods

apiVersion: v1
kind: Service
metadata:
name: nginx-service
namespace: security-lab
spec:
selector:
    app: ingress-demo
ports:
- port: 8080
    targetPort: 8080
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo
  namespace: security-lab
spec:
  tls:
  - hosts:
    - ingress-demo.apps-crc.testing
  rules:
  - host: ingress-demo.apps-crc.testing
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nginx-service
            port:
              number: 8080

28. All checks
kubeadmin bound to cluster-admin
non-system cluster-admin subjects
ClusterRole wildcard permissions
application Role wildcard permissions
broad ClusterRoleBindings to system groups
privileged containers and init containers
allowPrivilegeEscalation
explicit UID 0
added Linux capabilities
capabilities not dropping ALL
runAsNonRoot not enforced
readOnlyRootFilesystem not enabled
missing seccomp profile
missing resource limits
images using :latest
images not pinned by digest
hostNetwork, hostPID, hostIPC
hostPath volumes
default ServiceAccount usage
explicit ServiceAccount token automount
namespaces without any NetworkPolicy
routes without TLS
routes allowing insecure HTTP traffic
API/etcd encryption type
OAuth identity provider presence
cluster image allowedRegistries policy presence
risky custom SCC settings