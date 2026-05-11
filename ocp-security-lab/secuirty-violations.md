
------------------------------------------------------

# Scenario 1 — Privileged Container with securityContext: privileged: true

## Create insecure ServiceAccount

```bash
oc create sa insecure-sa -n security-lab
oc adm policy add-scc-to-user privileged -z insecure-sa -n security-lab
```

## Deploy privileged workload

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged-nginx
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: privileged-nginx
  template:
    metadata:
      labels:
        app: privileged-nginx
    spec:
      serviceAccountName: insecure-sa
      containers:
      - name: nginx
        image: nginx
        securityContext:
          privileged: true
```


---
---
---
---

# Scenario 2 — Missing NetworkPolicy

### Verify no policies exist

```bash
oc get networkpolicy -n security-lab
```

### To harden: Create default deny policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: security-lab
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

---
---
---


# Scenario 3 — HostNetwork Abuse

## Create insecure workload

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hostnetwork-sa
  namespace: security-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: hostnetwork-scc
  namespace: security-lab
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:hostnetwork-v2
subjects:
- kind: ServiceAccount
  name: hostnetwork-sa
  namespace: security-lab
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hostnetwork-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hostnetwork-app
  template:
    metadata:
      labels:
        app: hostnetwork-app
    spec:
      serviceAccountName: hostnetwork-sa
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: nginx
        image: nginxinc/nginx-unprivileged
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
EOF
```

### Verify

```bash
oc get pod -o yaml | grep hostNetwork
```

---
---
---


# Scenario 4 — Wildcard RBAC

## Dangerous role

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: wildcard-rbac-sa
  namespace: security-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wildcard-rbac-role
  namespace: security-lab
rules:
- apiGroups:
  - ""
  - apps
  resources:
  - "*"
  verbs:
  - "*"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: wildcard-rbac-binding
  namespace: security-lab
subjects:
- kind: ServiceAccount
  name: wildcard-rbac-sa
  namespace: security-lab
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: wildcard-rbac-role
EOF
```

### Verify

```bash
oc auth can-i delete pods \
  --as system:serviceaccount:security-lab:wildcard-rbac-sa \
  -n security-lab
```

---
---
---


# Scenario 5 — Secrets Exposed in Environment Variables

## Create Secret and use it as env-var in container

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
  namespace: security-lab
type: Opaque
stringData:
  username: admin
  password: SuperSecretPassword123
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-env-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secret-env-app
  template:
    metadata:
      labels:
        app: secret-env-app
    spec:
      containers:
      - name: app
        image: registry.access.redhat.com/ubi9/ubi-minimal
        command:
        - /bin/sh
        - -c
        - sleep 3600
        env:
        - name: DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: password
EOF
```

## Insecure env var usage

```bash
oc exec -it deploy/secret-env-app -n security-lab -- env | grep DB_
```

## Why insecure?

Secrets become environment variables inside the process memory and can be easily dumped from the container by the following commands:

Any process inside the container can read:

```bash
env
printenv
cat /proc/1/environ
```

## Better approach

Mount secrets as files and not as env-var:

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: db-secret-mounted
  namespace: security-lab
type: Opaque
stringData:
  username: admin
  password: SuperSecretPassword123
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-mounted-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secret-mounted-app
  template:
    metadata:
      labels:
        app: secret-mounted-app
    spec:
      containers:
      - name: app
        image: registry.access.redhat.com/ubi9/ubi-minimal
        command:
        - /bin/sh
        - -c
        - sleep 3600
        volumeMounts:
        - name: db-secret-volume
          mountPath: /etc/secrets
          readOnly: true
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
      volumes:
      - name: db-secret-volume
        secret:
          secretName: db-secret-mounted
EOF
```

---
---
---


# Scenario 6 — Containers Running as Root or UID=0

## Insecure configuration

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: root-sa
  namespace: security-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: root-anyuid-scc
  namespace: security-lab
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:anyuid
subjects:
- kind: ServiceAccount
  name: root-sa
  namespace: security-lab
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: root-container-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: root-container-app
  template:
    metadata:
      labels:
        app: root-container-app
    spec:
      serviceAccountName: root-sa
      containers:
      - name: app
        image: registry.access.redhat.com/ubi9/ubi-minimal
        command:
        - /bin/sh
        - -c
        - sleep 3600
        securityContext:
          runAsUser: 0
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
EOF
```

### Verify

```bash
oc exec -n security-lab deploy/root-container-app -- id
```

### To Harden

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
    - ALL
  seccompProfile:
    type: RuntimeDefault
```

---
---
---


# Scenario 7 — Dangerous Capability SYS_ADMIN

## Dangerous capability

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sysadmin-cap-sa
  namespace: security-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: sysadmin-cap-privileged-scc
  namespace: security-lab
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:privileged
subjects:
- kind: ServiceAccount
  name: sysadmin-cap-sa
  namespace: security-lab
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sysadmin-cap-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sysadmin-cap-app
  template:
    metadata:
      labels:
        app: sysadmin-cap-app
    spec:
      serviceAccountName: sysadmin-cap-sa
      containers:
      - name: app
        image: registry.access.redhat.com/ubi9/ubi-minimal
        command:
        - /bin/sh
        - -c
        - sleep 3600
        securityContext:
          allowPrivilegeEscalation: true
          capabilities:
            add:
            - SYS_ADMIN
EOF
```

## Why dangerous?

SYS_ADMIN is often called "the new root".

It allows:
- mount operations
- namespace manipulation
- filesystem operations
- kernel-related operations and kernel parameters change

### Verify

```bash
oc get pod -o yaml | grep SYS_ADMIN

oc get pod -n security-lab -l app=sysadmin-cap-app \
  -o jsonpath='{.items[0].spec.containers[0].securityContext.capabilities.add}{"\n"}'

oc exec -n security-lab deploy/sysadmin-cap-app -- sh -c 'grep Cap /proc/1/status'
```

---
---
---


# Scenario 8 — HostPath Mount Abuse

## Dangerous HostPath mount

```yaml
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: hostpath-sa
  namespace: security-lab
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: hostpath-privileged-scc
  namespace: security-lab
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:privileged
subjects:
- kind: ServiceAccount
  name: hostpath-sa
  namespace: security-lab
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hostpath-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: hostpath-app
  template:
    metadata:
      labels:
        app: hostpath-app
    spec:
      serviceAccountName: hostpath-sa
      containers:
      - name: app
        image: registry.access.redhat.com/ubi9/ubi-minimal
        command:
        - /bin/sh
        - -c
        - sleep 3600
        volumeMounts:
        - name: host-etc
          mountPath: /host-etc
        securityContext:
          allowPrivilegeEscalation: true
      volumes:
      - name: host-etc
        hostPath:
          path: /etc
          type: Directory
EOF
```

## Why dangerous?

Container gains access to host filesystem.

Possible abuse:
- read host configs
- steal credentials
- modify host files
- container escape paths

### Verify

```bash
oc exec -n security-lab deploy/hostpath-app -- ls /host-etc
```
---
---
---

# Scenario 9 — Insecure Route Without TLS
## a Route exposes your Service outside the cluster. If the Route has no spec.tls, traffic uses plain HTTP. Without TLS username, password, tokens, cookies, API data can travel unencrypted between the client and the router.
### Someone on the same network path could potentially:
- read traffic,
- steal session cookies,
- capture credentials,
- modify responses,
- inject malicious content.

## Insecure manifest

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-route-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure-route-app
  template:
    metadata:
      labels:
        app: insecure-route-app
    spec:
      containers:
      - name: nginx
        image: nginxinc/nginx-unprivileged
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
---
apiVersion: v1
kind: Service
metadata:
  name: insecure-route-app
  namespace: security-lab
spec:
  selector:
    app: insecure-route-app
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: insecure-route-app
  namespace: security-lab
spec:
  to:
    kind: Service
    name: insecure-route-app
  port:
    targetPort: 8080
EOF
```

### Verify

```bash
oc get route insecure-route-app -n security-lab -o yaml | grep -A5 "tls:"
```

### To Harden

```yaml
apiVersion: v1
kind: Service
metadata:
  name: secure-route-app
  namespace: security-lab
spec:
  selector:
    app: insecure-route-app
  ports:
  - name: http
    port: 8080
    targetPort: 8080
---
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: secure-route-app
  namespace: security-lab
spec:
  to:
    kind: Service
    name: secure-route-app
  port:
    targetPort: http
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect
```

---
---
---


# Scenario 10 — ServiceAccount Token Automount Enabled
## This means the pod automatically receives a Kubernetes API token inside the container filesystem usually in /var/run/secrets/kubernetes.io/serviceaccount/token
### If token automount is enabled like:  
automountServiceAccountToken: true
### then the pod can authenticate to the Kubernetes API.
### If an attacker compromises the container, they may steal that token and use it to:
- query the API,
- list resources,
- access secrets,
- move laterally,
- attack the cluster depending on RBAC permissions.


## Insecure manifest

```bash
cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: token-auto-sa
  namespace: security-lab
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: token-auto-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: token-auto-app
  template:
    metadata:
      labels:
        app: token-auto-app
    spec:
      serviceAccountName: token-auto-sa
      automountServiceAccountToken: true
      containers:
      - name: app
        image: registry.access.redhat.com/ubi9/ubi-minimal
        command:
        - /bin/sh
        - -c
        - sleep 3600
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
EOF
```

### Verify

```bash
oc get pod -n security-lab -l app=token-auto-app \
  -o jsonpath='{.items[0].spec.automountServiceAccountToken}{"\n"}'
```

```bash
oc exec -n security-lab deploy/token-auto-app -- ls /var/run/secrets/kubernetes.io/serviceaccount

oc exec -n security-lab deploy/token-auto-app -- sh -c \
'cat /var/run/secrets/kubernetes.io/serviceaccount/token | head'
```

### Harden

```bash
oc patch deployment token-auto-app -n security-lab --type='json' -p='[
  {"op":"replace","path":"/spec/template/spec/automountServiceAccountToken","value":false}
]'
```

```bash
oc rollout restart deployment token-auto-app -n security-lab
```

---
---
---


# Scenario 11 — Mutable latest Image Tag
## latest is mutable and the image behind the tag can change at any time.
## Insecure manifest

```bash
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: latest-image-app
  namespace: security-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: latest-image-app
  template:
    metadata:
      labels:
        app: latest-image-app
    spec:
      containers:
      - name: app
        image: nginxinc/nginx-unprivileged:latest
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL
          seccompProfile:
            type: RuntimeDefault
EOF
```

### Verify

```bash
oc get deployment latest-image-app -n security-lab \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

### To Harden

```bash
oc set image deployment/latest-image-app \
  app=nginxinc/nginx-unprivileged:1.27-alpine \
  -n security-lab
```

