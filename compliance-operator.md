1) Compliance Operator is an automated auditor (standardized, formal, based on benchmarks)

2) CSV = ClusterServiceVersion is a Kubernetes object that represents an installed operator version and it can be installed by

3) Install compliance-operator

    3.1) cat > compliance-operator-install.yaml <<'EOF'
    apiVersion: v1
    kind: Namespace
    metadata:
    name: openshift-compliance
    ---
    apiVersion: operators.coreos.com/v1
    kind: OperatorGroup
    metadata:
    name: compliance-operator
    namespace: openshift-compliance
    spec:
    targetNamespaces:
    - openshift-compliance
    ---
    apiVersion: operators.coreos.com/v1alpha1
    kind: Subscription
    metadata:
    name: compliance-operator
    namespace: openshift-compliance
    spec:
    channel: stable
    name: compliance-operator
    source: redhat-operators
    sourceNamespace: openshift-marketplace
    EOF

    3.2) ubuntu@ramin:~/Project/Openshift/ocp-security-lab$ oc apply -f compliance-operator-install.yaml
    3.3) ubuntu@ramin:~/Project/Openshift/ocp-security-lab$ oc get all -n openshift-compliance
        NAME                                                  READY   STATUS                   RESTARTS      AGE
        pod/compliance-operator-59db6f96fb-s8lbk              1/1     Running                  1 (29m ago)   29m
        pod/ocp4-openshift-compliance-pp-669c6bcf59-lvdq8     1/1     Running                  0             7m33s
        pod/ocp4-openshift-compliance-pp-669c6bcf59-xgckt     0/1     ContainerStatusUnknown   1             28m
        pod/rhcos4-openshift-compliance-pp-5b97fd4f67-4xtnk   0/1     Error                    0             28m
        pod/rhcos4-openshift-compliance-pp-5b97fd4f67-sg2jx   1/1     Running                  0             7m34s

        NAME              TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)             AGE
        service/metrics   ClusterIP   10.217.4.176   <none>        8383/TCP,8585/TCP   29m

        NAME                                             READY   UP-TO-DATE   AVAILABLE   AGE
        deployment.apps/compliance-operator              1/1     1            1           29m
        deployment.apps/ocp4-openshift-compliance-pp     1/1     1            1           28m
        deployment.apps/rhcos4-openshift-compliance-pp   1/1     1            1           28m

        NAME                                                        DESIRED   CURRENT   READY   AGE
        replicaset.apps/compliance-operator-59db6f96fb              1         1         1       29m
        replicaset.apps/ocp4-openshift-compliance-pp-669c6bcf59     1         1         1       28m
        replicaset.apps/rhcos4-openshift-compliance-pp-5b97fd4f67   1         1         1       28m

    3.4) ubuntu@ramin:~/Project/Openshift/ocp-security-lab$ oc get csv -n openshift-compliance -w
   

4) CIS = Center for Internet Security is an institute which publishes Security benchmarks (industry standards) like: CIS Kubernetes Benchmark or CIS OpenShift Benchmark

        ubuntu@ramin:~/Project/Openshift/ocp-security-lab$ oc get profiles.compliance -n openshift-compliance
        NAME                       AGE   VERSION
        ocp4-bsi                   25m   2022
        ocp4-bsi-2022              25m   2022
        ocp4-bsi-node              25m   2022
        ocp4-bsi-node-2022         25m   2022
        ocp4-cis                   25m   1.9.0
        ocp4-cis-1-7               25m   1.7.0
        ocp4-cis-1-9               25m   1.9.0
        ocp4-cis-node              25m   1.9.0
        ocp4-cis-node-1-7          25m   1.7.0
        ocp4-cis-node-1-9          25m   1.9.0
        ocp4-e8                    25m   
        ocp4-high                  25m   Revision 4
        ocp4-high-node             25m   Revision 4
        ocp4-high-node-rev-4       25m   Revision 4
        ocp4-high-rev-4            25m   Revision 4
        ocp4-moderate              25m   Revision 4
     
    
4) Perform CIS scan: 
        ✔ API server audit logging enabled?
        ✔ etcd encryption enabled?
        ✔ RBAC overly permissive?
        ✔ kubelet secure configuration?
        ✔ TLS properly configured?

        ubuntu@ramin:~/Project/Openshift/ocp-security-lab$ cat <<EOF | oc apply -f -
        apiVersion: compliance.openshift.io/v1alpha1
        kind: ScanSettingBinding
        metadata:
        name: cis-scan
        namespace: openshift-compliance
        profiles:
        - name: ocp4-cis
        kind: Profile
        apiGroup: compliance.openshift.io/v1alpha1
        - name: ocp4-cis-node
        kind: Profile
        apiGroup: compliance.openshift.io/v1alpha1
        settingsRef:
        name: default
        kind: ScanSetting
        apiGroup: compliance.openshift.io/v1alpha1
        EOF
       
5) Results:
        ubuntu@ramin:~/Project/Openshift/ocp-security-lab$ oc get compliancecheckresult -n openshift-compliance | grep FAIL

6. some checks
        $ oc get subscription -n openshift-compliance
        NAME                  PACKAGE               SOURCE             CHANNEL
        compliance-operator   compliance-operator   redhat-operators   release-0.1
        $ oc get csv -n openshift-compliance
        NAME                         DISPLAY               VERSION   REPLACES                     PHASE
        compliance-operator.v1.9.0   Compliance Operator   1.9.0     compliance-operator.v1.8.2   Succeeded