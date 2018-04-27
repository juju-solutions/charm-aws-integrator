# Overview

This charm acts as a proxy to AWS and provides an [interface][] to apply a
certain set of changes via IAM roles, profiles, and tags to the instances of
the applications that are related to this charm.

## Usage

When on AWS, this charm can be deployed, granted trust via Juju to access AWS,
and then related to an application that supports the [interface][].

For example, [CDK][] has [pending support](https://github.com/kubernetes/kubernetes/pull/62354)
for this, and can be deployed with the following bundle overlay:

```yaml
applications:
  kubernetes-master:
    charm: cs:~johnsca/kubernetes-master
  kubernetes-worker:
    charm: cs:~johnsca/kubernetes-worker
  aws:
    charm: cs:~johnsca/aws
    num_units: 1
relations:
  - ['aws', 'kubernetes-master']
  - ['aws', 'kubernetes-worker']
```

Using Juju 2.4-beta1 or later:

```
juju deploy cs:canonical-kubernetes --overlay ./k8s-aws-overlay.yaml
juju trust aws
```

To deploy with earlier versions of Juju, you will need to provide the cloud
credentials via the `credentials`, or `access-key` and `secret-key`, charm
config options.

# Examples

Following are some examples using AWS integration with CDK.

## Creating a pod with an EBS-backed volume

This script creates a busybox pod with a persistent volume claim backed by
AWS's Elastic Block Storage.

```sh
#!/bin/bash

# create a storage class using the `kubernetes.io/aws-ebs` provisioner
kubectl create -f - <<EOY
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ebs-1
provisioner: kubernetes.io/aws-ebs
parameters:
  type: gp2
EOY

# create a persistent volume claim using that storage class
kubectl create -f - <<EOY
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: testclaim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
  storageClassName: ebs-1
EOY

# create the busybox pod with a volume using that PVC:
kubectl create -f - <<EOY
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
    - image: busybox
      command:
        - sleep
        - "3600"
      imagePullPolicy: IfNotPresent
      name: busybox
      volumeMounts:
        - mountPath: "/pv"
          name: testvolume
  restartPolicy: Always
  volumes:
    - name: testvolume
      persistentVolumeClaim:
        claimName: testclaim
EOY
```

## Creating a service with an AWS load-balancer

The following script starts the hello-world pod behind an AWS Elastic Load Balancer.

```sh
#!/bin/bash

kubectl run hello-world --replicas=5 --labels="run=load-balancer-example" --image=gcr.io/google-samples/node-hello:1.0  --port=8080
kubectl expose deployment hello-world --type=LoadBalancer --name=hello
watch kubectl get svc -o wide --selector=run=load-balancer-example
```


[interface]: https://github.com/juju-solutions/interface-aws
[CDK]: https://jujucharms.com/canonical-kubernetes
