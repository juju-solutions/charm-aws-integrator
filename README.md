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


[interface]: https://github.com/juju-solutions/interface-aws
[CDK]: https://jujucharms.com/canonical-kubernetes
