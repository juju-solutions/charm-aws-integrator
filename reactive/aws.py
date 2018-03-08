from charms.reactive import (
    when_all,
    when_any,
    when_not,
    endpoint_from_flag,
    toggle_flag,
    clear_flag,
)
from charmhelpers.core import hookenv

from charms.layer.aws import (
    update_credentials_file,
    tag_instance,
    tag_instance_security_group,
    tag_instance_subnet,
    enable_elb,
    enable_ebs,
    enable_route53,
    enable_s3_read,
    enable_s3_write,
)


@when_any('config.changed.access_key',
          'config.changed.secret_key')
def update_credentials():
    config = hookenv.config()
    access_key = config['access_key']
    secret_key = config['secret_key']
    update_credentials_file(access_key, secret_key)
    toggle_flag('charm.aws.has_secrets',
                access_key and secret_key)


@when_not('charm.aws.has_secrets')
def no_secrets():
    hookenv.status_set('blocked', 'cloud credential access required')


@when_all('snap.installed.aws-cli',
          'charm.aws.has_secrets')
@when_not('endpoint.aws.requested')
def no_requests():
    hookenv.status_set('active', 'ready')


@when_all('snap.installed.aws-cli',
          'charm.aws.has_secrets',
          'endpoint.aws.requested')
def handle_requests():
    hookenv.status_set('maintenance', 'granting integration requests')
    aws = endpoint_from_flag('endpoint.aws.requested')
    for request in aws.requests:
        if request.instance_tags:
            tag_instance(request.instance_id,
                         request.region,
                         request.instance_tags)
        if request.instance_security_group_tags:
            tag_instance_security_group(request.instance_id,
                                        request.region,
                                        request.instance_security_group_tags)
        if request.instance_subnet_tags:
            tag_instance_subnet(request.instance_id,
                                request.region,
                                request.instance_subnet_tags)
        if request.requested_elb:
            enable_elb(request.instance_id, request.region)
        if request.requested_ebs:
            enable_ebs(request.instance_id, request.region)
        if request.requested_route53:
            enable_route53(request.instance_id, request.region)
        if request.requested_s3_read:
            enable_s3_read(request.instance_id, request.region)
        if request.requested_s3_write:
            enable_s3_write(request.instance_id, request.region)
        request.mark_completed()
    clear_flag('endpoint.aws.requested')
