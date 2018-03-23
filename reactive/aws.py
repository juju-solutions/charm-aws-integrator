from charms.reactive import (
    when_all,
    when_any,
    when_not,
    endpoint_from_flag,
    toggle_flag,
    clear_flag,
)
from charmhelpers.core import hookenv

from charms.layer import aws as charm_lib


@when_any('config.changed.access_key',
          'config.changed.secret_key')
def update_credentials():
    config = hookenv.config()
    access_key = config['access_key']
    secret_key = config['secret_key']
    charm_lib.update_credentials_file(access_key, secret_key)
    toggle_flag('charm.aws.has_secrets',
                access_key and secret_key)


@when_not('charm.aws.has_secrets')
def no_secrets():
    hookenv.status_set('blocked', 'cloud credential access required')


@when_all('snap.installed.aws-cli',
          'charm.aws.has_secrets')
@when_not('endpoint.aws.requested')
def no_requests():
    hookenv.status_set('maintenance', 'cleaning up unused aws entities')
    aws = endpoint_from_flag('endpoint.aws.requested')
    charm_lib.cleanup(aws.application_names)
    hookenv.status_set('active', 'ready')


@when_all('snap.installed.aws-cli',
          'charm.aws.has_secrets',
          'endpoint.aws.requested')
def handle_requests():
    hookenv.status_set('maintenance', 'granting integration requests')
    aws = endpoint_from_flag('endpoint.aws.requested')
    for request in aws.requests:
        if request.instance_tags:
            charm_lib.tag_instance(
                request.instance_id,
                request.region,
                request.instance_tags)
        if request.unit_security_group_tags:
            charm_lib.tag_unit_security_group(
                request.instance_id,
                request.region,
                request.unit_security_group_tags)
        if request.instance_subnet_tags:
            charm_lib.tag_instance_subnet(
                request.instance_id,
                request.region,
                request.instance_subnet_tags)
        if request.requested_elb:
            charm_lib.enable_elb(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_ebs:
            charm_lib.enable_ebs(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_route53:
            charm_lib.enable_route53(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_s3_read:
            charm_lib.enable_s3_read(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_s3_write:
            charm_lib.enable_s3_write(
                request.application_name,
                request.instance_id,
                request.region)
        request.mark_completed()
    clear_flag('endpoint.aws.requested')
