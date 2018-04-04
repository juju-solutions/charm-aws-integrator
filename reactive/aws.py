from charms.reactive import (
    when_all,
    when_any,
    when_not,
    endpoint_from_flag,
    toggle_flag,
    clear_flag,
)

from charms.layer import status
from charms.layer import aws as charm_lib


@when_any('config.changed.access-key',
          'config.changed.secret-key')
def update_creds():
    clear_flag('charm.aws.creds.set')


@when_not('charm.aws.creds.set')
def get_creds():
    toggle_flag('charm.aws.creds.set', charm_lib.get_credentials())


@when_all('snap.installed.aws-cli',
          'charm.aws.creds.set')
@when_not('endpoint.aws.requested')
def no_requests():
    status.maintenance('cleaning up unused aws entities')
    aws = endpoint_from_flag('endpoint.aws.requested')
    charm_lib.cleanup(aws.application_names)
    status.active('ready')


@when_all('snap.installed.aws-cli',
          'charm.aws.creds.set',
          'endpoint.aws.requested')
def handle_requests():
    status.maintenance('granting integration requests')
    aws = endpoint_from_flag('endpoint.aws.requested')
    for request in aws.requests:
        if request.instance_tags:
            charm_lib.tag_instance(
                request.instance_id,
                request.region,
                request.instance_tags)
        if request.unit_security_group_tags:
            charm_lib.tag_unit_security_group(
                request.application_name,
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
                request.region,
                request.s3_read_patterns)
        if request.requested_s3_write:
            charm_lib.enable_s3_write(
                request.application_name,
                request.instance_id,
                request.region,
                request.s3_write_patterns)
        request.mark_completed()
    clear_flag('endpoint.aws.requested')
