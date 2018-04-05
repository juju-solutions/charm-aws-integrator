from charms.reactive import (
    when_all,
    when_any,
    when_not,
    endpoint_from_flag,
    toggle_flag,
    clear_flag,
)

from charms import layer


@when_any('config.changed.access-key',
          'config.changed.secret-key')
def update_creds():
    clear_flag('charm.aws.creds.set')


@when_not('charm.aws.creds.set')
def get_creds():
    toggle_flag('charm.aws.creds.set', layer.aws.get_credentials())


@when_all('snap.installed.aws-cli',
          'charm.aws.creds.set')
@when_not('endpoint.aws.requested')
def no_requests():
    layer.status.maintenance('cleaning up unused aws entities')
    aws = endpoint_from_flag('endpoint.aws.requested')
    layer.aws.cleanup(aws.application_names)
    layer.status.active('ready')


@when_all('snap.installed.aws-cli',
          'charm.aws.creds.set',
          'endpoint.aws.requested')
def handle_requests():
    layer.status.maintenance('granting integration requests')
    aws = endpoint_from_flag('endpoint.aws.requested')
    for request in aws.requests:
        if request.instance_tags:
            layer.aws.tag_instance(
                request.instance_id,
                request.region,
                request.instance_tags)
        if request.unit_security_group_tags:
            layer.aws.tag_unit_security_group(
                request.instance_id,
                request.region,
                request.unit_security_group_tags)
        if request.instance_subnet_tags:
            layer.aws.tag_instance_subnet(
                request.instance_id,
                request.region,
                request.instance_subnet_tags)
        if request.requested_elb:
            layer.aws.enable_elb(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_ebs:
            layer.aws.enable_ebs(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_route53:
            layer.aws.enable_route53(
                request.application_name,
                request.instance_id,
                request.region)
        if request.requested_s3_read:
            layer.aws.enable_s3_read(
                request.application_name,
                request.instance_id,
                request.region,
                request.s3_read_patterns)
        if request.requested_s3_write:
            layer.aws.enable_s3_write(
                request.application_name,
                request.instance_id,
                request.region,
                request.s3_write_patterns)
        request.mark_completed()
    clear_flag('endpoint.aws.requested')
