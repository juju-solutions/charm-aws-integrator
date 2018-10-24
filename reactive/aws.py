import subprocess
from traceback import format_exc

from charms.reactive import (
    when_all,
    when_any,
    when_not,
    endpoint_from_name,
    toggle_flag,
    clear_flag,
    hook,
)
from charmhelpers.core import hookenv

from charms import layer


@when_all('snap.installed.aws-cli')
def set_app_ver():
    try:
        result = subprocess.run(['snap', 'info', 'aws-cli'],
                                stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        pass
    else:
        stdout = result.stdout.decode('utf8').splitlines()
        version = [line.split()[1] for line in stdout if 'installed' in line]
        if version:
            hookenv.application_version_set(version[0])


@when_any('config.changed.credentials',
          'config.changed.access-key',
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
    aws = endpoint_from_name('aws')
    layer.aws.cleanup(aws.application_names)
    layer.status.active('ready')


@when_all('snap.installed.aws-cli',
          'charm.aws.creds.set',
          'endpoint.aws.requested')
def handle_requests():
    aws = endpoint_from_name('aws')
    try:
        for request in aws.requests:
            layer.status.maintenance('granting request for {}'.format(
                request.unit_name))
            if request.instance_tags:
                layer.aws.tag_instance(
                    request.instance_id,
                    request.region,
                    request.instance_tags)
            if request.instance_security_group_tags:
                layer.aws.tag_instance_security_group(
                    request.instance_id,
                    request.region,
                    request.instance_security_group_tags)
            if request.instance_subnet_tags:
                layer.aws.tag_instance_subnet(
                    request.instance_id,
                    request.region,
                    request.instance_subnet_tags)
            if request.requested_acm_readonly:
                layer.aws.enable_acm_readonly(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_acm_fullaccess:
                layer.aws.enable_acm_fullaccess(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_instance_inspection:
                layer.aws.enable_instance_inspection(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_network_management:
                layer.aws.enable_network_management(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_load_balancer_management:
                layer.aws.enable_load_balancer_management(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_block_storage_management:
                layer.aws.enable_block_storage_management(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_dns_management:
                layer.aws.enable_dns_management(
                    request.application_name,
                    request.instance_id,
                    request.region)
            if request.requested_object_storage_access:
                layer.aws.enable_object_storage_access(
                    request.application_name,
                    request.instance_id,
                    request.region,
                    request.object_storage_access_patterns)
            if request.requested_object_storage_management:
                layer.aws.enable_object_storage_management(
                    request.application_name,
                    request.instance_id,
                    request.region,
                    request.object_storage_management_patterns)
            layer.aws.log('Finished request for {}'.format(request.unit_name))
            request.mark_completed()
        clear_flag('endpoint.aws.requested')
    except layer.aws.AWSError:
        hookenv.log(format_exc(), hookenv.ERROR)
        layer.status.blocked('error while granting requests; '
                             'check credentials and debug-log')


@hook('upgrade-charm')
def upgrade_charm():
    try:
        layer.aws.update_policies()
    except layer.aws.AWSError:
        hookenv.log(format_exc(), hookenv.ERROR)
        layer.status.blocked('error while updating policies; '
                             'check credentials and debug-log')
