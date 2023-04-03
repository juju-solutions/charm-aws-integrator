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


@when_all("snap.installed.aws-cli")
def set_app_ver():
    try:
        result = subprocess.run(["snap", "info", "aws-cli"], stdout=subprocess.PIPE)
    except subprocess.CalledProcessError:
        pass
    else:
        stdout = result.stdout.decode("utf8").splitlines()
        version = [line.split()[1] for line in stdout if "installed" in line]
        if version:
            hookenv.application_version_set(version[0])


@when_any(
    "config.changed.credentials",
    "config.changed.access-key",
    "config.changed.secret-key",
)
def update_creds():
    clear_flag("charm.aws.creds.set")


@when_not("charm.aws.creds.set")
def get_creds():
    toggle_flag("charm.aws.creds.set", layer.aws.get_credentials())


@when_all("snap.installed.aws-cli", "charm.aws.creds.set")
@when_not("endpoint.aws.requested")
@when_not("upgrade.series.in-progress")
def no_requests():
    aws = endpoint_from_name("aws")
    if aws and aws.application_names:
        layer.status.maintenance("Cleaning up unused AWS entities")
        layer.aws.cleanup(aws.application_names)
    layer.status.active("Ready")


@when_all("snap.installed.aws-cli", "charm.aws.creds.set", "endpoint.aws.requested")
@when_not("upgrade.series.in-progress")
def handle_requests():
    aws = endpoint_from_name("aws")
    try:
        for request in aws.requests:
            layer.status.maintenance(
                "Granting request for {}".format(request.unit_name)
            )
            if request.instance_tags:
                layer.aws.tag_instance(
                    request.instance_id, request.region, request.instance_tags
                )
            if request.instance_security_group_tags:
                layer.aws.tag_instance_security_group(
                    request.instance_id,
                    request.region,
                    request.instance_security_group_tags,
                )
            if request.instance_subnet_tags:
                layer.aws.tag_instance_subnet(
                    request.application_name,
                    request.instance_id,
                    request.region,
                    request.instance_subnet_tags,
                )
            if request.requested_acm_readonly:
                layer.aws.enable_acm_readonly(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_acm_fullaccess:
                layer.aws.enable_acm_fullaccess(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_autoscaling_readonly:
                layer.aws.enable_autoscaling_readonly(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_instance_inspection:
                layer.aws.enable_instance_inspection(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_instance_modification:
                layer.aws.enable_instance_modification(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_network_management:
                layer.aws.enable_network_management(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_load_balancer_management:
                layer.aws.enable_load_balancer_management(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_block_storage_management:
                layer.aws.enable_block_storage_management(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_dns_management:
                layer.aws.enable_dns_management(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_region_readonly:
                layer.aws.enable_region_readonly(
                    request.application_name, request.instance_id, request.region
                )
            if request.requested_object_storage_access:
                layer.aws.enable_object_storage_access(
                    request.application_name,
                    request.instance_id,
                    request.region,
                    request.object_storage_access_patterns,
                )
            if request.requested_object_storage_management:
                layer.aws.enable_object_storage_management(
                    request.application_name,
                    request.instance_id,
                    request.region,
                    request.object_storage_management_patterns,
                )
            layer.aws.log("Finished request for {}".format(request.unit_name))
            request.mark_completed()
        clear_flag("endpoint.aws.requested")
    except layer.aws.AWSError as e:
        hookenv.log(format_exc(), hookenv.ERROR)
        layer.status.blocked(
            "Error while granting requests ({}); "
            "check credentials and debug-log".format(e.error_type or "unknown")
        )


@when_all(
    "snap.installed.aws-cli", "charm.aws.creds.set", "rds-mysql.database.requested"
)
@when_not("upgrade.series.in-progress")
def handle_mysql_requests():
    mysql_clients = endpoint_from_name("rds-mysql")
    mysql_rds = layer.aws.MySQLRDSManager()
    reqs = {
        req: app
        for req, app in mysql_clients.database_requests().items()
        if app
        and req
        not in (
            mysql_rds.failed_creates | set(mysql_rds.active) | set(mysql_rds.pending)
        )
    }

    for req, app in reqs.items():
        layer.status.maintenance("Creating RDS MySQL database for " + app)
        mysql_rds.create_db(req)

    if mysql_rds.pending:
        layer.status.maintenance("Waiting for RDS MySQL databases")
        completed = mysql_rds.poll_pending()
        for req, db in completed.items():
            mysql_clients.provide_database(
                req,
                host=db["host"],
                port=db["port"],
                database_name=db["database"],
                user=db["username"],
                password=db["password"],
            )

    if mysql_rds.failed_creates:
        layer.status.blocked("Failed to create one or " "more RDS MySQL databases")
    elif mysql_rds.pending:
        layer.status.waiting("Waiting for RDS MySQL databases")
    else:
        layer.status.active("Ready")


@when_all("snap.installed.aws-cli", "charm.aws.creds.set")
@when_not("upgrade.series.in-progress")
def cleanup_mysql_dbs():
    mysql_clients = endpoint_from_name("rds-mysql")
    mysql_rds = layer.aws.MySQLRDSManager()
    reqs = set(mysql_clients.database_requests() if mysql_clients else [])

    abandonded_dbs = (set(mysql_rds.active) | set(mysql_rds.pending)) - reqs
    if abandonded_dbs:
        layer.status.maintenance(
            "Cleaning up {} RDS MySQL database{}".format(
                len(abandonded_dbs), "s" if len(abandonded_dbs) > 1 else ""
            )
        )
        for req in abandonded_dbs:
            mysql_rds.delete_db(req)

    abandonded_failures = mysql_rds.failed_creates - reqs
    if abandonded_failures:
        mysql_rds.remove_failed_creates(abandonded_failures)

    if mysql_rds.failed_deletes:
        layer.status.blocked("Failed to delete one or " "more RDS MySQL databases")


@hook("upgrade-charm")
def upgrade_charm():
    try:
        layer.aws.update_policies()
    except layer.aws.AWSError:
        hookenv.log(format_exc(), hookenv.ERROR)
        layer.status.blocked(
            "Error while updating policies; " "check credentials and debug-log"
        )


@hook("pre-series-upgrade")
def pre_series_upgrade():
    layer.status.blocked("Series upgrade in progress")


@hook("stop")
def final_cleanup():
    try:
        # cleanup all managed entities, including
        # ones we might have missed previously
        layer.aws.cleanup([])
        cleanup_mysql_dbs()
    except layer.aws.AWSError:
        pass  # can't stop the stop
