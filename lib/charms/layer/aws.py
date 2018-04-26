import json
import os
import re
import sys
import subprocess
from base64 import b64decode
from math import ceil, floor
from time import sleep
from configparser import ConfigParser, MissingSectionHeaderError
from pathlib import Path

import yaml

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


ENTITY_PREFIX = 'charm.aws'
MODEL_UUID = os.environ['JUJU_MODEL_UUID']
MAX_ROLE_NAME_LEN = 64
MAX_POLICY_NAME_LEN = 128


def log(msg, *args):
    hookenv.log(msg.format(*args), hookenv.INFO)


def log_err(msg, *args):
    hookenv.log(msg.format(*args), hookenv.ERROR)


def get_credentials():
    """
    Get the credentials from either the config or the hook tool.

    Prefers the config so that it can be overridden.
    """
    no_creds_msg = 'missing credentials; set credentials config'
    config = hookenv.config()
    # try to use Juju's trust feature
    try:
        result = subprocess.run(['credential-get'],
                                check=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        creds = yaml.load(result.stdout.decode('utf8'))
        access_key = creds['credential']['attributes']['access-key']
        secret_key = creds['credential']['attributes']['secret-key']
        update_credentials_file(access_key, secret_key)
        return True
    except FileNotFoundError:
        pass  # juju trust not available
    except subprocess.CalledProcessError as e:
        if 'permission denied' not in e.stderr.decode('utf8'):
            raise
        no_creds_msg = 'missing credentials access; grant with: juju trust'

    # try credentials config
    if config['credentials']:
        try:
            creds_data = b64decode(config['credentials']).decode('utf8')
            creds = ConfigParser()
            try:
                creds.read_string(creds_data)
            except MissingSectionHeaderError:
                creds.read_string('[default]\n' + creds_data)
            for section in creds.sections():
                access_key = creds[section].get('aws_access_key_id')
                secret_key = creds[section].get('aws_secret_access_key')
                if access_key and secret_key:
                    update_credentials_file(access_key, secret_key)
                    return True
        except Exception:
            status.blocked('invalid value for credentials config')
            return False

    # try access-key and secret-key config
    access_key = config['access-key']
    secret_key = config['secret-key']
    if access_key and secret_key:
        update_credentials_file(access_key, secret_key)
        return True

    # no creds provided
    status.blocked(no_creds_msg)
    return False


def update_credentials_file(access_key, secret_key):
    """
    Write the credentials to the config file for the aws-cli tool.
    """
    conf_dir = Path('/root/.aws')
    conf_dir.mkdir(0o700, exist_ok=True)
    conf_file = conf_dir / 'credentials'
    config = ConfigParser()
    if conf_file.exists():
        config.read(str(conf_file))
    if 'juju' not in config.sections():
        config.add_section('juju')
    config['juju']['aws_access_key_id'] = access_key
    config['juju']['aws_secret_access_key'] = secret_key
    with conf_file.open('w') as fp:
        os.fchmod(fp.fileno(), 0o600)
        config.write(fp)


def tag_instance(instance_id, region, tags):
    """
    Tag the given instance with the given tags.
    """
    log('Tagging instance {} in {} with: {}', instance_id, region, tags)
    _apply_tags(region, [instance_id], tags)


def tag_instance_security_group(instance_id, region, tags):
    """
    Tag the instance-specific security group that Juju created for the
    given instance with the given tags.
    """
    groups = _aws('ec2', 'describe-instances',
                  '--instance-ids', instance_id,
                  '--region', region,
                  '--query', 'Reservations[*]'
                             '.Instances[*]'
                             '.SecurityGroups[*]'
                             '.[GroupId,GroupName]'
                             '[][]')
    groups = {group_name: group_id
              for group_id, group_name in groups
              if re.match(r'^juju-.*-\d+$', group_name)}
    if len(groups) != 1:
        log_err('Got unexpected number of security groups: {}', groups)
        sys.exit(1)
    group_name, group_id = list(groups.items())[0]
    log('Tagging security group {} for instance {} in {} with: {}',
        group_name, instance_id, region, tags)
    _apply_tags(region, [group_id], tags)


def tag_instance_subnet(instance_id, region, tags):
    """
    Tag the subnet for the given instance with the given tags.
    """
    log('Tagging subnet for instance {} in {} with: {}',
        instance_id, region, tags)
    subnet_id = _aws('ec2', 'describe-instances',
                     '--instance-ids', instance_id,
                     '--region', region,
                     '--query', 'Reservations[*]'
                                '.Instances[*]'
                                '.SubnetId[] | [0]')
    _apply_tags(region, [subnet_id], tags)


def enable_instance_inspection(application_name, instance_id, region):
    """
    Enable instance inspection access for the given instance.
    """
    log('Enabling instance inspection for instance {} '
        'of application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('instance-inspection')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_network_management(application_name, instance_id, region):
    """
    Enable network (firewall, subnet, etc.) management for the given
    instance.
    """
    log('Enabling network management for instance {} '
        'of application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('network-management')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_load_balancer_management(application_name, instance_id, region):
    """
    Enable load balancer (ELB) management for the given instance.
    """
    log('Enabling ELB for instance {} of application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('elb')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_block_storage_management(application_name, instance_id, region):
    """
    Enable block storage (EBS) management for the given instance.
    """
    log('Enabling EBS for instance {} of application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('ebs')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_dns_management(application_name, instance_id, region):
    """
    Enable DNS (Route53) management for the given instance.
    """
    log('Enabling DNS (Route53) management for instance {} of '
        'application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('route53')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_object_storage_access(application_name, instance_id, region,
                                 patterns):
    """
    Enable object storage (S3) read-only access for the given instance to
    resources matching the given patterns.
    """
    log('Enabling object storage (S3) read for instance {} of '
        'application {} in region {}',
        instance_id, application_name, region)
    policy_name = 's3-read'
    if patterns:
        policy_name = _restrict_policy_for_app(policy_name,
                                               application_name,
                                               patterns)
    policy_arn = _get_policy_arn(policy_name)
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)
    if patterns:
        _add_app_entity(application_name, 'policy', policy_arn)


def enable_object_storage_management(application_name, instance_id, region,
                                     patterns):
    """
    Enable object storage (S3) management for the given instance to
    resources matching the given patterns.
    """
    log('Enabling S3 write for instance {} of application {} in region {}',
        instance_id, application_name, region)
    policy_name = 's3-write'
    if patterns:
        policy_name = _restrict_policy_for_app(policy_name,
                                               application_name,
                                               patterns)
    policy_arn = _get_policy_arn(policy_name)
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)
    if patterns:
        _add_app_entity(application_name, 'policy', policy_arn)


def cleanup(current_applications):
    """
    Cleanup unused IAM entities from the current model that are being managed
    by this charm instance.
    """
    managed_entities = _get_managed_entities()
    departed_applications = managed_entities.keys() - current_applications
    if not departed_applications:
        return
    log('Cleaning up unused AWS entities')
    for app in departed_applications:
        entities = managed_entities.pop(app)
        for role in entities['role']:
            _cleanup_role(role)
        for instance_profile in entities['instance-profile']:
            _cleanup_instance_profile(instance_profile)
        for policy in entities['policy']:
            _cleanup_policy(policy)
    _set_managed_entities(managed_entities)


# Internal helpers


class AWSError(Exception):
    """
    Exception class representing an error returned from the aws-cli tool.

    Includes an `error_type` field to distinguish the different error cases.
    """
    @classmethod
    def get(cls, message):
        """
        Factory method to create either an instance of this class or a
        meta-subclass for certain `error_type`s.
        """
        error_type = None
        match = re.match(r'An error occurred \(([^)]+)\)', message)
        if match:
            error_type = match.group(1)
        for error_cls in (DoesNotExistAWSError, AlreadyExistsAWSError):
            if error_type in error_cls.error_types:
                return error_cls(error_type, message)
        return AWSError(error_type, message)

    def __init__(self, error_type, message):
        self.error_type = error_type
        self.message = message
        super().__init__(message)

    def __str__(self):
        return self.message


class DoesNotExistAWSError(AWSError):
    """
    Meta-error subclass of AWSError representing something not existing.
    """
    error_types = [
        'NoSuchEntity',
        'InvalidParameterValue',
    ]


class AlreadyExistsAWSError(AWSError):
    """
    Meta-error subclass of AWSError representing something already existing.
    """
    error_types = [
        'EntityAlreadyExists',
        'LimitExceeded',
        'IncorrectState',
    ]


def _elide(s, max_len, ellipsis='...'):
    """
    Elide s in the middle to ensure it is under max_len.

    That is, shorten the string, inserting an ellipsis where the removed
    characters were to show that they've been removed.
    """
    if len(s) > max_len:
        hl = (max_len - len(ellipsis)) / 2
        headl, taill = floor(hl), ceil(hl)
        s = s[:headl] + ellipsis + s[-taill:]
    return s


def _aws(cmd, subcmd, *args):
    """
    Call the aws-cli tool.
    """
    cmd = ['aws', '--profile', 'juju', '--output', 'json', cmd, subcmd]
    cmd.extend(args)
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
        if output:
            output = json.loads(output.decode('utf8'))
        return output
    except subprocess.CalledProcessError as e:
        ae = AWSError.get(e.stderr.decode('utf8').strip())
        raise ae from e


def _build_query(collection, filter_attr, return_attr=None, model_uuid=None):
    """
    Build an entity filter query for the aws-cli tool.
    """
    if return_attr is None:
        return_attr = filter_attr
    if model_uuid is None:
        prefix = '{}.'.format(ENTITY_PREFIX)
    else:
        prefix = '{}.{}.'.format(ENTITY_PREFIX, model_uuid)
    return '{}[?starts_with({}, `{}`)].{}'.format(
        collection, filter_attr, prefix, return_attr)


def _list_roles(model_uuid=None):
    """
    Helper to list IAM roles, optionally filtering to the given model.
    """
    return _aws('iam', 'list-roles',
                '--query', _build_query('Roles',
                                        'RoleName',
                                        model_uuid=model_uuid))


def _list_instance_profiles(model_uuid=None):
    """
    Helper to list IAM instance-profiles, optionally filtering to the given
    model.
    """
    return _aws('iam', 'list-instance-profiles',
                '--query', _build_query('InstanceProfiles',
                                        'InstanceProfileName',
                                        model_uuid=model_uuid))


def _list_policies(model_uuid=None):
    """
    Helper to list IAM policies, optionally filtering to the given model.
    """
    return _aws('iam', 'list-policies',
                '--query', _build_query('Policies',
                                        'PolicyName',
                                        'Arn',
                                        model_uuid=model_uuid))


def _get_managed_entities():
    """
    Get the set of IAM entities managed by this charm instance.
    """
    return kv().get('charm.aws.managed-entities', {})


def _add_app_entity(app_name, entity_type, entity_name):
    """
    Add an IAM entity to the set managed by this charm instance.
    """
    managed_entities = _get_managed_entities()
    app_entities = managed_entities.setdefault(app_name, {
        'role': [],
        'instance-profile': [],
        'policy': [],
    })
    if entity_name not in app_entities[entity_type]:
        app_entities[entity_type].append(entity_name)
        _set_managed_entities(managed_entities)


def _set_managed_entities(managed_entities):
    """
    Update the cached set of IAM entities managed by this charm instance.
    """
    kv().set('charm.aws.managed-entities', managed_entities)


def _retry_for_entity_delay(func):
    """
    Retry the given function a few times if it raises a DoesNotExistAWSError
    with an increasing delay.

    It sometimes takes AWS a bit for new entities to be available, so this
    helper retries an AWS call a few times allowing for any of the errors
    that indicate that an entity is not available, which may be a temporary
    state after adding it.
    """
    for attempt in range(4):
        try:
            func()
            break
        except DoesNotExistAWSError as e:
            log(e.message)
            if attempt == 3:
                raise AWSError(None, 'Timed out waiting for entity')
            delay = 10 * (attempt + 1)
            log('Retrying in {} seconds', delay)
            sleep(delay)


def _apply_tags(region, resources, tags):
    """
    Apply the given tags to the given EC2 resources.
    """
    tags = ['Key={},Value={}'.format(key, value or '')
            for key, value in tags.items()]
    _aws(*(['ec2', 'create-tags'] +
           ['--region', region] +
           ['--resources'] + resources +
           ['--tags'] + tags))


def _attach_policy(policy_arn, role_name):
    """
    Ensure that the given IAM policy is attached to the given IAM role.
    """
    def _attach_role_policy():
        try:
            _aws('iam', 'attach-role-policy',
                 '--policy-arn', policy_arn,
                 '--role-name', role_name)
            log('Attached IAM policy {} to role {}', policy_arn, role_name)
        except AlreadyExistsAWSError:
            pass
    _retry_for_entity_delay(_attach_role_policy)


def _get_account_id():
    """
    Get the AWS account ID.
    """
    account_id = kv().get('charm.aws.account-id')
    if not account_id:
        account_id = _aws('sts', 'get-caller-identity',
                          '--query', 'Account')
        kv().set('charm.aws.account-id', account_id)
    return account_id


def _get_policy_arn(policy_name):
    """
    Translate a short policy name into an ARN and ensure that it is loaded.
    """
    policy_name = 'charm.aws.{}'.format(policy_name)
    account_id = _get_account_id()
    _ensure_policy(policy_name)
    return 'arn:aws:iam::{}:policy/{}'.format(account_id, policy_name)


def _ensure_policy(policy_name):
    """
    Ensure that the given policy is loaded into AWS.
    """
    policy_file = Path('files/policies/{}.json'.format(policy_name[10:]))
    policy_file_url = 'file://{}'.format(policy_file.absolute())
    try:
        _aws('iam', 'create-policy',
             '--policy-name', policy_name,
             '--policy-document', policy_file_url)
        log('Loaded IAM policy: {}', policy_name)
    except AlreadyExistsAWSError:
        pass


def _get_role_name(application_name, instance_id, region):
    """
    Get the instance-specific role name and ensure that it and the
    instance-profile exist and are connected up properly in AWS.
    """
    prefix = '{}.{}.'.format(ENTITY_PREFIX, MODEL_UUID)
    max_app_name_len = MAX_ROLE_NAME_LEN - len(prefix)
    app_name = _elide(application_name, max_app_name_len)
    role_name = prefix + app_name
    _ensure_role(application_name, role_name)
    _ensure_role_attached(role_name, instance_id, region)
    return role_name


def _ensure_role(application_name, role_name):
    """
    Ensure that the given role is created in AWS.
    """
    role_file = Path('files/role.json')
    role_file_url = 'file://{}'.format(role_file.absolute())
    try:
        _aws('iam', 'create-role',
             '--role-name', role_name,
             '--assume-role-policy-document', role_file_url)
        log('Created IAM role: {}', role_name)
    except AlreadyExistsAWSError:
        pass
    _add_app_entity(application_name, 'role', role_name)
    try:
        _aws('iam', 'create-instance-profile',
             '--instance-profile-name', role_name)
        log('Created IAM instance-profile: {}', role_name)
    except AlreadyExistsAWSError:
        pass
    _add_app_entity(application_name, 'instance-profile', role_name)

    def _add_role_to_instance_profile():
        try:
            _aws('iam', 'add-role-to-instance-profile',
                 '--role-name', role_name,
                 '--instance-profile-name', role_name)
            log('Attached IAM role {} to instance-profile {}',
                role_name, role_name)
        except AlreadyExistsAWSError:
            pass
    _retry_for_entity_delay(_add_role_to_instance_profile)


def _ensure_role_attached(role_name, instance_id, region):
    """
    Ensure that the given role is attached the corresponding instance-profile.
    """
    def _associate_iam_instance_profile():
        try:
            _aws('ec2', 'associate-iam-instance-profile',
                 '--iam-instance-profile', 'Name={}'.format(role_name),
                 '--instance-id', instance_id,
                 '--region', region)
            log('Attached IAM instance-profile {} to instance {} '
                'in region {}', role_name, instance_id, region)
        except AlreadyExistsAWSError:
            pass
    _retry_for_entity_delay(_associate_iam_instance_profile)


def _restrict_policy_for_app(policy_name, application_name, patterns):
    """
    Modify one of the general policies with application-specific resource
    patterns and return the new policy name.
    """
    non_app_name = '{}.{}..{}'.format(ENTITY_PREFIX, MODEL_UUID, policy_name)
    max_app_name_len = (MAX_POLICY_NAME_LEN - len(non_app_name))
    app_name = _elide(application_name, max_app_name_len)
    app_policy_name = '{}.{}.{}'.format(MODEL_UUID, app_name, policy_name)
    policy_file_src = Path('files/policies/{}.json'.format(policy_name))
    policy_file_dst = Path('files/policies/{}.json'.format(app_policy_name))
    policy_data = json.loads(policy_file_src.read_text())
    policy_data['Statement'][0]['Resource'] = patterns
    policy_file_dst.write_text(json.dumps(policy_data))
    return app_policy_name


def _cleanup_role(role_name):
    """
    Cleanup an IAM role.
    """
    try:
        policies = _aws('iam', 'list-attached-role-policies',
                        '--role-name', role_name,
                        '--query', 'AttachedPolicies[*].PolicyArn')
    except DoesNotExistAWSError:
        policies = []
    for policy_arn in policies:
        try:
            _aws('iam', 'detach-role-policy',
                 '--role-name', role_name,
                 '--policy-arn', policy_arn)
            log('Detached IAM policy {} from role {}', policy_arn, role_name)
        except DoesNotExistAWSError:
            pass
    try:
        _aws('iam', 'remove-role-from-instance-profile',
             '--role-name', role_name,
             '--instance-profile-name', role_name)
        log('Detached IAM role {} from instance-profile {}',
            role_name, role_name)
    except DoesNotExistAWSError:
        pass
    try:
        _aws('iam', 'delete-role',
             '--role-name', role_name)
        log('Deleted IAM role {}', role_name)
    except DoesNotExistAWSError:
        pass


def _cleanup_instance_profile(instance_profile_name):
    """
    Cleanup an IAM instance-profile.
    """
    try:
        _aws('iam', 'delete-instance-profile',
             '--instance-profile-name', instance_profile_name)
        log('Deleted IAM instance-profile {}', instance_profile_name)
    except DoesNotExistAWSError:
        pass


def _cleanup_policy(policy_arn):
    """
    Cleanup an IAM policy.
    """
    try:
        _aws('iam', 'delete-policy',
             '--policy-arn', policy_arn)
        log('Deleted IAM policy {}', policy_arn)
    except DoesNotExistAWSError:
        pass
