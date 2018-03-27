import json
import os
import re
import sys
import subprocess
import yaml
from time import sleep
from configparser import ConfigParser
from pathlib import Path

from charmhelpers.core import hookenv
from charmhelpers.core.unitdata import kv

from charms.layer import status


_roles = None


def log(msg, *args):
    hookenv.log(msg.format(*args), hookenv.INFO)


def log_err(msg, *args):
    hookenv.log(msg.format(*args), hookenv.ERROR)


def get_credentials():
    config = hookenv.config()
    access_key = config['access-key']
    secret_key = config['secret-key']
    if not (access_key and secret_key):
        try:
            result = subprocess.run(['credential-get'],
                                    check=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            creds = yaml.load(result.stdout.decode('utf8'))
            access_key = creds['credential']['attributes']['access-key']
            secret_key = creds['credential']['attributes']['secret-key']
        except subprocess.CalledProcessError as e:
            if 'permission denied' not in e.stderr.decode('utf8'):
                raise
            status.blocked('missing credentials access; '
                           'grant with: juju trust')
            return False
        except FileNotFoundError:
            status.blocked('missing credentials; '
                           'set access-key and secret-key config')
            return False
    update_credentials_file(access_key, secret_key)
    return True


def update_credentials_file(access_key, secret_key):
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
    log('Tagging instance {} in {} with: {}', instance_id, region, tags)
    _apply_tags(region, [instance_id], tags)


def tag_unit_security_group(instance_id, region, tags):
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
    log('Tagging subnet for instance {} in {} with: {}',
        instance_id, region, tags)
    subnet_id = _aws('ec2', 'describe-instances',
                     '--instance-ids', instance_id,
                     '--region', region,
                     '--query', 'Reservations[*]'
                                '.Instances[*]'
                                '.SubnetId[] | [0]')
    _apply_tags(region, [subnet_id], tags)


def enable_elb(application_name, instance_id, region):
    log('Enabling ELB for instance {} of application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('elb')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_ebs(application_name, instance_id, region):
    log('Enabling EBS for instance {} of application {} in region {}',
        instance_id, application_name, region)
    policy_arn = _get_policy_arn('ebs')
    role_name = _get_role_name(application_name, instance_id, region)
    _attach_policy(policy_arn, role_name)


def enable_route53(application_name, instance_id, region):
    pass


def enable_s3_read(application_name, instance_id, region):
    pass


def enable_s3_write(application_name, instance_id, region):
    pass


def cleanup(current_applications):
    log('Looking for unused AWS role and instance-profiles to cleanup')
    cached_roles = _get_roles()
    prefix = 'charm-aws-{}-'.format(os.environ['JUJU_MODEL_UUID'])
    query = 'Roles[?starts_with(RoleName, `{}`)].RoleName'.format(prefix)
    role_names = _aws('iam', 'list-roles', '--query', query)
    for role_name in role_names:
        application_name = role_name[len(prefix):]
        if application_name not in current_applications:
            log('Found: {}', role_name)
            _cleanup_role(role_name)
            cached_roles.pop(role_name, None)
    _update_roles()


# Internal helpers


class AWSError(Exception):
    def __init__(self, message):
        self.error_type = None
        self.message = message
        match = re.match(r'An error occurred \(([^)]+)\)', message)
        if match:
            self.error_type = match.group(1)
        super().__init__(message)

    def __str__(self):
        return self.message


def _aws(cmd, subcmd, *args, ignore_errors=False):
    cmd = ['aws', '--profile', 'juju', '--output', 'json', cmd, subcmd]
    cmd.extend(args)
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.PIPE)
        if output:
            output = json.loads(output.decode('utf8'))
        return output
    except subprocess.CalledProcessError as e:
        ae = AWSError(e.stderr.decode('utf8').strip())
        if ignore_errors is True or ae.error_type in (ignore_errors or []):
            return None
        log_err(ae.message)
        raise ae from e


def _apply_tags(region, resources, tags):
    tags = ['Key={},Value={}'.format(key, value or '')
            for key, value in tags.items()]
    _aws(*['ec2', 'create-tags'] +
          ['--region', region] +
          ['--resources'] + resources +
          ['--tags'] + tags)


def _attach_policy(policy_arn, role_name):
    for attempt in range(3):
        try:
            log('Attaching IAM policy {} to role {}', policy_arn, role_name)
            _aws('iam', 'attach-role-policy',
                 '--policy-arn', policy_arn,
                 '--role-name', role_name)
            break
        except AWSError as e:
            if e.error_type not in {'NoSuchEntity', 'InvalidParameterValue'}:
                raise
            # it sometimes takes AWS a bit for new entities to be available
            delay = 10 * (attempt + 1)
            log('Retrying in {} seconds', delay)
            sleep(delay)
    else:
        raise AWSError('Timed out waiting for entity')


def _get_account_id():
    account_id = kv().get('charm.aws.account-id')
    if not account_id:
        account_id = _aws('sts', 'get-caller-identity',
                          '--query', 'Account')
        kv().set('charm.aws.account-id', account_id)
    return account_id


def _get_policy_arn(policy_name):
    policy_name = 'charm-aws-{}'.format(policy_name)
    account_id = _get_account_id()
    _ensure_policy(policy_name)
    return 'arn:aws:iam::{}:policy/{}'.format(account_id, policy_name)


def _ensure_policy(policy_name):
    policies = kv().get('charm.aws.policies', [])
    if policy_name not in policies:
        _load_policy(policy_name)
        policies.append(policy_name)
        kv().set('charm.aws.policies', policies)


def _load_policy(policy_name):
    policy_file = Path('files/policies/{}.json'.format(policy_name[10:]))
    policy_file_url = 'file://{}'.format(policy_file.absolute())
    log('Loading IAM policy: {}', policy_name)
    _aws('iam', 'create-policy',
         '--policy-name', policy_name,
         '--policy-document', policy_file_url,
         ignore_errors=['EntityAlreadyExists'])


def _get_role_name(application_name, instance_id, region):
    if len(application_name) > 17:
        # role names can be max 64 characters, and application name length is
        # effective arbitrary, so elide it down to 17 chars (prefix + UUID
        # take up 47 chars, and adding the ellipsis in the middle should make
        # it less likely to conflict than truncating)
        application_name = '...'.join([application_name[:7],
                                       application_name[-7:]])
    role_name = 'charm-aws-{}-{}'.format(os.environ['JUJU_MODEL_UUID'],
                                         application_name)
    _ensure_role(role_name, application_name)
    _ensure_role_attached(role_name, instance_id, region)
    return role_name


def _get_roles():
    global _roles
    if _roles is None:
        _roles = kv().get('charm.aws.roles', {})
    return _roles


def _update_roles():
    kv().set('charm.aws.roles', _roles)


def _ensure_role(role_name, application_name):
    roles = _get_roles()
    if role_name not in roles:
        _create_role(role_name)
        roles[role_name] = []
        _update_roles()


def _create_role(role_name):
    role_file = Path('files/role.json')
    role_file_url = 'file://{}'.format(role_file.absolute())
    log('Creating IAM role: {}', role_name)
    _aws('iam', 'create-role',
         '--role-name', role_name,
         '--assume-role-policy-document', role_file_url,
         ignore_errors=['EntityAlreadyExists'])
    log('Creating IAM instance-profile: {}', role_name)
    _aws('iam', 'create-instance-profile',
         '--instance-profile-name', role_name,
         ignore_errors=['EntityAlreadyExists'])
    for attempt in range(3):
        try:
            log('Attaching IAM role {} to instance-profile {}',
                role_name, role_name)
            _aws('iam', 'add-role-to-instance-profile',
                 '--role-name', role_name,
                 '--instance-profile-name', role_name,
                 ignore_errors=['LimitExceeded'])  # aka, already added
            break
        except AWSError as e:
            if e.error_type not in {'NoSuchEntity', 'InvalidParameterValue'}:
                raise
            # it sometimes takes AWS a bit for new entities to be available
            delay = 10 * (attempt + 1)
            log('Retrying in {} seconds', delay)
            sleep(delay)
    else:
        raise AWSError('Timed out waiting for entity')


def _ensure_role_attached(role_name, instance_id, region):
    roles = _get_roles()
    instance_key = '{}-{}'.format(instance_id, region)
    if instance_key not in roles[role_name]:
        _attach_role(role_name, instance_id, region)
        roles[role_name].append(instance_key)
        _update_roles()


def _attach_role(role_name, instance_id, region):
    for attempt in range(3):
        try:
            log('Attaching IAM instance-profile {} to instance {} '
                'in region {}', role_name, instance_id, region)
            _aws('ec2', 'associate-iam-instance-profile',
                 '--iam-instance-profile', 'Name={}'.format(role_name),
                 '--instance-id', instance_id,
                 '--region', region,
                 ignore_errors=['IncorrectState'])  # aka, already attached
            break
        except AWSError as e:
            if e.error_type not in {'NoSuchEntity', 'InvalidParameterValue'}:
                raise
            # it sometimes takes AWS a bit for new entities to be available
            delay = 10 * (attempt + 1)
            log('Retrying in {} seconds', delay)
            sleep(delay)
    else:
        raise AWSError('Timed out waiting for entity')


def _cleanup_role(role_name):
    policies = _aws('iam', 'list-attached-role-policies',
                    '--role-name', role_name,
                    '--query', 'AttachedPolicies[*].PolicyArn')
    for policy_arn in policies:
        log('Detaching IAM policy {} from role {}', policy_arn, role_name)
        _aws('iam', 'detach-role-policy',
             '--role-name', role_name,
             '--policy-arn', policy_arn)
    log('Detaching IAM role from instance-profile {}', role_name, role_name)
    _aws('iam', 'remove-role-from-instance-profile',
         '--role-name', role_name,
         '--instance-profile-name', role_name,
         ignore_errors=['NoSuchEntity'])
    log('Deleting IAM role {}', role_name)
    _aws('iam', 'delete-role',
         '--role-name', role_name,
         ignore_errors=['NoSuchEntity'])
    log('Deleting IAM instance-profile {}', role_name)
    _aws('iam', 'delete-instance-profile',
         '--instance-profile-name', role_name,
         ignore_errors=['NoSuchEntity'])


def _cleanup_policy(policy_arn):
    log('Deleting IAM policy {}', policy_arn)
    _aws('iam', 'delete-policy',
         '--policy-arn', policy_arn)
