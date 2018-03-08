import os
import re
import subprocess
from configparser import ConfigParser
from pathlib import Path


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


def _aws(cmd, subcmd, *args, **kwargs):
    cmd = ['aws', '--profile', 'juju', cmd, subcmd]
    for key, value in kwargs.items():
        cmd.extend(('--{}'.format(key.replace('_', '-')), str(value)))
    cmd.extend(args)
    return subprocess.check_output(cmd).decode('utf8')


def _apply_tags(region, resources, tags):
    tags = ['Key={},Value={}'.format(key, value or '')
            for key, value in tags.items()]
    _aws(*['ec2', 'create-tags'] +
          ['--region', region] +
          ['--resources'] + resources +
          ['--tags'] + tags)


def tag_instance(instance_id, region, tags):
    _apply_tags(region, [instance_id], tags)


def tag_instance_security_group(instance_id, region, tags):
    groups = _aws('ec2', 'describe-instances', '--output', 'text',
                  '--instance-ids', instance_id, '--region', region,
                  '--query', ('Reservations[*]'
                              '.Instances[*]'
                              '.SecurityGroups[*]'
                              '.[GroupId,GroupName]'))
    groups = [line.split() for line in groups.splitlines()]
    group_ids = [group_id for group_id, group_name in groups
                 if re.match(r'^juju-.*-\d+$', group_name)]
    _apply_tags(region, group_ids, tags)


def tag_instance_subnet(instance_id, region, tags):
    subnet_id = _aws('ec2', 'describe-instances', '--output', 'text',
                     '--instance-ids', instance_id, '--region', region,
                     '--query', ('Reservations[*]'
                                 '.Instances[*]'
                                 '.SubnetId')).strip()
    _apply_tags(region, [subnet_id], tags)


def enable_elb(instance_id, region):
    pass


def enable_ebs(instance_id, region):
    pass


def enable_route53(instance_id, region):
    pass


def enable_s3_read(instance_id, region):
    pass


def enable_s3_write(instance_id, region):
    pass
