import os
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
    subprocess.check_call(cmd)


def tag_instance(instance_id, region, tags):
    _aws('ec2', 'create-tags', '--resources', instance_id, '--region', region,
         '--tags', *['Key={},Value={}'.format(key, value or '')
                     for key, value in tags.items()])


def tag_security_group(instance_id, region, tags):
    pass


def tag_subnet(instance_id, region, tags):
    pass


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
