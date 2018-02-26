import os
from configparser import ConfigParser
from pathlib import Path


def update_credentials_file(access_key, secret_key):
    conf_dir = Path('/root/.aws')
    conf_dir.mkdir(0o700, exist_ok=True)
    conf_file = conf_dir / 'credentials'
    config = ConfigParser()
    if conf_file.exists():
        config.read(str(conf_file))
    if 'default' not in config.sections():
        config.add_section('default')
    config['default']['aws_access_key_id'] = access_key
    config['default']['aws_secret_key'] = secret_key
    with conf_file.open('w') as fp:
        os.fchmod(fp.fileno(), 0o600)
        config.write(fp)


def tag_instance(instance_id, tags):
    pass


def tag_security_group(instance_id, tags):
    pass


def tag_subnet(instance_id, tags):
    pass


def enable_elb(instance_id):
    pass


def enable_ebs(instance_id):
    pass


def enable_route53(instance_id):
    pass


def enable_s3_read(instance_id):
    pass


def enable_s3_write(instance_id):
    pass
