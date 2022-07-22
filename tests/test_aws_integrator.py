from unittest.mock import MagicMock, Mock
import pytest

from charms.unit_test import patch_fixture

# auto-patched
from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charms import layer

from charms.layer import aws as layer_aws
from reactive import aws as reactive_aws


_aws = patch_fixture("charms.layer.aws._aws")
mysql_api = patch_fixture("charms.layer.aws.MySQLRDSManager")


def test_series_upgrade():
    assert layer.status.blocked.call_count == 0
    reactive_aws.pre_series_upgrade()
    assert layer.status.blocked.call_count == 1


@pytest.fixture
def mock_kv():
    orig = unitdata.kv.return_value
    unitdata.kv.return_value = MagicMock()
    yield unitdata.kv.return_value
    unitdata.kv.return_value = orig


def test_rds_mysql_api(_aws, mock_kv):
    hookenv.config.return_value = {
        "rds-mysql-port": 3306,
        "rds-mysql-storage": 20,
        "rds-mysql-instance-class": "db.t3.small",
    }
    mock_kv.get.return_value = {}
    mysql_rds = layer_aws.MySQLRDSManager()
    _aws.side_effect = [
        {"SecurityGroups": [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}]},
        None,
        {
            "DBInstances": [
                {
                    "DBInstanceStatus": "available",
                    "Endpoint": {"Address": "address"},
                }
            ]
        },
        None,
    ]
    mysql_rds.create_db("1")
    assert len(mysql_rds.failed_creates) == 0
    assert len(mysql_rds.pending) == 1
    assert len(mysql_rds.active) == 0
    assert mock_kv.set.call_count == 1
    mysql_rds.poll_pending()
    assert len(mysql_rds.pending) == 0
    assert len(mysql_rds.active) == 1
    assert mock_kv.set.call_count == 2
    mysql_rds.delete_db("1")
    assert len(mysql_rds.failed_deletes) == 0
    assert len(mysql_rds.active) == 0
    assert len(mysql_rds.pending) == 0
    assert mock_kv.set.call_count == 3


def test_rds_mysql_handle_requests(mysql_api):
    mgr = Mock(active={}, pending={}, failed_creates=set(), failed_deletes={})
    mysql_api.return_value = mgr
    reactive_aws.handle_mysql_requests()
