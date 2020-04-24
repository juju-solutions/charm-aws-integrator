from charms import layer

from reactive.aws import pre_series_upgrade


def test_series_upgrade():
    assert layer.status.blocked.call_count == 0
    pre_series_upgrade()
    assert layer.status.blocked.call_count == 1
