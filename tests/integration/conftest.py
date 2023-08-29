import pytest
import yaml


def pytest_addoption(parser):
    parser.addoption(
        "--series",
        type=str,
        default="",
        help="Set series for the machine units",
    )


@pytest.fixture(scope="module")
def k8s_core_bundle(ops_test):
    return ops_test.Bundle("kubernetes-core", channel="edge")


@pytest.fixture(scope="module")
@pytest.mark.asyncio
async def k8s_core_yaml(ops_test, k8s_core_bundle):
    """Download and render the kubernetes-core bundle, return it's full yaml"""
    (bundle_path,) = await ops_test.async_render_bundles(k8s_core_bundle)
    return yaml.safe_load(bundle_path.read_text())


@pytest.fixture(scope="module")
def series(k8s_core_yaml, request):
    series = request.config.getoption("--series")
    return series if series else k8s_core_yaml["series"]
