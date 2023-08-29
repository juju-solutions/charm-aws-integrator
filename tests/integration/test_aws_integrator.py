import asyncio
import logging
from pathlib import Path
import pytest
import shlex
from typing import List
from lightkube import AsyncClient
from lightkube.config.kubeconfig import KubeConfig
from lightkube.codecs import load_all_yaml
from lightkube.resources.core_v1 import Node, PersistentVolumeClaim, Pod

log = logging.getLogger(__name__)
K8S_CP = "kubernetes-control-plane"


@pytest.fixture(scope="module")
async def kubeconfig(ops_test):
    kubeconfig_path = ops_test.tmp_path / "kubeconfig"
    retcode, stdout, stderr = await ops_test.juju(
        "ssh", f"{K8S_CP}/leader", "--", "cat", "config"
    )
    if retcode != 0:
        log.error(f"retcode: {retcode}")
        log.error(f"stdout:\n{stdout.strip()}")
        log.error(f"stderr:\n{stderr.strip()}")
        pytest.fail("Failed to copy kubeconfig from kubernetes-control-plane")
    assert stdout, "kubeconfig file is 0 bytes"
    kubeconfig_path.write_text(stdout)
    yield kubeconfig_path


@pytest.fixture(scope="module")
async def lk_client(kubeconfig):
    yield AsyncClient(config=KubeConfig.from_file(kubeconfig))


@pytest.fixture()
async def pvc_and_pod(lk_client):
    objects = load_all_yaml(Path("tests/data/bind_pvc.yaml").read_text())
    for obj in objects:
        await lk_client.create(obj, obj.metadata.name, namespace=obj.metadata.namespace)

    yield objects

    for obj in reversed(objects):
        await lk_client.delete(
            type(obj), obj.metadata.name, namespace=obj.metadata.namespace
        )


@pytest.mark.abort_on_fail
@pytest.mark.skip_if_deployed
async def test_build_and_deploy(ops_test, k8s_core_bundle, series):
    charm = next(Path.cwd().glob("aws-integrator*.charm"), None)
    if not charm:
        log.info("Build Charm...")
        charm = await ops_test.build_charm(".")

    context = dict(charm=charm, series=series)
    overlays = [
        k8s_core_bundle,
        Path("tests/data/charm.yaml"),
    ]
    bundle, *overlays = await ops_test.async_render_bundles(*overlays, **context)
    log.info("Deploy Charm...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} --trust " + " ".join(
        f"--overlay={f}" for f in overlays
    )
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"
    log.info(stdout)
    await ops_test.model.block_until(
        lambda: "aws-integrator" in ops_test.model.applications, timeout=60
    )
    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)


@pytest.mark.abort_on_fail
async def test_provider_ids(ops_test, lk_client: AsyncClient):
    """Tests that every node has a provider id."""
    kubelet_apps = [K8S_CP, "kubernetes-worker"]
    unit_args = await get_kubelet_args(ops_test, kubelet_apps)
    log.info("provider-ids from kubelet are %s.", unit_args)

    has_cp = all(args.get("--cloud-provider") for args in unit_args.values())
    if not has_cp:
        log.info("cloud-provider not found without reconfiguring kubelets.")
        # reconfigure kubelets to ensure they have provider-id arg
        key = "kubelet-extra-args"
        await asyncio.gather(
            *(
                ops_test.model.applications[app].set_config({key: "v=1"})
                for app in kubelet_apps
            )
        )
        # Allow time for the cluster to apply the providerID
        await ops_test.model.wait_for_idle(wait_for_active=True, timeout=5 * 60)

        # Gather the cloud-provider again
        unit_args = await get_kubelet_args(ops_test, kubelet_apps)
        log.info("now args from kubelet are %s.", unit_args)

        # Confirm each unit has a provider-id
        has_cp = all(args.get("--cloud-provider") for args in unit_args.values())
    assert has_cp, "Every node should have a cloud-provider, not empty"

    nodes = await get_node_provider_ids(lk_client)
    assert all(nodes.values()), "All nodes should have a providerID"


async def test_pvc_creation(lk_client, pvc_and_pod):
    async def _wait_til_bound():
        async for _, dep in lk_client.watch(PersistentVolumeClaim, namespace=ns):
            if dep.status.phase != "Bound" or not dep.spec.volumeName:
                continue
            pod = await lk_client.get(Pod, name=pod_name, namespace=ns)
            pvcs = [
                _.persistentVolumeClaim.claimName
                for _ in pod.spec.volumes
                if _.persistentVolumeClaim
            ]
            if pvc.metadata.name in pvcs:
                return

    pvc, pod = pvc_and_pod
    pod_name = pod.metadata.name
    ns = pvc.metadata.namespace
    await asyncio.wait_for(_wait_til_bound(), timeout=1 * 60)


async def get_kubelet_args(ops_test, kubelet_apps: List[str]):
    async def unit_kubelet_args(unit):
        cmd = f"exec -u {unit.name} -- pgrep -la kubelet"
        rc, stdout, _ = await ops_test.juju(*shlex.split(cmd))
        if rc == 0:
            _, kubelet_cmd = stdout.split(" ", 1)
            _, *args = shlex.split(kubelet_cmd)
            return dict(arg.split("=", 1) for arg in args)
        return {}

    return {
        unit.name: await unit_kubelet_args(unit)
        for app in kubelet_apps
        for unit in ops_test.model.applications[app].units
    }


async def get_node_provider_ids(lk_client):
    lister = lk_client.list(Node)
    node_list = {}
    try:
        async for node in lister:
            node_list[node.metadata.name] = getattr(node.spec, "providerID", None)
    finally:
        await lister.aclose()
    return node_list
