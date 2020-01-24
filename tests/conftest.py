import json
import pathlib

import kubernetes
import pytest
from pytest_bdd import given, parsers, then
import yaml

from tests import kube_utils
from tests import utils


# Pytest command-line options
def pytest_addoption(parser):
    parser.addoption(
        "--iso-root",
        action="store",
        default="_build/root",
        type=pathlib.Path,
        help="Root of the ISO file tree."
    )

# Fixtures {{{


@pytest.fixture(scope="module")
def version(request, host):
    iso_root = request.config.getoption("--iso-root")
    product_path = iso_root / "product.txt"
    with host.sudo():
        return host.check_output(
            'source %s && echo $VERSION', str(product_path)
        )

@pytest.fixture(scope="module")
def hostname(host):
    """Return the result of `hostname` on the `host` fixture.

    The hostname registered in the SSH config file may not match the one known
    by the server, especially if running tests locally.
    """
    return host.check_output('hostname')


@pytest.fixture(scope="module")
def nodename(host):
    """Return the kubernetes node name of the `host`

    Node name need to be equal to the salt minion id so just retrieve the
    salt minion id
    """
    with host.sudo():
        return host.check_output(
            'salt-call --local --out txt grains.get id | cut -c 8-'
        )


@pytest.fixture(scope="module")
def kubeconfig_data(request, host):
    """Fixture to generate a kubeconfig file for remote usage."""
    with host.sudo():
        kubeconfig_file = host.file('/etc/kubernetes/admin.conf')
        if not kubeconfig_file.exists:
            pytest.skip(
                "Must be run on bootstrap node, or have an existing file at "
                "/etc/kubernetes/admin.conf"
            )
        return yaml.safe_load(kubeconfig_file.content_string)


@pytest.fixture
def kubeconfig(kubeconfig_data, tmp_path):
    kubeconfig_path = tmp_path / "admin.conf"
    kubeconfig_path.write_text(yaml.dump(kubeconfig_data), encoding='utf-8')
    return str(kubeconfig_path)  # Need Python 3.6 to open() a Path object


@pytest.fixture
def k8s_apiclient(kubeconfig):
    """Return an ApiClient to use for interacting with all K8s APIs."""
    return kubernetes.config.new_client_from_config(
        config_file=kubeconfig, persist_config=False
    )


@pytest.fixture
def k8s_client(request, k8s_apiclient):
    """Parametrized fixture to instantiate a client for a single K8s API.

    By default, this will return a CoreV1Api client.
    One can decorate a test function to use another API, like so:

    ```
    @pytest.mark.parametrize(
        'k8s_client', ['AppsV1Api'], indirect=True
    )
    def test_something(k8s_client):
        assert k8s_client.list_namespaced_deployment(namespace="default")
    ```

    FIXME: this is not working as of right now, since `pytest-bdd` manipulates
    fixtures in its own way through the various scenario/when/then/given
    decorators.
    """
    api_name = getattr(request, "param", "CoreV1Api")
    api_cls = getattr(kubernetes.client, api_name, None)

    if api_cls is None:
        pytest.fail(
            "Unknown K8s API '{}' to use with `k8s_client` fixture.".format(
                api_name
            )
        )

    return api_cls(api_client=k8s_apiclient)


@pytest.fixture(scope='module')
def bootstrap_config(host):
    with host.sudo():
        config_file = host.file('/etc/metalk8s/bootstrap.yaml')
        if not config_file.exists:
            pytest.skip('Must be run on bootstrap node')
        return yaml.safe_load(config_file.content_string)


@pytest.fixture
def registry_address(host, version):
    with host.sudo():
        registry_json = host.check_output(
            "salt-call --out json slsutil.renderer string='"
            "{% from \"metalk8s/map.jinja\" import repo with context %}"
            "{{ repo.registry_endpoint }}' "
            "saltenv='metalk8s-" + str(version) + "'"
        )
    return json.loads(registry_json)["local"]


@pytest.fixture
def utils_image(registry_address, version):
    return "{registry_address}/{repository}/{image}".format(
        registry_address=registry_address,
        repository="metalk8s-{}".format(version),
        image="metalk8s-utils:{}".format(version)
    )


@pytest.fixture
def ssh_config(request):
    return request.config.getoption('--ssh-config')


def count_running_pods(
        request, k8s_client, pods_count, label, namespace, node):
    ssh_config = request.config.getoption('--ssh-config')

    def _check_pods_count():
        pods = kube_utils.get_pods(
            k8s_client, ssh_config, label, node,
            namespace=namespace, state="Running",
        )
        assert len(pods) == pods_count

    error_msg = (
        "There is not exactly '{count}' pod(s) labeled '{label}' running "
        "in namespace '{namespace}'"
        .format(count=pods_count, label=label, namespace=namespace)
    )
    if node:
        error_msg += "on node '{node}'".format(node=node)

    utils.retry(_check_pods_count, times=20, wait=3, error_msg=error_msg)


_COUNT_RUNNING_PODS_PARSER = parsers.re(
    r"we have (?P<pods_count>\d+) running pod labeled '(?P<label>[^']+)' "
    r"in namespace '(?P<namespace>[^']+)'(?: on node '(?P<node>[^']+)')?")


# }}}
# Given {{{

@given('the Kubernetes API is available')
def check_service(host):
    _verify_kubeapi_service(host)


@given(_COUNT_RUNNING_PODS_PARSER, converters=dict(pods_count=int))
def given_count_running_pods(
        request, k8s_client, pods_count, label, namespace, node):
    return count_running_pods(
        request, k8s_client, pods_count, label, namespace, node)


# }}}
# Then {{{

@then('the Kubernetes API is available')
def verify_kubeapi_service(host):
    _verify_kubeapi_service(host)


@then(_COUNT_RUNNING_PODS_PARSER, converters=dict(pods_count=int))
def then_count_running_pods(
        request, k8s_client, pods_count, label, namespace, node):
    return count_running_pods(
        request, k8s_client, pods_count, label, namespace, node)


@then(parsers.parse(
    "the '{resource}' list should not be "
    "empty in the '{namespace}' namespace"))
def check_resource_list(host, resource, namespace):
    with host.sudo():
        output = host.check_output(
            "kubectl --kubeconfig=/etc/kubernetes/admin.conf "
            "get %s --namespace %s -o custom-columns=:metadata.name",
            resource,
            namespace,
        )

    assert len(output.strip()) > 0, 'No {0} found in namespace {1}'.format(
            resource, namespace)


@then(parsers.parse('node "{node_name}" is a member of etcd cluster'))
def check_etcd_role(ssh_config, k8s_client, node_name):
    """Check if the given node is a member of the etcd cluster."""
    etcd_member_list = etcdctl(k8s_client, ['member', 'list'], ssh_config)
    assert node_name in etcd_member_list, \
        'node {} is not part of the etcd cluster'.format(node_name)

# }}}
# Helpers {{{

def _verify_kubeapi_service(host):
    """Verify that the kubeapi service answer"""
    with host.sudo():
        cmd = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf cluster-info'
        res = host.run(cmd)
        if res.rc != 0:
            pytest.fail(res.stderr)


def etcdctl(k8s_client, command, ssh_config):
    """Run an etcdctl command inside the etcd container."""
    name = 'etcd-{}'.format(
        utils.get_node_name('bootstrap', ssh_config)
    )

    etcd_command = [
        'etcdctl',
        '--endpoints', 'https://localhost:2379',
        '--ca-file', '/etc/kubernetes/pki/etcd/ca.crt',
        '--key-file', '/etc/kubernetes/pki/etcd/server.key',
        '--cert-file', '/etc/kubernetes/pki/etcd/server.crt',
    ] + command
    output = kubernetes.stream.stream(
        k8s_client.connect_get_namespaced_pod_exec,
        name=name, namespace='kube-system',
        command=etcd_command,
        stderr=True, stdin=False, stdout=True, tty=False
    )
    return output

# }}}
