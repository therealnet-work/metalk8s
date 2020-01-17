import json
import pathlib
import string

import pytest
from pytest_bdd import scenario, then, parsers, when
import testinfra
import kubernetes as k8s
import yaml

from tests import kube_utils
from tests import utils
from tests import versions

# Scenarios
@scenario('../features/expansion.feature', 'Add one node to the cluster')
def test_cluster_expansion(host):
    pass


@scenario('../features/expansion.feature', 'ETCD failover on multi-member')
def test_etcd_failover_on_multi_member(host):
    pass

# When {{{

@when(parsers.parse('we declare a new "{node_type}" node on host "{hostname}"'))
def declare_node(
    ssh_config, version, k8s_client, node_type, hostname, bootstrap_config
):
    """Declare the given node in Kubernetes."""
    node_ip = get_node_ip(hostname, ssh_config, bootstrap_config)
    node_name = utils.resolve_hostname(hostname, ssh_config)
    node_manifest = get_node_manifest(
        node_type, version, node_ip, node_name
    )
    k8s_client.create_node(body=node_from_manifest(node_manifest))


@when(parsers.parse('we deploy the node "{name}"'))
def deploy_node(host, ssh_config, version, name):
    node_name = utils.resolve_hostname(name, ssh_config)
    accept_ssh_key = [
        'salt-ssh', '-i', node_name, 'test.ping', '--roster=kubernetes'
    ]
    pillar = {'orchestrate': {'node_name': node_name}}
    deploy = [
        'salt-run', 'state.orchestrate', 'metalk8s.orchestrate.deploy_node',
        'saltenv=metalk8s-{}'.format(version),
        "pillar='{}'".format(json.dumps(pillar))
    ]
    run_salt_command(host, accept_ssh_key, ssh_config)
    run_salt_command(host, deploy, ssh_config)


@when(parsers.parse('we remove "{node_name}" from the etcd cluster'))
def remove_etcd_node(ssh_config, k8s_client, node_name):
    node_id = node_name
    node_name = utils.resolve_hostname(node_name, ssh_config)
    etcd_member_id = get_etcd_member_id(k8s_client, ssh_config, node_id)
    if etcd_member_id is None:
        pytest.fail(
            "unable to get etcd member ID for node {}".format(node_name)
        )
    try:
        etcd_member_remove = etcdctl(
            k8s_client, ['member', 'remove'], ssh_config, etcd_member_id
        )
    except Exception as exc:
        raise

    if etcd_member_remove:
        etcd_member_list = etcdctl(
            k8s_client, ['member', 'list'], ssh_config, node_id
        )
        assert node_name not in etcd_member_list, \
            'node {} is still part of the etcd cluster'.format(node_name)
    else:
        pytest.fail("Unable to remove etcd member {}".format(node_name))


# }}}
# Then {{{

@then(parsers.parse('node "{hostname}" is registered in Kubernetes'))
def check_node_is_registered(ssh_config, k8s_client, hostname):
    """Check if the given node is registered in Kubernetes."""
    node_name = utils.resolve_hostname(hostname, ssh_config)
    try:
        k8s_client.read_node(node_name)
    except k8s.client.rest.ApiException as exn:
        pytest.fail(str(exn))


@then(parsers.parse('node "{hostname}" status is "{expected_status}"'))
def check_node_status(ssh_config, k8s_client, hostname, expected_status):
    """Check if the given node has the expected status."""
    node_name = utils.resolve_hostname(hostname, ssh_config)

    def _check_node_status():
        try:
            status = k8s_client.read_node_status(node_name).status
        except k8s.client.rest.ApiException as exn:
            raise AssertionError(exn)
        # If really not ready, status may not have been pushed yet.
        if status.conditions is None:
            assert expected_status == 'NotReady'
            return

        for condition in status.conditions:
            if condition.type == 'Ready':
                break
        assert kube_utils.MAP_STATUS[condition.status] == expected_status

    utils.retry(
        _check_node_status,
        times=10, wait=5,
        name="check node '{}' status".format(node_name)
    )


@then(parsers.parse('node "{node_name}" is a member of etcd cluster'))
def check_etcd_role(ssh_config, k8s_client, node_name):
    """Check if the given node is a member of the etcd cluster."""
    node_name = utils.resolve_hostname(node_name, ssh_config)
    node_id = "bootstrap"
    etcd_member_list = etcdctl(
        k8s_client, ['member', 'list'], ssh_config, node_id
    )
    assert node_name in etcd_member_list, \
        'node {} is not part of the etcd cluster'.format(node_name)


# }}}
# Helpers {{{

def kubectl_exec(
    host,
    command,
    pod,
    kubeconfig='/etc/kubernetes/admin.conf',
    **kwargs
):
    """Grab the return code from a `kubectl exec`"""
    kube_args = ['--kubeconfig', kubeconfig]

    if kwargs.get('container'):
        kube_args.extend(['-c', kwargs.get('container')])
    if kwargs.get('namespace'):
        kube_args.extend(['-n', kwargs.get('namespace')])

    kubectl_cmd_tplt = 'kubectl exec {} {} -- {}'

    with host.sudo():
        output = host.run(
            kubectl_cmd_tplt.format(
                pod,
                ' '.join(kube_args),
                ' '.join(command)
            )
        )
        return output

def get_node_ip(hostname, ssh_config, bootstrap_config):
    """Return the IP of the node `hostname`.
    We have to jump through hoops because `testinfra` does not provide a simple
    way to get this information…
    """
    infra_node = testinfra.get_host(hostname, ssh_config=ssh_config)
    control_plane_cidr = bootstrap_config['networks']['controlPlane']
    return utils.get_ip_from_cidr(infra_node, control_plane_cidr)

def get_node_manifest(node_type, metalk8s_version, node_ip, node_name):
    """Return the YAML to declare a node with the specified IP."""
    filename = '{}-node.yaml.tpl'.format(node_type)
    filepath = (pathlib.Path(__file__)/'..'/'files'/filename).resolve()
    manifest = filepath.read_text(encoding='utf-8')
    return string.Template(manifest).substitute(
        metalk8s_version=metalk8s_version, node_ip=node_ip, node_name=node_name
    )

def node_from_manifest(manifest):
    """Create V1Node object from a YAML manifest."""
    manifest = yaml.safe_load(manifest)
    manifest['api_version'] = manifest.pop('apiVersion')
    return k8s.client.V1Node(**manifest)

def run_salt_command(host, command, ssh_config):
    """Run a command inside the salt-master container."""

    pod = 'salt-master-{}'.format(
        utils.resolve_hostname('bootstrap', ssh_config)
    )

    output = kubectl_exec(
        host,
        command,
        pod,
        container='salt-master',
        namespace='kube-system'
    )

    assert output.exit_status == 0, \
        'deploy failed with: \nout: {}\nerr:'.format(
            output.stdout,
            output.stderr
        )

def etcdctl(k8s_client, command, ssh_config, node_id):
    """Run an etcdctl command inside the etcd container."""
    name = 'etcd-{}'.format(
        utils.resolve_hostname(node_id, ssh_config)
    )
    etcd_command = [
        'etcdctl',
        '--endpoints', 'https://localhost:2379',
        '--ca-file', '/etc/kubernetes/pki/etcd/ca.crt',
        '--key-file', '/etc/kubernetes/pki/etcd/server.key',
        '--cert-file', '/etc/kubernetes/pki/etcd/server.crt',
    ] + command
    output = k8s.stream.stream(
        k8s_client.connect_get_namespaced_pod_exec,
        name=name, namespace='kube-system',
        command=etcd_command,
        stderr=True, stdin=False, stdout=True, tty=False
    )
    return output


def get_etcd_member_id(k8s_client, ssh_config, node_id):
    """Returns an etcd member ID"""
    try:
        etcd_member_list = etcdctl(
            k8s_client, ['member', 'list'], ssh_config, node_id
        )
        # the member list above output is:
        # 4b6029846830dc61: name=metalk8s-zzpcc-bootstrap.novalocal peerURLs=https://10.100.1.44:2380 clientURLs=https://10.100.1.44:2379 isLeader=true
        # 6550922484a42d67: name=metalk8s-zzpcc-node-1.novalocal peerURLs=https://10.100.2.93:2380 clientURLs=https://10.100.2.93:2379 isLeader=false
        # f000a963d764c8e: name=metalk8s-zzpcc-node-2.novalocal peerURLs=https://10.100.2.97:2380 clientURLs=https://10.100.2.97:2379 isLeader=false
    except Exception as exc:
        raise

    for member in etcd_member_list.splitlines():
        if node_name in member:
            return member.split(':')[0]
        else:
            return None

# }}}
