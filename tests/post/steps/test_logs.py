import re

from pytest_bdd import scenario, then

from tests import kube_utils, utils

# Scenarios
@scenario('../features/log_accessible.feature',
          'check logs from all containers')
def test_logs(host):
    pass


# Some sidecar containers don't have logs
SKIP_CONTAINERS = frozenset((
    'config-reloader',
    'kube-rbac-proxy',
    'kube-rbac-proxy-main',
    'kube-rbac-proxy-self',
    'rules-configmap-reloader',
    'nginx-ingress-default-backend',
))


@then("all Pod logs should be non-empty")
def check_logs(k8s_client):
    pod_status = 'Running'
    all_pods = k8s_client.list_pod_for_all_namespaces()

    for pod in all_pods.items:
        pod_name = pod.metadata.name
        namespace = pod.metadata.namespace

        for container in pod.spec.containers:
            if container.name in SKIP_CONTAINERS:
                continue

            if pod.status.phase != pod_status:
                # Wait for the Pod to be ready
                utils.retry(
                    kube_utils.check_pod_status(
                        k8s_client,
                        name=pod_name,
                        namespace=namespace,
                        state=pod_status
                    ),
                    times=12,
                    wait=5,
                    name="wait for Pod '{}'".format(pod_name),
                )
            logs = k8s_client.read_namespaced_pod_log(
                pod_name,
                namespace,
                container=container.name
            )

            assert logs.strip(), (
                "Couldn't find logs for container '{}' in Pod '{}' (status {})"
            ).format(container.name, pod_name, pod.status.phase)
