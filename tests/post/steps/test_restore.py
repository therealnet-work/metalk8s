import os

from pytest_bdd import scenario, when

from tests import utils


# Scenarios
@scenario('../features/restore.feature', 'Restore the bootstrap node')
def test_restore(host):
    pass


# When
@when('we run the restore')
def run_restore(request, host, ssh_config):
    iso_root = request.config.getoption("--iso-root")

    backup_archive = os.environ.get('BOOTSTRAP_BACKUP_ARCHIVE')
    assert backup_archive, \
        "No BOOTSTRAP_BACKUP_ARCHIVE environment variable defined"

    apiserver_node_ip = utils.get_node_control_plane_ip('node1', ssh_config)

    with host.sudo():
        res = host.run(
            "%s/restore.sh --backup-archive %s --apiserver-node-ip %s",
            str(iso_root),
            backup_archive,
            apiserver_node_ip,
        )
        assert res.rc == 0, res.stdout
