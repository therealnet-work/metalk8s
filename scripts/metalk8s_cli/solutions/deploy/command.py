import json

from metalk8s_cli.mixins import log
from metalk8s_cli.mixins import salt
from metalk8s_cli import utils


class DeploySolutionCommand(salt.SaltCommandMixin, log.LoggingCommandMixin,
                            utils.Command):
    """Deploy a Solution's cluster-wide components.

    Namely, those components are the Admin UI, CRDs, StorageClasses, and may
    include Grafana dashboards in the future.
    """
    NAME = 'deploy'

    ARGUMENTS = {
        ('solution',): {},
        ('--latest',): {
            'action': 'store_true',
        },  # TODO: support mutex groups
        ('--use-version',): {},
        ('-d', '--delete',): {},
    }

    def __init__(self, args):
        super(DeploySolutionCommand, self).__init__(args)
        self.solutions_config = args.solutions_config
        self.solution = args.solution
        if args.latest:
            self.version = 'latest'
        else:
            self.version = args.use_version
        self.delete = args.delete
        self.saltenv = self.get_saltenv()

    def edit_config(self):
        if self.delete:
            self.solutions_config.deactivate_solution(self.solution)
            message = 'Disabled Solution "{}" in configuration file.'.format(
                self.solution
            )
        else:
            self.solutions_config.activate_solution_version(
                self.solution, self.version
            )
            message = (
                'Enabled version "{}" for Solution "{}" in configuration file.'
            ).format(self.version, self.solution)

        self.solutions_config.write_to_file()
        self.print_and_log(message, level='DEBUG')

    def run(self):
        with self.log_active_run():
            with self.log_step('Editing configuration file'):
                self.edit_config()

            with self.log_step('Deploying Solution components'):
                cmd_output = self.run_salt_master([
                    'state.orchestrate',
                    'metalk8s.orchestrate.solutions.deploy-components',
                    'saltenv={}'.format(self.saltenv),
                    "pillar='{{bootstrap_id: {}}}'".format(self.minion_id),
                ])
                self.print_and_log(cmd_output.decode('utf-8'), level='DEBUG')
