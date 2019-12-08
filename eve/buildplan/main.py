"""Generate the Eve YAML description of build plan for MetalK8s."""
import pathlib
import sys

from buildplan import core
from buildplan import dsl
from buildplan import shell
from buildplan import yamlprint


def build_project():
    project = core.Project()
    project.add(pre_merge())
    return project


# Stages {{{
@dsl.WithStatus(is_root=True)
def pre_merge():
    return core.Stage(
        name="pre-merge",
        worker=core.LocalWorker(),
        branches=[
            "user/*",
            "feature/*",
            "improvement/*",
            "bugfix/*",
            "w/*",
            "q/*",
            "hotfix/*",
            "dependabot/*",
            "documentation/*",
            "release/*",
        ],
        steps=[
            core.TriggerStages(
                "Trigger build, docs, and lint stages",
                stages=[build(), docs(), lint()],
            ),
            set_version_property(),
            core.TriggerStages(
                "Trigger single-node and multiple-nodes steps with built ISO",
                stages=[single_node(), multiple_nodes()],
            ),
        ],
    )


@dsl.WithStatus()
@dsl.WithArtifacts(urls=["metalk8s.iso", "SHA256SUM", "product.txt"])
@dsl.WithSetup([dsl.SetupStep.DOCKER, dsl.SetupStep.GIT, dsl.SetupStep.CACHE])
def build():
    return core.Stage(
        name="build",
        worker=core.KubePodWorker(
            path="eve/workers/pod-builder/pod.yaml",
            images=[
                core.KubePodWorker.Image(
                    name="docker-builder", context="eve/workers/pod-builder"
                )
            ],
        ),
        steps=[
            build_all(),
            *dsl.copy_artifacts(
                [
                    "build.log",
                    "_build/metalk8s.iso",
                    "_build/SHA256SUM",
                    "_build/root/product.txt",
                ]
            ),
        ],
    )


@dsl.WithStatus()
@dsl.WithArtifacts(urls=["docs/html/index.html", "docs/latex/MetalK8s.pdf"])
@dsl.WithSetup([dsl.SetupStep.GIT, dsl.SetupStep.CACHE])
def docs():
    return core.Stage(
        name="docs",
        worker=core.KubePodWorker(
            path="eve/workers/pod-docs-builder/pod.yaml",
            images=[
                core.KubePodWorker.Image(
                    name="doc-builder",
                    context=".",
                    dockerfile="docs/Dockerfile",
                )
            ],
        ),
        steps=[
            build_docs(),
            *dsl.copy_artifacts(["docs/_build/*"], destination="docs",),
        ],
    )


@dsl.WithStatus()
@dsl.WithSetup([dsl.SetupStep.GIT, dsl.SetupStep.CACHE])
def lint():
    return core.Stage(
        name="lint",
        worker=core.KubePodWorker(
            path="eve/workers/pod-linter/pod.yaml",
            images=[
                core.KubePodWorker.Image(
                    name="docker-linter", context="eve/workers/pod-linter"
                )
            ],
        ),
        steps=[lint_all()],
    )


@dsl.WithStatus()
@dsl.WithArtifacts(urls=["sosreport/single-node-downgrade-centos"])
@dsl.WithSetup([dsl.SetupStep.GIT, dsl.SetupStep.CACHE, dsl.SetupStep.SSH])
def single_node():
    return core.Stage(
        name="single-node",
        worker=core.OpenStackWorker(
            path="eve/workers/openstack-single-node",
            flavor=core.OpenStackWorker.Flavor.LARGE,
            image=core.OpenStackWorker.Image.CENTOS7,
        ),
        steps=[
            *get_iso_from_artifacts(),
            *prepare_bootstrap(),
            install_bootstrap(),
            provision_prometheus_volumes(),
            run_tests(
                "Run fast tests locally",
                mode="local",
                filters="post and ci and not multinode and not slow",
            ),
            run_tests(
                "Run slow tests locally",
                mode="local",
                filters="post and ci and not multinode and slow",
            ),
            run_cypress_tests(),
            *dsl.copy_artifacts(
                {
                    "ui/cypress": [
                        "ui/cypress/screenshots",
                        "ui/cypress/videos",
                    ],
                    "ui": ["ui/junit"],
                }
            ),
            collect_sosreport(),
            *dsl.copy_artifacts(
                ["/var/tmp/sosreport*"], destination="sosreport/single-node",
            ),
        ],
    )


@dsl.WithStatus()
@dsl.WithArtifacts(urls=["sosreport/multiple-nodes"])
@dsl.WithSetup(
    [
        dsl.SetupStep.GIT,
        dsl.SetupStep.CACHE,
        dsl.SetupStep.SSH,
        dsl.SetupStep.CHECK_DEPS,
    ]
)
@dsl.WithTerraform(tf_vars={"nodes_count": "2"}, setup_bastion=True)
def multiple_nodes():
    ssh_config = "eve/workers/openstack-multiple-nodes/terraform/ssh_config"

    return core.Stage(
        name="multiple-nodes",
        worker=core.OpenStackWorker(
            path="eve/workers/openstack-multiple-nodes",
            flavor=core.OpenStackWorker.Flavor.MEDIUM,
            image=core.OpenStackWorker.Image.CENTOS7,
        ),
        steps=[
            *dsl.on_remote(host="bootstrap")(
                *get_iso_from_artifacts(),
                *prepare_bootstrap(),
                install_bootstrap(),
                provision_prometheus_volumes(),
                enable_ipip(),
            ),
            *dsl.on_remote(host="bastion")(
                run_tests(
                    "Run installation scenarii",
                    filters="install and ci and multinodes",
                    ssh_config=ssh_config,
                ),
                run_tests(
                    "Run fast tests",
                    filters="post and ci and multinodes and not slow",
                    ssh_config=ssh_config,
                ),
                run_tests(
                    "Run slow tests",
                    filters="post and ci and multinodes and slow",
                    ssh_config=ssh_config,
                ),
            ),
            # TODO: mutualize, maybe have a way to generate for loops, or just
            # a single one and only accept single steps for
            # multi-host `on_remote`...
            *dsl.on_remote(host="bootstrap")(
                collect_sosreport(),
                *dsl.copy_artifacts(
                    ["/var/tmp/sosreport*"],
                    destination="sosreport/single-multiple-nodes/bootstrap",
                ),
            ),
            *dsl.on_remote(host="node1")(
                collect_sosreport(),
                *dsl.copy_artifacts(
                    ["/var/tmp/sosreport*"],
                    destination="sosreport/single-multiple-nodes/node1",
                ),
            ),
        ],
    )


# }}}
# Steps {{{
def set_version_property():
    return core.SetPropertyFromCommand(
        "Set version as property from built artifacts",
        property_name="metalk8s_version",
        command="bash -c '{}'".format(
            shell._and(
                '. <(curl -s "%(prop:artifacts_private_url)s/product.txt")',
                "echo $VERSION",
            )
        ),
    )


def build_all():
    return shell.Shell(
        "Build everything",
        command="./doit.sh -n 4",
        env={"PYTHON_SYS": "python3.6"},
        use_pty=True,
        halt_on_failure=True,
    )


def build_docs():
    return shell.Shell(
        "Build documentation",
        command="tox --workdir /tmp/tox -e docs -- html latexpdf",
        env={"READTHEDOCS": "True"},
        halt_on_failure=True,
    )


def lint_all():
    return shell.Shell(
        "Run all linting targets",
        command="./doit.sh lint",
        use_pty=True,
        halt_on_failure=False,
    )


ARTIFACTS_URL = pathlib.Path("%(prop:artifacts_private_url)s")


def get_iso_from_artifacts(destination=None, source=None):
    base_url = ARTIFACTS_URL
    name_suffix = ""
    if source is not None:
        base_url = base_url / source
        name_suffix = " ({})".format(source)

    dest_dir = pathlib.Path(".")
    if destination is not None:
        dest_dir = pathlib.Path(destination)

    def _curl_cmd(filename):
        return 'curl -s -XGET -o "{out_path}" "{in_url}"'.format(
            out_path=dest_dir / filename, in_url=base_url / filename,
        )

    # Get ISO checksum
    yield shell.Shell(
        "Retrieve ISO image checksum" + name_suffix,
        command=_curl_cmd("SHA256SUM"),
    )

    # Get ISO archive, with retry
    yield shell.Bash(
        "Retrieve ISO image" + name_suffix,
        command=shell._seq(
            shell._for(
                "{{1..{max_attempts}}}",
                shell._seq(
                    'echo "Attempt $i out of {max_attempts}"',
                    "{curl_cmd} && exit",
                    "sleep 2",
                ),
                var="i",
            ),
            'echo "Could not retrieve ISO after {max_attempts} attempts" >&2',
            "exit 1",
        ).format(max_attempts=20, curl_cmd=_curl_cmd("metalk8s.iso")),
        inline=True,
        halt_on_failure=True,
    )

    # Validate checksum
    yield shell.Shell(
        "Check ISO image with checksum" + name_suffix,
        command="sha256sum -c SHA256SUM",
        workdir=dest_dir,
    )


SRV_SCAL = pathlib.Path("/srv/scality")
DEFAULT_MOUNTPOINT = SRV_SCAL / "metalk8s-%(prop:metalk8s_version)s"


def prepare_bootstrap(iso="metalk8s.iso", mountpoint=DEFAULT_MOUNTPOINT):
    # Create mountpoint
    yield shell.Shell(
        "Create ISO mountpoint",
        command='mkdir -p "{}"'.format(mountpoint),
        sudo=True,
        halt_on_failure=True,
    )

    # Mount ISO
    yield shell.Shell(
        "Mount ISO image",
        command='mount -o loop "{}" "{}"'.format(iso, mountpoint),
        sudo=True,
        halt_on_failure=True,
    )

    # Create BootstrapConfiguration
    # TODO: store this into a shareable script
    yield shell.Bash(
        "Create bootstrap configuration file",
        command=shell._seq(
            "mkdir -p /etc/metalk8s",
            shell._fmt_args(
                "cat > /etc/metalk8s/bootstrap.yaml << END",
                "apiVersion: metalk8s.scality.com/v1alpha2",
                "kind: BootstrapConfiguration",
                "networks:",
                "  controlPlane: 10.100.0.0/16",
                "  workloadPlane: 10.100.0.0/16",
                "ca:",
                "  minion: $(hostname)",
                "apiServer:",
                shell._fmt_args(
                    "host: $(ip route get 10.100.0.0",
                    "| awk '/10.100.0.0/{{ print $6 }}')",
                ),
                "archives:",
                "- \"$(relpath '{iso}')\"",
                "END",
                join_with="\n",
            ),
        ).format(iso=iso),
        sudo=True,
        inline=True,
        halt_on_failure=True,
    )


def install_bootstrap(mountpoint=DEFAULT_MOUNTPOINT):
    return shell.Bash(
        "Start the bootstrap process",
        mountpoint / "bootstrap.sh",
        "--verbose",
        sudo=True,
        halt_on_failure=True,
    )


def provision_prometheus_volumes(mountpoint=DEFAULT_MOUNTPOINT):
    return shell.Bash(
        "Provision Prometheus and AlertManager storage",
        "eve/create-volumes.sh",
        sudo=True,
        wrap_env=True,
        env={
            "PRODUCT_TXT": str(mountpoint / "product.txt"),
            "PRODUCT_MOUNT": str(mountpoint),
        },
        halt_on_failure=True,
    )


def run_tests(
    name,
    mode="default",
    filters=None,
    branch="%(prop:branch)s",
    iso_mountpoint=DEFAULT_MOUNTPOINT,
    ssh_config=None,
):
    env = {"BRANCH": branch, "ISO_MOUNTPOINT": iso_mountpoint}
    if mode != "local":
        env["SSH_CONFIG"] = ssh_config

    return shell.Shell(
        name,
        command=shell._and(
            'git checkout "$BRANCH" --quiet',
            shell._fmt_args(
                "tox",
                "-e",
                "tests-local" if mode == "local" else "tests",
                '-- -m "{}"'.format(filters) if filters else None,
            ),
        ),
        env=env,
        halt_on_failure=True,
    )


BUILD_DIR = pathlib.Path("build")


def run_cypress_tests():
    return shell.Bash(
        "Run Cypress tests",
        command="cypress.sh",
        env={"IN_CI": "True"},
        workdir=BUILD_DIR / "ui",
        halt_on_failure=True,
    )


def collect_sosreport(owner="eve", group="eve"):
    return shell.Shell(
        "Collect logs using sosreport",
        command=shell._and(
            shell._fmt_args(
                "sudo sosreport --all-logs",
                "-o metalk8s -kmetalk8s.podlogs=True",
                "-o containerd -kcontainerd.all=True -kcontainerd.logs=True",
                "--batch --tmp-dir /var/tmp",
            ),
            "sudo chown {}:{} /var/tmp/sosreport*".format(owner, group),
        ),
    )


def enable_ipip():
    return shell.Bash(
        "Enable IP-in-IP encapsulation for Calico",
        command="/home/centos/scripts/enable_ipip.sh",
    )


# }}}

if __name__ == "__main__":
    build_plan = build_project().dump()
    yamlprint.dump(build_plan, stream=sys.stdout)
