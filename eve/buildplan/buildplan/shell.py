"""Helpers to manipulate `core.ShellCommand`."""

from buildplan import core


# Helpers {{{
def _fmt_args(*args, join_with=" "):
    """Join an iterable of `Optional[str]`, omitting `None`s."""
    return join_with.join(str(arg) for arg in args if args is not None)


def _and(*args):
    return _fmt_args(*args, join_with=" && ")


def _or(*args):
    return _fmt_args(*args, join_with=" || ")


def _seq(*args):
    return _fmt_args(*args, join_with="; ")


def _for(values_in, command, var="varname"):
    values = (
        values_in
        if isinstance(values_in, str)
        else " ".join(map(str, values_in))
    )

    return _seq('for {var} in {values}', "do {command}", "done").format(
        var=var, values=values, command=command,
    )


def _if(predicate, _then, _else=None):
    return _seq(
        'if "{predicate}"',
        "then {_then}",
        "else {_else}" if _else is not None else None,
        "done",
    ).format(predicate=predicate, _then=_then, _else=_else)


# }}}
# Steps {{{
class Shell(core.ShellCommand):
    STEP_NAME = "ShellCommand"

    def __init__(self, name, command, sudo=False, **kwargs):
        if sudo:
            command = "sudo " + command

        self._kwargs = kwargs
        super(Shell, self).__init__(name, command, **kwargs)


class Bash(Shell):
    def __init__(
        self, name, command, *args, inline=False, wrap_env=False, **kwargs
    ):
        if inline:
            if args:
                raise ValueError(
                    "Cannot pass positional arguments to `Bash` "
                    "if using `inline=True`."
                )
            full_command = "bash -c '{}'".format(command)

        else:
            inner_command = _fmt_args(command, *args)

            if wrap_env and "env" in kwargs:
                inner_command = "env {values} {command}".format(
                    values=_fmt_args(
                        *(
                            "{}={}".format(key, value)
                            for key, value in kwargs.pop("env").items()
                        )
                    ),
                    command=inner_command,
                )

            full_command = "bash " + inner_command

        super(Bash, self).__init__(name, full_command, **kwargs)


# }}}
