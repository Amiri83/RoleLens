"""RoleLens: explore, graph and safely redesign AWS IAM roles (read-only)."""

from importlib.metadata import PackageNotFoundError, version

try:  # the version lives in pyproject.toml only
    __version__ = version("aws-rolelens")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0+unknown"
