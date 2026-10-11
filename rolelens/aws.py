"""boto3 session construction and a hard read-only guard.

Every client created through :class:`AwsGateway` has a botocore ``before-call``
hook that rejects any API operation whose name does not start with ``List`` or
``Get`` (``Describe`` too, for completeness), and a few ``Get`` calls that return
secret values or credentials. The only other operations allowed are the read-only
reports of :data:`EXTRA_READ_ONLY_OPERATIONS` (usage data and the IAM credential report).
RoleLens never mutates AWS: drafts and exports are local only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, NamedTuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .accounts import EXPIRED_MESSAGE, Account, CredentialError

log = logging.getLogger(__name__)

READ_ONLY_PREFIXES = ("Describe", "List", "Get")

# AWS error codes meaning "these credentials are no longer valid".
EXPIRED_CREDENTIAL_CODES = frozenset(
    {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId"}
)

_BOTO_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"}, user_agent_extra="rolelens")


class ReadOnlyViolation(RuntimeError):
    """Raised when code attempts a non read-only AWS API call."""


# "Get" calls that return secret values or credentials. RoleLens never needs them, so they
# are refused even though their names carry a read-only prefix.
SECRET_VALUE_OPERATIONS = frozenset(
    {
        ("secretsmanager", "GetSecretValue"),
        ("secretsmanager", "BatchGetSecretValue"),
        ("ssm", "GetParameter"),
        ("ssm", "GetParameters"),
        ("ssm", "GetParametersByPath"),
        ("ssm", "GetParameterHistory"),
        ("sts", "GetSessionToken"),
        ("sts", "GetFederationToken"),
        ("ecr", "GetAuthorizationToken"),
    }
)

# The IAM credential report: an optional, faster source of user metadata (console access,
# MFA, access key age and last use). It holds no secret or key value; the collector keeps
# only those fields (see rolelens.collector.parse_credential_report) and never stores or
# logs the report itself. GenerateCredentialReport only starts building the report.
CREDENTIAL_REPORT_OPERATIONS = frozenset(
    {
        ("iam", "GenerateCredentialReport"),
        ("iam", "GetCredentialReport"),
    }
)

# Read-only operations whose names carry no read-only prefix, allowed by exact name:
# GenerateServiceLastAccessedDetails only starts a report job (read back with
# GetServiceLastAccessedDetails); LookupEvents reads the CloudTrail event history.
EXTRA_READ_ONLY_OPERATIONS = (
    frozenset(
        {
            ("iam", "GenerateServiceLastAccessedDetails"),
            ("cloudtrail", "LookupEvents"),
        }
    )
    | CREDENTIAL_REPORT_OPERATIONS
)


def is_read_only_operation(service: str, op_name: str) -> bool:
    if (service, op_name) in SECRET_VALUE_OPERATIONS:
        return False
    if (service, op_name) in EXTRA_READ_ONLY_OPERATIONS:
        return True
    return op_name.startswith(READ_ONLY_PREFIXES)


def _guard_read_only(model: Any = None, **_: Any) -> None:
    op_name = getattr(model, "name", "")
    service = getattr(getattr(model, "service_model", None), "service_name", "")
    if not is_read_only_operation(service, op_name):
        raise ReadOnlyViolation(f"RoleLens is read-only; refusing AWS operation {op_name!r}")


def error_code(exc: Exception) -> str:
    """The AWS error code of a failed call (the exception type for other errors)."""
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "") or "ClientError"
    return type(exc).__name__


def iso_time(value: Any) -> str:
    """A boto3 timestamp as ISO UTC (``""`` for None)."""
    if isinstance(value, datetime):
        ts = value if value.tzinfo else value.replace(tzinfo=UTC)
        return ts.astimezone(UTC).isoformat(timespec="seconds")
    return str(value or "")


def is_credential_failure(exc: BaseException) -> bool:
    """True for errors the user fixes by pasting new credentials."""
    if isinstance(exc, CredentialError):
        return True
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "") in EXPIRED_CREDENTIAL_CODES
    return False


def build_session(account: Account) -> boto3.session.Session:
    """Create a boto3 session for the account's auth mode.

    ``account`` must have been loaded with ``with_secret=True`` for key and
    temporary auth. Raises :class:`CredentialError` (safe message) when the
    credentials are incomplete or already expired.
    """
    problem = account.credential_problem()
    if problem:
        raise CredentialError(problem)
    region = account.region or None
    if account.auth_mode == "profile":
        return boto3.session.Session(profile_name=account.profile, region_name=region)
    if account.auth_mode in ("keys", "temporary"):
        if not account.secret_access_key:
            raise CredentialError("credentials are incomplete")
        return boto3.session.Session(
            aws_access_key_id=account.access_key_id,
            aws_secret_access_key=account.secret_access_key,
            aws_session_token=account.session_token or None,
            region_name=region,
        )
    # "env": the process environment / default chain (env vars, shared config, role, ...)
    return boto3.session.Session(region_name=region)


class AwsGateway:
    def __init__(self, session: boto3.session.Session):
        self.session = session

    @classmethod
    def from_account(cls, account: Account) -> AwsGateway:
        return cls(build_session(account))

    @property
    def region(self) -> str | None:
        return self.session.region_name

    def client(
        self, service: str, *, region: str | None = None, config: Config | None = None
    ) -> Any:
        merged = _BOTO_CONFIG.merge(config) if config is not None else _BOTO_CONFIG
        client = self.session.client(service, region_name=region or None, config=merged)
        # "before-call" is hierarchical: it fires for every operation of this client.
        client.meta.events.register("before-call", _guard_read_only)
        return client

    def caller_identity(self) -> dict[str, str]:
        ident = self.client("sts").get_caller_identity()
        return {"account": ident.get("Account", ""), "arn": ident.get("Arn", "")}


class ConnectionCheck(NamedTuple):
    ok: bool
    message: str
    credentials_problem: bool = False
    account_id: str = ""  # AWS account the credentials resolved to (on success)


def check_connection(
    account: Account, factory: Callable[[Account], AwsGateway] | None = None
) -> ConnectionCheck:
    """Test the account's credentials without ever echoing them."""
    try:
        gw = (factory or AwsGateway.from_account)(account)
        ident = gw.caller_identity()
        gw.client("iam").list_roles(MaxItems=1)
    except (BotoCoreError, ClientError, ValueError, ReadOnlyViolation) as exc:
        log.warning("connection test failed: %s", type(exc).__name__)
        if is_credential_failure(exc):
            msg = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
            return ConnectionCheck(False, f"Connection failed: {msg}", True)
        return ConnectionCheck(False, f"Connection failed: {_safe_error(exc)}")
    log.info("connection test succeeded (region=%s)", gw.region)
    return ConnectionCheck(
        True,
        f"Connected to account {ident['account']} (iam:ListRoles allowed)",
        account_id=ident["account"],
    )


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"
