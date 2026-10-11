# RoleLens

Local web app to explore, graph and safely redesign AWS IAM roles, users, groups and managed
policies.

RoleLens collects your IAM roles, users, groups and managed policies **read-only**, shows who
can assume each role, what each principal can do and who uses each policy as interactive
graphs, and lets you clone a role, user or customer managed policy into a local **draft**, edit
its policies with live IAM validation, diff it against the original and export policy JSON or
Terraform. **Insights** flag risky roles and users, unused permissions and duplicate or
overlapping roles, users and groups. **RoleLens never writes to AWS**: every boto3 client
refuses any operation that is not `List*` / `Get*` (plus a few read-only reports allowed by
exact name, see Security), and drafts only ever live in the local SQLite database.

Same stack and conventions as [IPLens](https://github.com/Amiri83/IPLens): Flask + SQLite, one
data directory, Fernet-encrypted credentials, background jobs with a progress modal, a
redacting log file and Host / CSRF guards.

## Features

- **Accounts**: environment, named profile (incl. SSO), access key, or pasted temporary STS
  credentials (three fields, an `export AWS_…` block or `aws sts get-session-token` JSON).
  Secrets are Fernet-encrypted at rest or kept in memory only.
- **Collect** (background job, cancellable): `iam:ListRoles`, `iam:GetRole` (trust policy,
  last used), `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRolePolicy`;
  users and groups (`iam:ListUsers`, `iam:GetUser`, `iam:ListGroups`, `iam:GetGroup`,
  `iam:ListGroupsForUser`, `iam:ListAttached{User,Group}Policies`,
  `iam:List{User,Group}Policies` + `iam:Get{User,Group}Policy`, `iam:ListAccessKeys` +
  `iam:GetAccessKeyLastUsed`, and console access / MFA from the **credential report**
  (`iam:GenerateCredentialReport` + `iam:GetCredentialReport`) or, without it,
  `iam:GetLoginProfile` (existence only) + `iam:ListMFADevices`); managed policies
  (`iam:ListPolicies` — every customer managed policy and the attached AWS managed ones —,
  `iam:GetPolicy`, `iam:GetPolicyVersion` (default version), `iam:ListPolicyVersions`,
  `iam:ListEntitiesForPolicy`). Everything is snapshotted in SQLite; only roles are required,
  a missing permission on any other call becomes a warning.
- **Users**: console access, MFA, access keys (count, oldest active key, longest unused), last
  activity, groups, direct vs via-group policies and findings. Column filters: search, console
  access, MFA, access key older than 90 / 180 / 365 days, no activity for 30 / 90 / 180 days,
  inline policies, where permissions come from (direct, via groups, both, none) and risk
  finding; **Export to Excel** like the Roles page. Only an access key's id (shown shortened),
  status, age and last use are kept — never a secret key or password.
- **Groups**: members, policies and findings. **Policies**: every collected managed policy with
  who uses it (roles / users / groups), an *unattached* flag, versions, the JSON document and
  its risk findings; filters (type, unattached, used by) and **Export to Excel**.
- **Roles**: list with path, last used, trust type, flags, number of policies and trusted
  principals. Column filters: name / path / ARN / principal search, last used (never, more
  than 30 / 90 / 180 days ago), trust type (service, same account, cross-account, OIDC, SAML),
  service-linked, permissions boundary, inline policies, number of policies and risk finding.
  Filters live in the URL and are applied by the server; **Export to Excel** downloads exactly
  the rows shown (openpyxl: frozen header row, autofilter, a "Findings" sheet with severity,
  why and suggested fix of every finding of those roles, plus an "Export" sheet listing the
  account, snapshot time and applied filters).
- **Effective permissions** per role, user (its own policies plus those of its groups) and
  group, computed at the end of every collection and stored in
  SQLite: the union of every policy (inline, customer and AWS managed), wildcards expanded
  against the built-in action catalog (a wildcard is also kept as-is, since it can grant
  actions the catalog does not list); unconditional `Deny` on `"*"` is subtracted.
  Permissions boundaries and narrower `Deny` statements are not evaluated, so the result may
  overstate, never understate.
- **Risk findings**, each with a severity, why it matters and a suggested fix snippet:
  admin-equivalent (`*`, `iam:*`, `<service>:*` on `"*"`, `NotAction`, AdministratorAccess),
  wildcard action and/or resource, `iam:PassRole` on `"*"`, cross-account trust without an
  `sts:ExternalId` condition, trust to another account's root, OIDC trust without a `:sub`
  condition, no permissions boundary, only inline policies. The permission rules also apply to
  users and groups; users add console access without MFA, access keys older than 90 days or
  unused for 90 days, and policies attached to the user instead of a group.
- **Insights dashboard**: counts per finding type (each links to the filtered Roles or Users
  list), top risky roles, users and groups, top unused permissions, Access Analyzer findings.
- **Usage data** (optional background job, every source optional — a missing permission is a
  warning): role last used; services granted but not used in 90 days
  (`iam:GenerateServiceLastAccessedDetails` + `GetServiceLastAccessedDetails`, service level);
  who assumes each role, how often, when last and from which source IP / service
  (`cloudtrail:LookupEvents` for `AssumeRole*`, 90 days, account region and `us-east-1`);
  IAM Access Analyzer findings when an analyzer exists (`access-analyzer:ListAnalyzers`,
  `ListFindings`).
- **Recommendations**: duplicate roles (same effective permissions and trust) and overlapping
  pairs (Jaccard similarity of the effective actions ≥ 0.8, configurable in Settings or per
  view), with a side-by-side diff and a suggested merged role — exportable as JSON / Terraform
  through the regular export, or opened as a draft. Duplicate and overlapping users and groups
  use the same engine and threshold.
- **Role graph** (cytoscape.js, vendored; Grid layout by default, also dagre hierarchy,
  breadth-first, concentric, circle): principals that can assume → role → policies → services →
  actions → resources. Allow edges are green, Deny edges red with a bar end, statements with a
  `Condition` are dashed, nodes reached by both are marked "mixed". Click a node for the
  statements behind it. Filter by node type and by effect (Allow / Deny). Users have the same
  graph as user → groups → policies → services → …, and a managed policy shows the roles, users
  and groups that use it; role, user, group and managed policy nodes link to their own page.
- **Graph export** (role page and draft editor) of the graph *as shown* — current layout,
  filters and selection: **SVG** (self-contained, node icons embedded as `data:` URIs),
  **PNG** (rendered by cytoscape) and **draw.io** (`.drawio` mxfile; AWS service nodes use the
  `mxgraph.aws4` service shapes).
- **Background jobs**: a progress modal with Cancel and Close (Close on a running job keeps it
  going in the background). When a collection ends, closing the modal re-fetches the page's
  data in place — no full page reload.
- **Draft editor**: clone a role, edit role settings, the trust policy and the inline / customer
  managed policies in a JSON editor (line numbers, error line marker, indentation, format);
  add or remove policies (AWS managed policies are read-only: detach only). Validation covers
  JSON syntax (line / column), document structure, `Effect` / `Action` / `Resource` /
  `Principal` rules for trust vs identity policies, `Sid`s, condition operators, IAM name and
  size limits and **known action names** (a built-in catalog of common services; actions of
  other services are reported as "not checked"). The graph and a section-by-section diff
  against the original update live.
- **Export**: policy JSON files (copy each, download one or a zip) and Terraform HCL
  (`aws_iam_role`, `aws_iam_policy_document` data sources, `aws_iam_role_policy`,
  `aws_iam_policy` + `aws_iam_role_policy_attachment`; AWS managed policies attached by ARN),
  `terraform fmt` style, copy or download. User drafts (the user's own policies and group
  memberships) export as `aws_iam_user`, `aws_iam_user_policy`,
  `aws_iam_user_policy_attachment` and `aws_iam_user_group_membership`; standalone customer
  managed policy drafts as `aws_iam_policy`. Access keys and passwords are never exported.

Planned: policy simulator, permissions boundary evaluation, UI polish.

## Install and run

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/rolelens            # http://127.0.0.1:8078
```

Options: `--port`, `--host` (default `127.0.0.1`, local only), `--home` (data directory,
default `$ROLELENS_HOME` or `~/.rolelens`), `--no-browser` (do not open the browser), `--debug`
(Flask development server with the debugger; development only). Set `ROLELENS_SECRET_KEY` to
supply the Fernet key instead of the generated `secret.key` file.

RoleLens is served by [waitress](https://docs.pylonsproject.org/projects/waitress/) and prints one
line with its URL, data directory and log file. With a desktop session the UI opens in the web
browser; otherwise open the printed URL. Ctrl+C (or SIGTERM) stops it cleanly: running jobs are
cancelled.

### Minimal IAM permissions

`iam:ListRoles`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`,
`iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion` (`sts:GetCallerIdentity` needs
none). Optional, for users, groups and policies: the `List*` / `Get*` calls listed under
Collect, and `iam:GenerateCredentialReport` + `iam:GetCredentialReport` (faster; without them
RoleLens calls `iam:GetLoginProfile` and `iam:ListMFADevices` per user). Optional, for usage
data: `iam:GenerateServiceLastAccessedDetails`,
`iam:GetServiceLastAccessedDetails`, `cloudtrail:LookupEvents`,
`access-analyzer:ListAnalyzers`, `access-analyzer:ListFindings`.

## Security

- Read-only AWS: a botocore `before-call` hook on every client rejects any operation that is
  not `List*` / `Get*` (and secret-returning calls such as `sts:GetSessionToken`). The only
  other operations allowed, by exact name, are the read-only reports
  `iam:GenerateServiceLastAccessedDetails`, `cloudtrail:LookupEvents` and the IAM credential
  report (`iam:GenerateCredentialReport`, `iam:GetCredentialReport`).
- The credential report is parsed in memory: only console access, password last used, MFA
  and each access key's status, rotation and last use are kept; the report itself is never
  stored or logged. No secret access key or password is ever requested, stored or shown, and
  access key ids stay out of warnings and the log.
- Usage data (including CloudTrail source IP addresses) stays in the local database; the log
  file only records counts.
- Credentials are never rendered, never logged (the log file redacts key ids, secrets and
  tokens) and never part of an error message.
- Only `127.0.0.1` / `localhost` Host headers are served (DNS rebinding); every POST needs the
  session's CSRF token; the session cookie is `SameSite=Strict`.
- A non-loopback `--host` is refused unless `--allow-remote` is passed. RoleLens has **no
  authentication**, so it then prints a warning and also accepts IP-address Host headers
  (hostnames other than `localhost` stay rejected as DNS-rebinding protection).
- All front-end assets are vendored: the browser makes no external requests.

## Development

```sh
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Tests use moto and placeholder data only (`123456789012`, `role-a`, `bucket-a`). Export
snapshots live in `tests/snapshots/`; after an intended output change run
`ROLELENS_UPDATE_SNAPSHOTS=1 .venv/bin/pytest tests/test_export.py` and review the diff.

## Vendored front-end assets

| asset | path | source | license |
|---|---|---|---|
| cytoscape.js 3.34.3 (`dist/cytoscape.min.js`, unmodified) | `rolelens/static/vendor/cytoscape.min.js` | npm package `cytoscape@3.34.3` (same file as IPLens) | MIT – `rolelens/static/vendor/cytoscape.LICENSE` |
| dagre (`dagre.min.js`, unmodified) | `rolelens/static/vendor/dagre.min.js` | npm package `dagre` (same file as IPLens) | MIT – `rolelens/static/vendor/dagre.LICENSE` |

The JSON editor (`rolelens/static/jsonedit.js`), the in-place refresh (`refresh.js`), the graph
icons and the SVG / draw.io writers (`rolelens/graph_export.py`) are RoleLens' own,
dependency-free code.
