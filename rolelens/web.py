"""Flask application: accounts, IAM collection, roles, graph, insights, draft editor, export,
logs."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from . import drafts as drafts_mod
from . import export as export_mod
from . import graph_export, insights, queries, recommend
from .accounts import (
    AUTH_MODE_LABELS,
    AUTH_MODES,
    EXPIRED_MESSAGE,
    Account,
    AccountStore,
    CredentialError,
    MemoryVault,
    discover_profiles,
)
from .aws import AwsGateway, check_connection, is_credential_failure
from .collector import Collector
from .config import AppPaths, default_paths
from .crypto import SecretBox
from .db import closing, connect, init_db
from .filters import FINDINGS, LAST_USED, RoleFilters
from .graph import build_graph
from .jobs import KINDS as JOB_KINDS
from .jobs import JobBusy, JobCancelled, JobContext, JobFailed, JobManager, Progress
from .logging_setup import LEVELS, configure_logging, read_log
from .policy import TRUST_TYPES, dumps
from .settings import MAX_DISPLAY_NAME, REGIONS, Settings, SettingsStore
from .usage import WINDOW_DAYS, UsageCollector
from .validate import has_errors, validate_model
from .xlsx import roles_workbook

log = logging.getLogger(__name__)

GatewayFactory = Callable[[Account], AwsGateway]
HISTORY_ROWS = 20
# DNS-rebinding protection: only these Host header names are served.
ALLOWED_HOSTS = ("127.0.0.1", "localhost")
MAX_UPLOAD_BYTES = 4 * 1024 * 1024
# Graph layouts offered on the role and editor pages (Grid is the default).
LAYOUTS = {
    "grid": "Grid",
    "dagre": "Hierarchy (dagre)",
    "breadthfirst": "Breadth-first",
    "concentric": "Concentric",
    "circle": "Circle",
}
NO_DATA = "No IAM data yet: collect the active account first."
XLSX_MIMETYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
# Graph exports rendered on the server (PNG is rendered by cytoscape in the browser).
GRAPH_FORMATS: dict[str, tuple[str, Callable[[graph_export.View], str]]] = {
    "svg": ("image/svg+xml", graph_export.to_svg),
    "drawio": ("application/vnd.jgraph.mxfile", graph_export.to_drawio),
}


def _ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name.removeprefix("[").removesuffix("]"))
    except ValueError:
        return False
    return True


def host_allowed(host: str, port: int | None, *, ip_literals: bool = False) -> bool:
    """True if ``host`` (a raw Host header) names this local server.

    With a known ``port`` the header must carry exactly that port (a bare name
    is only valid for port 80). With ``port=None`` any numeric port is accepted.
    ``ip_literals`` (``rolelens --allow-remote``) also accepts any IP address as the
    name: DNS rebinding always arrives under a hostname, never an IP literal.
    """
    host = host.strip().lower()
    if host.startswith("["):  # [IPv6]:port
        name, _, rest = host.partition("]")
        name += "]"
        sep, host_port = (":", rest[1:]) if rest.startswith(":") else ("", rest)
    else:
        name, sep, host_port = host.partition(":")
    if name not in ALLOWED_HOSTS and not (ip_literals and _ip_literal(name)):
        return False
    if port is None:
        return not sep or host_port.isdigit()
    return host_port == str(port) if sep else port == 80


def account_label(account_id: str | None, display_name: str = "") -> str:
    """``"<name> (<account id>)"``; without a name only the account id is shown."""
    if display_name and account_id:
        return f"{display_name} ({account_id})"
    return display_name or account_id or "unknown account"


def utc_iso(value: Any) -> str | None:
    """Normalise a stored timestamp to ``YYYY-MM-DDTHH:MM:SSZ``.

    Snapshot times are stored timezone-aware (UTC); naive values (log file lines)
    are in the server's local time. Returns None for empty/unparseable input.
    """
    if not value:
        return None
    try:
        ts = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.astimezone()
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_time(value: Any) -> Markup | str:
    """``<time>`` element that static/localtime.js re-renders in the browser's time zone.

    The UTC text is only the no-JavaScript fallback; the ISO value stays in the tooltip.
    """
    iso = utc_iso(value)
    if iso is None:
        return value or ""
    fallback = iso.replace("T", " ").removesuffix("Z") + " UTC"
    return Markup('<time class="localtime" datetime="{0}" title="{0}">{1}</time>').format(
        iso, fallback
    )


def _flask_secret(paths: AppPaths) -> bytes:
    p = paths.flask_secret_path
    if p.exists():
        return p.read_bytes()
    key = secrets.token_bytes(32)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def create_app(
    home: str | os.PathLike[str] | None = None,
    *,
    gateway_factory: GatewayFactory | None = None,
    testing: bool = False,
    port: int | None = None,
    allow_remote: bool = False,
) -> Flask:
    """Build the app. ``port`` is the port the server listens on; when given,
    the Host header must be ``127.0.0.1:<port>`` or ``localhost:<port>``.
    ``allow_remote`` (``rolelens --allow-remote``) also accepts IP-address Host headers
    (see :func:`host_allowed`)."""
    paths = default_paths(home).ensure()
    init_db(paths.db_path)
    box = SecretBox.from_path(paths.key_path)
    store = SettingsStore(paths.db_path)
    # Memory-only credentials live in this process for the lifetime of the app.
    account_store = AccountStore(paths.db_path, box, MemoryVault())

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_flask_secret(paths),
        TESTING=testing,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_HTTPONLY=True,
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    )
    app.extensions["rolelens"] = {
        "paths": paths,
        "store": store,
        "accounts": account_store,
        "gateway_factory": gateway_factory or AwsGateway.from_account,
        "port": port,
        "allow_remote": allow_remote,
        # Background jobs (IAM collection): one per account.
        "jobs": JobManager(paths.db_path),
    }
    apply_log_dir(app, store.load())
    log.info("RoleLens started (data dir %s)", paths.home)
    _register(app)
    return app


def shutdown_app(app: Flask, timeout: float = 10.0) -> None:
    """Stop the app's background work (server shutdown): running jobs are cancelled and
    waited for up to ``timeout`` seconds."""
    cancelled = app.extensions["rolelens"]["jobs"].shutdown(timeout)
    log.info("RoleLens stopped (%d job(s) cancelled)", len(cancelled))


def _ext() -> dict[str, Any]:
    return current_app.extensions["rolelens"]


def _paths() -> AppPaths:
    return _ext()["paths"]


def _store() -> SettingsStore:
    return _ext()["store"]


def _accounts() -> AccountStore:
    return _ext()["accounts"]


def _jobs() -> JobManager:
    return _ext()["jobs"]


def flash_job_messages(job: dict[str, Any]) -> None:
    """Flash a finished job's result lines (forms submitted without JavaScript)."""
    for m in job.get("messages", []):
        if m.get("link_url"):
            flash(
                Markup('{0} <a href="{1}">{2}</a>').format(
                    m["text"], m["link_url"], m["link_text"]
                ),
                m["category"],
            )
        else:
            flash(m["text"], m["category"])


def _credential_message(ctx: Progress, prefix: str, exc: BaseException, edit_url: str) -> None:
    msg = str(exc) if isinstance(exc, CredentialError) else EXPIRED_MESSAGE
    ctx.message("error", f"{prefix}: {msg} —", edit_url, "edit account")


def log_dir_for(paths: AppPaths, settings: Settings) -> Path:
    return Path(settings.log_dir).expanduser() if settings.log_dir else paths.default_log_dir


def apply_log_dir(app: Flask, settings: Settings) -> Path:
    paths: AppPaths = app.extensions["rolelens"]["paths"]
    log_dir = log_dir_for(paths, settings)
    configure_logging(log_dir)
    app.extensions["rolelens"]["log_dir"] = log_dir
    return log_dir


def _db():
    if "db" not in g:
        g.db = connect(_paths().db_path)
    return g.db


def _active() -> Account | None:
    """The active account; falls back to (and persists) the first one if unset or gone."""
    if "active_account" not in g:
        store = _accounts()
        acct = store.get(_store().active_account_id())
        if acct is None:
            acct = next(iter(store.list()), None)
            _store().set_active_account_id(acct.id if acct else None)
        g.active_account = acct
    return g.active_account


def _active_ref() -> int | None:
    acct = _active()
    return acct.id if acct else None


def _snapshot_or_none():
    """Latest successful snapshot of the active account (None without an account)."""
    if "snapshot" not in g:
        g.snapshot = queries.latest_snapshot(_db(), _active_ref())
    return g.snapshot


def _analysed_snapshot():
    """Like :func:`_snapshot_or_none`, with the snapshot's insights analysis guaranteed."""
    snap = _snapshot_or_none()
    if snap is not None and "analysed" not in g:
        insights.ensure_analysis(_paths().db_path, snap["id"])
        g.analysed = True
    return snap


def account_choice_label(acct: Account) -> str:
    """Selector label: the display name, else the AWS account id seen last."""
    return acct.display_name or acct.aws_account_id or f"Account {acct.id}"


def _account_choices() -> list[dict[str, Any]]:
    if "account_choices" not in g:
        g.account_choices = [
            {"id": acct.id, "label": account_choice_label(acct), "account": acct.public_dict()}
            for acct in _accounts().list()
        ]
    return g.account_choices


def _safe_next(target: str | None) -> str:
    """Only same-site paths ("/..."), never "//host", a scheme or a backslash trick."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return url_for("roles")


def _credential_flash(prefix: str, message: str, account_id: int) -> None:
    edit = url_for("account_edit", account_id=account_id)
    flash(
        Markup('{0}: {1} — <a href="{2}">edit account</a>').format(prefix, message, edit),
        "error",
    )


def _identity_flash(message: str, account_id: int) -> None:
    edit = url_for("account_edit", account_id=account_id)
    flash(
        Markup('Warning: {0} — check the <a href="{1}">account settings</a>.').format(
            message, edit
        ),
        "warn",
    )


def _register(app: Flask) -> None:
    @app.teardown_appcontext
    def _close_db(_exc: BaseException | None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # Registered first so it runs before anything else touches the request.
    @app.before_request
    def _trusted_host() -> None:
        # Raw header: werkzeug's request.host drops default ports.
        host = request.headers.get("Host", "")
        if not host_allowed(host, _ext()["port"], ip_literals=_ext()["allow_remote"]):
            log.warning(
                "rejected request %s with untrusted Host header %r", request.path, host[:100]
            )
            abort(400, "invalid Host header")

    @app.before_request
    def _csrf() -> None:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not secrets.compare_digest(sent, session["csrf"]):
                log.warning("rejected POST %s with bad CSRF token", request.path)
                abort(400, "invalid CSRF token")

    @app.context_processor
    def _globals() -> dict[str, Any]:
        active = _active()
        choice = next((c for c in _account_choices() if active and c["id"] == active.id), None)
        return {
            "csrf_token": session.get("csrf", ""),
            "active_account": active.public_dict() if active else None,
            "active_label": choice["label"] if choice else "",
            "account_choices": _account_choices(),
            "header_snap": _snapshot_or_none(),
            "account_label": account_label,
        }

    app.add_template_filter(local_time, "localtime")
    # Node-type icons of the live graph (the same images the SVG export embeds).
    app.jinja_env.globals["graph_icons"] = graph_export.icon_data_uris()

    # -- roles -----------------------------------------------------------------------

    def _filtered_roles(snap) -> tuple[RoleFilters, list[dict[str, Any]], int]:
        """The column filters of the request and the rows they keep (page and export)."""
        filters = RoleFilters.from_args(request.args)
        if snap is not None:
            _analysed_snapshot()
        rows = queries.role_list(_db(), snap["id"]) if snap else []
        return filters, filters.apply(rows), len(rows)

    @app.get("/")
    def roles():
        snap = _snapshot_or_none()
        filters, rows, total = _filtered_roles(snap)
        ref = _active_ref()
        history = queries.recent_snapshots(_db(), ref, HISTORY_ROWS) if ref is not None else []
        return render_template(
            "roles.html",
            snap=snap,
            rows=rows,
            total=total,
            f=filters,
            last_used_choices=LAST_USED,
            trust_choices=TRUST_TYPES,
            finding_choices=FINDINGS,
            history=history,
        )

    @app.get("/roles.xlsx")
    def roles_xlsx():
        """The Roles page as shown: same filters (query string), same rows."""
        snap = _snapshot_or_none()
        if snap is None:
            abort(404, NO_DATA)
        filters, rows, total = _filtered_roles(snap)
        by_role = insights.findings_by_role(_db(), snap["id"])
        findings = [f for r in rows for f in by_role.get(r["name"], [])]
        data = roles_workbook(
            rows,
            filters,
            account=account_label(snap["account_id"], snap["account_name"]),
            taken_at=snap["taken_at"],
            total=total,
            findings=findings,
        )
        log.info(
            "roles exported to Excel (%d of %d rows, %d findings)", len(rows), total, len(findings)
        )
        stamp = (utc_iso(snap["taken_at"]) or "")[:10]
        return _download(data, f"rolelens-roles-{stamp}.xlsx", XLSX_MIMETYPE)

    def _role_or_404(name: str) -> dict[str, Any]:
        snap = _snapshot_or_none()
        if snap is None:
            abort(404, NO_DATA)
        model = queries.role_model(_db(), snap["id"], name)
        if model is None:
            abort(404)
        return model

    @app.get("/roles/<name>")
    def role_page(name: str):
        model = _role_or_404(name)
        snap = _analysed_snapshot()
        return render_template(
            "role.html",
            role=model,
            graph=build_graph(model),
            layouts=LAYOUTS,
            dumps=dumps,
            info=insights.role_insights(_db(), snap["id"], name),
            window_days=WINDOW_DAYS,
        )

    @app.get("/roles/<name>/graph.json")
    def role_graph(name: str):
        return jsonify(build_graph(_role_or_404(name)))

    @app.post("/graph/export.<fmt>")
    def graph_export_file(fmt: str):
        """SVG / draw.io file of the graph view posted by graph.js (role page and editor):
        only the visible nodes and edges, at their current positions."""
        if fmt not in GRAPH_FORMATS:
            abort(404)
        try:
            view = graph_export.parse_view(request.form.get("view"))
        except graph_export.ViewError as exc:
            abort(400, str(exc))
        mimetype, render = GRAPH_FORMATS[fmt]
        log.info("graph exported as %s (%d nodes, %d edges)", fmt, len(view.nodes), len(view.edges))
        name = export_mod.identifier(view.name, set())
        return _download(render(view).encode(), f"{name}-graph.{fmt}", mimetype)

    @app.post("/roles/<name>/clone")
    def role_clone(name: str):
        snap = _snapshot_or_none()
        if snap is None:
            abort(404, NO_DATA)
        with closing(_paths().db_path) as conn:
            draft_id = drafts_mod.clone(conn, _active_ref(), snap["id"], name)
        if draft_id is None:
            abort(404)
        log.info("draft %s cloned from a collected role (snapshot=%s)", draft_id, snap["id"])
        flash("Draft created. It is local only: RoleLens never writes to AWS.", "ok")
        return redirect(url_for("draft_edit", draft_id=draft_id))

    # -- background jobs -------------------------------------------------------------

    def _wants_background() -> bool:
        """Pages with JavaScript post ``background=1`` and follow the job in a modal;
        plain form posts run the job to the end and flash its result lines."""
        return request.form.get("background") == "1"

    def _run_job(account_ref: int, kind: str, work: Callable[[JobContext], None], back: str):
        background = _wants_background()
        try:
            job = _jobs().start(account_ref, kind, work, background=background)
        except JobBusy as exc:
            if background:
                return jsonify({"ok": False, "error": str(exc), "job": exc.job}), 409
            flash(str(exc), "error")
            return redirect(back)
        if background:
            return jsonify(
                {"ok": True, "job": job, "status_url": url_for("job_status", job_id=job["id"])}
            )
        flash_job_messages(job)
        return redirect(back)

    def _job_account() -> int:
        """Jobs are keyed by the active account (0 when there is none)."""
        return _active_ref() or 0

    @app.get("/jobs/current")
    def job_current():
        """The active account's running job, else its last one (a reload re-attaches)."""
        job = _jobs().current(_job_account())
        return jsonify({"job": job, "kinds": JOB_KINDS})

    @app.get("/jobs/<job_id>")
    def job_status(job_id: str):
        job = _jobs().status(job_id[:64], _job_account())
        if job is None:
            abort(404)
        return jsonify({"job": job})

    @app.post("/jobs/<job_id>/cancel")
    def job_cancel(job_id: str):
        ok = _jobs().cancel(job_id[:64], _job_account())
        return jsonify({"ok": ok, "job": _jobs().status(job_id[:64], _job_account())})

    @app.post("/collect")
    def collect():
        active = _active()
        if active is None:
            if _wants_background():
                return jsonify({"ok": False, "error": "Add an AWS account in Settings first."}), 400
            flash("Add an AWS account in Settings first.", "error")
            return redirect(url_for("settings_page"))
        return _run_job(active.id, "collect", _collect_work(active.id), url_for("roles"))

    def _collect_work(account_id: int) -> Callable[[JobContext], None]:
        """The collection job of an account. Everything the job needs is resolved here, so
        the worker never touches the request."""
        account = _accounts().get(account_id, with_secret=True)
        if account is None:
            raise ValueError(f"unknown account {account_id}")
        factory = _ext()["gateway_factory"]
        db_path = _paths().db_path
        accounts = _accounts()
        edit_url = url_for("account_edit", account_id=account.id)

        def work(ctx: JobContext) -> None:
            try:
                gw = factory(account)
                result = Collector(
                    gw, db_path, account.id, account.display_name, progress=ctx
                ).run()
            except (JobCancelled, JobFailed):
                raise
            except Exception as exc:
                # Full details go to the log file only; raw errors can carry ARNs.
                log.exception("collection failed (account=%s)", account.id)
                if is_credential_failure(exc):
                    _credential_message(ctx, "Collection failed", exc, edit_url)
                else:
                    ctx.message("error", "Collection failed. See the log for details.")
                raise JobFailed("Collection failed") from None
            label = account_label(result.account_id, account.display_name)
            ctx.message(
                "ok",
                f"Collected {label}: {result.roles} roles, {result.inline_policies} inline "
                f"and {result.managed_policies} managed policies",
            )
            mismatch = accounts.record_identity(account.id, result.account_id)
            if mismatch:
                log.warning("collection of account=%s: %s", account.id, mismatch)
                ctx.message(
                    "warn", f"Warning: {mismatch} — check the", edit_url, "account settings"
                )
            for w in result.warnings[:20]:
                ctx.message("warn", w)
            if len(result.warnings) > 20:
                ctx.message("warn", f"… and {len(result.warnings) - 20} more warnings (see Logs)")

        return work

    @app.post("/snapshots/<int:snap_id>/delete")
    def snapshot_delete(snap_id: int):
        with closing(_paths().db_path) as conn:
            cur = conn.execute(
                "DELETE FROM snapshots WHERE id=? AND account_ref IS ?", (snap_id, _active_ref())
            )
        if not cur.rowcount:
            abort(404)
        log.info("snapshot %s deleted", snap_id)
        flash("Snapshot deleted (drafts cloned from it are kept).", "ok")
        return redirect(url_for("roles"))

    # -- insights --------------------------------------------------------------------

    @app.get("/insights")
    def insights_page():
        snap = _analysed_snapshot()
        return render_template(
            "insights.html",
            snap=snap,
            d=insights.dashboard(_db(), snap["id"]) if snap else None,
            window_days=WINDOW_DAYS,
        )

    @app.post("/insights/usage")
    def usage_collect():
        active = _active()
        snap = _snapshot_or_none()
        if active is None or snap is None:
            error = "Collect the IAM roles of an account first."
            if _wants_background():
                return jsonify({"ok": False, "error": error}), 400
            flash(error, "error")
            return redirect(url_for("insights_page"))
        work = _usage_work(active.id, snap["id"])
        return _run_job(active.id, "usage", work, url_for("insights_page"))

    def _usage_work(account_id: int, snap_id: int) -> Callable[[JobContext], None]:
        """The usage job of a snapshot (service last accessed, CloudTrail, Access Analyzer);
        like the collection job, everything is resolved before the worker starts."""
        account = _accounts().get(account_id, with_secret=True)
        if account is None:
            raise ValueError(f"unknown account {account_id}")
        factory = _ext()["gateway_factory"]
        db_path = _paths().db_path
        edit_url = url_for("account_edit", account_id=account.id)

        def work(ctx: JobContext) -> None:
            try:
                result = UsageCollector(factory(account), db_path, snap_id, progress=ctx).run()
            except (JobCancelled, JobFailed):
                raise
            except Exception as exc:
                log.exception("usage collection failed (account=%s)", account.id)
                if is_credential_failure(exc):
                    _credential_message(ctx, "Usage collection failed", exc, edit_url)
                else:
                    ctx.message("error", "Usage collection failed. See the log for details.")
                raise JobFailed("Usage collection failed") from None
            ctx.message(
                "ok",
                f"Usage collected: {result.services} service entries, {result.events} "
                f"AssumeRole events, {result.analyzer_findings} Access Analyzer findings",
            )
            for w in result.warnings[:20]:
                ctx.message("warn", w)
            if len(result.warnings) > 20:
                ctx.message("warn", f"… and {len(result.warnings) - 20} more warnings (see Logs)")

        return work

    @app.get("/insights/recommendations")
    def insights_recommendations():
        snap = _analysed_snapshot()
        default = _store().load().overlap_threshold
        threshold = recommend.parse_threshold(request.args.get("threshold"), default)
        dups: list[list[str]] = []
        pairs: list[dict[str, Any]] = []
        if snap is not None:
            perms = insights.role_perms(_db(), snap["id"])
            dups = recommend.duplicates(perms)
            pairs = recommend.overlaps(perms, threshold)
        return render_template(
            "recommendations.html",
            snap=snap,
            duplicates=dups,
            overlaps=pairs,
            threshold=threshold,
            default_threshold=default,
            limit=recommend.MAX_OVERLAPS,
        )

    def _pair_or_404() -> tuple[dict[str, Any], dict[str, Any], Any, Any]:
        """Role models and permission sets of the ``a`` / ``b`` query parameters."""
        snap = _analysed_snapshot()
        if snap is None:
            abort(404, NO_DATA)
        name_a, name_b = request.args.get("a", ""), request.args.get("b", "")
        if name_a == name_b:
            abort(400, "pick two different roles")
        a = queries.role_model(_db(), snap["id"], name_a)
        b = queries.role_model(_db(), snap["id"], name_b)
        if a is None or b is None:
            abort(404)
        perms = {p.name: p for p in insights.role_perms(_db(), snap["id"])}
        empty = recommend.RolePerms("", frozenset(), frozenset(), "")
        return a, b, perms.get(name_a, empty), perms.get(name_b, empty)

    def _merge_header(a: dict[str, Any], b: dict[str, Any]) -> str:
        return (
            f"Generated by RoleLens: suggested merge of roles {a['role_name']} and "
            f"{b['role_name']}.\nReview it and run terraform plan yourself: RoleLens never "
            "writes to AWS."
        )

    @app.get("/insights/compare")
    def insights_compare():
        a, b, perms_a, perms_b = _pair_or_404()
        merged = recommend.merged_model(a, b)
        return render_template(
            "compare.html",
            a=a,
            b=b,
            cmp=recommend.compare(perms_a, perms_b),
            merged=merged,
            issues=[i.as_dict() for i in validate_model(merged)],
            hcl=export_mod.terraform(merged, _merge_header(a, b)),
            files=export_mod.json_files(merged),
        )

    @app.get("/insights/merge.tf")
    def insights_merge_tf():
        a, b, _pa, _pb = _pair_or_404()
        merged = recommend.merged_model(a, b)
        body = export_mod.terraform(merged, _merge_header(a, b))
        name = export_mod.identifier(merged["role_name"], set())
        return _download(body.encode(), f"{name}.tf", "text/plain")

    @app.get("/insights/merge.zip")
    def insights_merge_zip():
        a, b, _pa, _pb = _pair_or_404()
        merged = recommend.merged_model(a, b)
        name = export_mod.identifier(merged["role_name"], set())
        data = export_mod.zip_bytes(export_mod.json_files(merged), name)
        return _download(data, f"{name}-policies.zip", "application/zip")

    @app.post("/insights/merge/draft")
    def insights_merge_draft():
        a, b, _pa, _pb = _pair_or_404()
        snap = _snapshot_or_none()
        with closing(_paths().db_path) as conn:
            draft_id = drafts_mod.create(
                conn, _active_ref(), snap["id"], a["role_name"], a, recommend.merged_model(a, b)
            )
        log.info("draft %s created from a merge of two roles (snapshot=%s)", draft_id, snap["id"])
        flash("Merged draft created. It is local only: RoleLens never writes to AWS.", "ok")
        return redirect(url_for("draft_edit", draft_id=draft_id))

    # -- drafts ----------------------------------------------------------------------

    def _draft_or_404(draft_id: int) -> dict[str, Any]:
        draft = drafts_mod.get(_db(), draft_id, _active_ref())
        if draft is None:
            abort(404)
        return draft

    def _preview(draft: dict[str, Any], model: dict[str, Any] | None, issues: list[Any]):
        if model is not None:
            issues = issues + validate_model(model)
        return {
            "ok": not has_errors(issues),
            "issues": [i.as_dict() for i in issues],
            "graph": build_graph(model) if model is not None else None,
            "diff": drafts_mod.diff(draft["original"], model) if model is not None else None,
        }

    @app.get("/drafts")
    def drafts_list():
        rows = []
        for d in drafts_mod.list_drafts(_db(), _active_ref()):
            issues = validate_model(d["model"])
            rows.append(
                {
                    **d,
                    "errors": sum(1 for i in issues if i.level == "error"),
                    "warnings": sum(1 for i in issues if i.level == "warning"),
                    "changed": drafts_mod.diff(d["original"], d["model"])["changed"],
                }
            )
        return render_template("drafts.html", rows=rows)

    def _editor(draft: dict[str, Any], raw: str | None = None, status: int = 200):
        model = draft["model"]
        return render_template(
            "editor.html",
            draft=draft,
            model_json=json.dumps(model, indent=2),
            raw_model=raw if raw is not None else json.dumps(model, indent=2),
            preview=_preview(draft, model, []),
            layouts=LAYOUTS,
        ), status

    @app.get("/drafts/<int:draft_id>")
    def draft_edit(draft_id: int):
        return _editor(_draft_or_404(draft_id))

    @app.post("/drafts/<int:draft_id>")
    def draft_save(draft_id: int):
        draft = _draft_or_404(draft_id)
        raw = request.form.get("model", "")
        model, issues = drafts_mod.parse_model(raw, draft["original"])
        ajax = request.form.get("ajax") == "1"
        if model is None:
            if ajax:
                return jsonify({**_preview(draft, None, issues), "saved": False}), 400
            for i in issues:
                flash(f"Not saved: {i.where}: {i.message}", "error")
            return _editor(draft, raw, 400)
        with closing(_paths().db_path) as conn:
            drafts_mod.save(conn, draft_id, model)
        result = _preview(draft, model, issues)
        log.info(
            "draft %s saved (%d issue(s), errors=%s)",
            draft_id,
            len(result["issues"]),
            not result["ok"],
        )
        if ajax:
            return jsonify({**result, "saved": True})
        if result["ok"]:
            flash("Draft saved.", "ok")
        else:
            flash("Draft saved with validation errors; fix them before exporting.", "warn")
        return redirect(url_for("draft_edit", draft_id=draft_id))

    @app.post("/drafts/<int:draft_id>/preview")
    def draft_preview(draft_id: int):
        draft = _draft_or_404(draft_id)
        model, issues = drafts_mod.parse_model(request.form.get("model", ""), draft["original"])
        return jsonify(_preview(draft, model, issues))

    @app.post("/drafts/<int:draft_id>/reset")
    def draft_reset(draft_id: int):
        draft = _draft_or_404(draft_id)
        with closing(_paths().db_path) as conn:
            drafts_mod.save(conn, draft_id, draft["original"])
        flash("Draft reset to the collected role.", "ok")
        return redirect(url_for("draft_edit", draft_id=draft_id))

    @app.post("/drafts/<int:draft_id>/delete")
    def draft_delete(draft_id: int):
        with closing(_paths().db_path) as conn:
            if not drafts_mod.delete(conn, draft_id, _active_ref()):
                abort(404)
        log.info("draft %s deleted", draft_id)
        flash("Draft deleted.", "ok")
        return redirect(url_for("drafts_list"))

    # -- export ----------------------------------------------------------------------

    def _export_header(draft: dict[str, Any]) -> str:
        return (
            f"Generated by RoleLens from draft {draft['id']} (cloned from role "
            f"{draft['source_role']}).\nReview it and run terraform plan yourself: RoleLens "
            "never writes to AWS."
        )

    def _export_name(draft: dict[str, Any]) -> str:
        return export_mod.identifier(draft["model"].get("role_name") or "role", set())

    @app.get("/drafts/<int:draft_id>/export")
    def draft_export(draft_id: int):
        draft = _draft_or_404(draft_id)
        model = draft["model"]
        issues = validate_model(model)
        return render_template(
            "export.html",
            draft=draft,
            issues=[i.as_dict() for i in issues],
            has_errors=has_errors(issues),
            hcl=export_mod.terraform(model, _export_header(draft)),
            files=export_mod.json_files(model),
        )

    @app.get("/drafts/<int:draft_id>/export/main.tf")
    def draft_export_tf(draft_id: int):
        draft = _draft_or_404(draft_id)
        body = export_mod.terraform(draft["model"], _export_header(draft))
        return _download(body.encode(), f"{_export_name(draft)}.tf", "text/plain")

    @app.get("/drafts/<int:draft_id>/export/policies.zip")
    def draft_export_zip(draft_id: int):
        draft = _draft_or_404(draft_id)
        name = _export_name(draft)
        data = export_mod.zip_bytes(export_mod.json_files(draft["model"]), name)
        return _download(data, f"{name}-policies.zip", "application/zip")

    @app.get("/drafts/<int:draft_id>/export/file")
    def draft_export_file(draft_id: int):
        draft = _draft_or_404(draft_id)
        files = export_mod.json_files(draft["model"])
        path = request.args.get("path", "")
        if path not in files:
            abort(404)
        return _download(files[path].encode(), path.rsplit("/", 1)[-1], "application/json")

    def _download(data: bytes, filename: str, mimetype: str) -> Response:
        return Response(
            data,
            mimetype=mimetype,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # -- logs ------------------------------------------------------------------------

    @app.get("/logs")
    def logs():
        level = request.args.get("level", "")
        q = request.args.get("q", "")
        limit = min(max(request.args.get("limit", 500, type=int), 1), 5000)
        log_dir = _ext()["log_dir"]
        entries = read_log(log_dir, min_level=level, q=q, limit=limit)
        return render_template(
            "logs.html",
            entries=entries,
            level=level,
            q=q,
            limit=limit,
            levels=LEVELS,
            log_dir=log_dir,
        )

    # -- settings and accounts -------------------------------------------------------

    @app.get("/settings")
    def settings_page():
        return render_template(
            "settings.html",
            s=_store().load(),
            accounts=_account_choices(),
            default_log_dir=_paths().default_log_dir,
        )

    @app.post("/settings")
    def settings_save():
        try:
            _store().save(
                log_dir=request.form.get("log_dir", ""),
                overlap_threshold=request.form.get("overlap_threshold"),
            )
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("settings_page"))
        settings = _store().load()
        new_dir = apply_log_dir(current_app, settings)
        log.info(
            "settings saved: log_dir=%s overlap_threshold=%s", new_dir, settings.overlap_threshold
        )
        flash("Settings saved", "ok")
        return redirect(url_for("settings_page"))

    @app.post("/accounts/active")
    def account_activate():
        raw = request.form.get("account_id", "")
        acct = _accounts().get(int(raw)) if raw.isdigit() else None
        if acct is None:
            abort(400, "unknown account")
        _store().set_active_account_id(acct.id)
        log.info("active account set to %s", acct.id)
        return redirect(_safe_next(request.form.get("next")))

    def _account_form(acct: Account, status: int = 200):
        profiles = discover_profiles()
        return render_template(
            "account_form.html",
            a=acct.public_dict(),
            modes=AUTH_MODES,
            mode_labels=AUTH_MODE_LABELS,
            regions=REGIONS,
            profiles=profiles,
            profile_known=acct.profile in {p.name for p in profiles},
            max_name=MAX_DISPLAY_NAME,
        ), status

    def _save_account(account_id: int | None):
        f = request.form
        fields: dict[str, Any] = {
            "display_name": f.get("display_name", ""),
            "region": f.get("region_custom", "").strip() or f.get("region", ""),
            "auth_mode": f.get("auth_mode", "env"),
            "profile": f.get("profile", ""),
            "memory_only": f.get("memory_only") == "on",
        }
        try:
            new_id = _accounts().save(
                account_id,
                **fields,
                access_key_id=f.get("access_key_id", ""),
                secret_access_key=f.get("secret_access_key") or None,
                paste=f.get("temporary_paste") or None,
            )
        except ValueError as exc:
            # Messages never quote secrets, and the form is re-rendered without them.
            flash(str(exc), "error")
            shown = _accounts().get(account_id) or Account()
            for key, value in fields.items():
                if key != "auth_mode" or value in AUTH_MODES:
                    setattr(shown, key, value)
            return _account_form(shown, 400)
        if _accounts().get(_store().active_account_id()) is None:
            _store().set_active_account_id(new_id)
        acct = _accounts().get(new_id)
        log.info(
            "account %s: id=%s auth_mode=%s region=%s memory_only=%s",
            "created" if account_id is None else "updated",
            new_id,
            acct.auth_mode,
            acct.region,
            acct.memory_only,
        )
        flash("Account saved", "ok")
        return redirect(url_for("settings_page"))

    @app.route("/accounts/new", methods=["GET", "POST"])
    def account_new():
        if request.method == "GET":
            return _account_form(Account())
        return _save_account(None)

    @app.route("/accounts/<int:account_id>/edit", methods=["GET", "POST"])
    def account_edit(account_id: int):
        acct = _accounts().get(account_id)
        if acct is None:
            abort(404)
        if request.method == "GET":
            return _account_form(acct)
        return _save_account(account_id)

    @app.post("/accounts/<int:account_id>/delete")
    def account_delete(account_id: int):
        if not _accounts().delete(account_id):
            abort(404)
        if _store().active_account_id() == account_id:
            first = next(iter(_accounts().list()), None)
            _store().set_active_account_id(first.id if first else None)
        log.info("account deleted: id=%s", account_id)
        flash("Account deleted together with its snapshots and drafts", "ok")
        return redirect(url_for("settings_page"))

    @app.post("/accounts/<int:account_id>/test")
    def account_test(account_id: int):
        acct = _accounts().get(account_id, with_secret=True)
        if acct is None:
            abort(404)
        result = check_connection(acct, _ext()["gateway_factory"])
        if result.credentials_problem:
            prefix, _sep, msg = result.message.partition(": ")
            _credential_flash(prefix, msg, account_id)
        else:
            flash(result.message, "ok" if result.ok else "error")
        mismatch = _accounts().record_identity(account_id, result.account_id)
        if mismatch:
            log.warning("connection test of account=%s: %s", account_id, mismatch)
            _identity_flash(mismatch, account_id)
        return redirect(url_for("settings_page"))

    @app.errorhandler(404)
    def _not_found(e):
        message = getattr(e, "description", "")
        if message != NO_DATA:
            message = "Not found"
        return render_template("error.html", message=message), 404

    @app.errorhandler(400)
    def _bad_request(e):
        return render_template("error.html", message=getattr(e, "description", "Bad request")), 400
