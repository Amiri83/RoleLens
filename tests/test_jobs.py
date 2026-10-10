"""Background jobs: progress, cancel, one job per account, persistence."""

import logging
import threading

import pytest

from rolelens import jobs

WAIT = 30  # seconds a test waits for a background job at most


def test_job_reports_progress_log_and_can_be_cancelled(db_path):
    mgr = jobs.JobManager(db_path)
    started, release = threading.Event(), threading.Event()

    def work(ctx: jobs.JobContext) -> None:
        ctx.step("role role-a", done=1, total=3)
        logging.getLogger("rolelens.example").warning("first line only\nsecond line stays out")
        started.set()
        release.wait(WAIT)
        ctx.check()  # cancelled meanwhile: raises JobCancelled

    try:
        job = mgr.start(1, "collect", work)
        assert started.wait(WAIT)
        live = mgr.status(job["id"])
        assert live["running"] and (live["step"], live["done"], live["total"]) == (
            "role role-a",
            1,
            3,
        )
        tail = "\n".join(live["log"])
        assert "warning: first line only" in tail and "second line" not in tail
        with pytest.raises(jobs.JobBusy):
            mgr.start(1, "collect", work)
        assert mgr.cancel(job["id"])
        release.set()
        assert mgr.wait(job["id"], WAIT)
        done = mgr.status(job["id"])
        assert done["state"] == jobs.CANCELLED
        assert done["messages"][-1]["text"] == "Collect IAM roles cancelled."
    finally:
        mgr.close()


def test_failed_job_shows_type_only_and_is_persisted(db_path):
    mgr = jobs.JobManager(db_path)

    def work(ctx):
        raise RuntimeError("arn:aws:iam::123456789012:role/role-a details")

    try:
        job = mgr.start(2, "collect", work, background=False)
        assert job["state"] == jobs.ERROR
        assert job["error"] == "Collect IAM roles failed (RuntimeError); see the log"
        assert "123456789012" not in job["error"]
    finally:
        mgr.close()
    # a new manager (restart) still reports the last job
    again = jobs.JobManager(db_path)
    try:
        assert again.current(2)["state"] == jobs.ERROR
    finally:
        again.close()


def test_running_job_of_a_previous_process_is_marked_interrupted(db_path):
    mgr = jobs.JobManager(db_path)
    mgr._persist(jobs.Job(id="job-a", account_ref=3, kind="collect", label="Collect IAM roles"))
    mgr.close()
    again = jobs.JobManager(db_path)
    try:
        assert again.current(3)["error"] == jobs.INTERRUPTED
    finally:
        again.close()


def test_unknown_kind_is_refused(db_path):
    mgr = jobs.JobManager(db_path)
    try:
        with pytest.raises(ValueError):
            mgr.start(1, "write-to-aws", lambda ctx: None)
    finally:
        mgr.close()


def test_shutdown_cancels_running_jobs_and_waits(db_path):
    mgr = jobs.JobManager(db_path)
    started = threading.Event()

    def work(ctx: jobs.JobContext) -> None:
        started.set()
        while not ctx.cancelled:  # a cooperative job: stops at its next check
            threading.Event().wait(0.01)
        ctx.check()

    try:
        job = mgr.start(1, "collect", work)
        finished = mgr.start(2, "usage", lambda ctx: None, background=False)
        assert started.wait(WAIT)
        assert mgr.shutdown(WAIT) == [job["id"]]  # the finished job is left alone
        assert mgr.status(job["id"])["state"] == jobs.CANCELLED
        assert mgr.status(finished["id"])["state"] == jobs.DONE
        assert mgr.shutdown(WAIT) == []
    finally:
        mgr.close()
