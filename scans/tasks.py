import django_rq

from scans.models import Scan
from scans.services.pipeline import execute_scan


def run_scan_job(scan_id: int) -> None:
    execute_scan(scan_id)


def enqueue_scan(scan_id: int) -> None:
    try:
        queue = django_rq.get_queue("default")
        job = queue.enqueue(run_scan_job, scan_id, job_timeout=3600)
        Scan.objects.filter(pk=scan_id).update(rq_job_id=job.id)
    except Exception:
        run_scan_job(scan_id)


def enqueue_continue_scan(scan_id: int) -> None:
    enqueue_scan(scan_id)


def cancel_rq_job(scan: Scan) -> None:
    if not scan.rq_job_id:
        return
    try:
        from rq.job import Job

        job = Job.fetch(scan.rq_job_id)
        job.cancel()
    except Exception:
        pass
