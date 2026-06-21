import django_rq

from scans.services.pipeline import execute_scan


def run_scan_job(scan_id: int) -> None:
    execute_scan(scan_id)


def enqueue_scan(scan_id: int) -> None:
    try:
        queue = django_rq.get_queue("default")
        queue.enqueue(run_scan_job, scan_id, job_timeout=3600)
    except Exception:
        run_scan_job(scan_id)
