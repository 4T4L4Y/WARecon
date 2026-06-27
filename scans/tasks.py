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


def run_subdomain_intel_job(scan_id: int) -> None:
    from scans.services.subdomain_intel import run_subdomain_intel

    run_subdomain_intel(scan_id)


def enqueue_subdomain_intel(scan_id: int) -> None:
    """Tarama sonrası OSINT istihbaratını arka planda çalıştır."""
    from django.conf import settings

    if not getattr(settings, "OTX_API_KEY", ""):
        return
    try:
        queue = django_rq.get_queue("default")
        queue.enqueue(run_subdomain_intel_job, scan_id, job_timeout=1800)
    except Exception:
        run_subdomain_intel_job(scan_id)


def cancel_rq_job(scan: Scan) -> None:
    if not scan.rq_job_id:
        return
    try:
        from rq.job import Job

        job = Job.fetch(scan.rq_job_id)
        job.cancel()
    except Exception:
        pass
