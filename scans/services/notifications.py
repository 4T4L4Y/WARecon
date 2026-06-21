import json
import logging
import re

from django.conf import settings
from django.core.mail import send_mail
from django.db.models.signals import post_save
from django.dispatch import receiver

from scans.models import Scan, ScanNotification, UserProfile

logger = logging.getLogger(__name__)


def get_or_create_profile(user) -> UserProfile:
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


def create_notification(
    user,
    *,
    title: str,
    message: str,
    level: str = ScanNotification.Level.INFO,
    scan: Scan | None = None,
) -> ScanNotification | None:
    if not user:
        return None
    profile = get_or_create_profile(user)
    if not profile.notify_in_app:
        return None
    return ScanNotification.objects.create(
        user=user,
        scan=scan,
        level=level,
        title=title,
        message=message,
    )


def notify_scan_finished(scan: Scan) -> None:
    if not scan.user:
        return
    profile = get_or_create_profile(scan.user)
    if scan.status == Scan.Status.COMPLETED:
        title = f"Tarama tamamlandı: {scan.domain}"
        message = "Tüm seçili modüller işlendi. Sonuçları geçmişten görüntüleyebilirsiniz."
        level = ScanNotification.Level.SUCCESS
    elif scan.status == Scan.Status.CANCELLED:
        title = f"Tarama iptal edildi: {scan.domain}"
        message = scan.progress_message or "Kullanıcı tarafından durduruldu."
        level = ScanNotification.Level.WARNING
    elif scan.status == Scan.Status.FAILED:
        title = f"Tarama başarısız: {scan.domain}"
        message = scan.error_message or "Bilinmeyen hata."
        level = ScanNotification.Level.WARNING
    else:
        return

    create_notification(scan.user, title=title, message=message, level=level, scan=scan)

    if profile.notify_email and scan.user.email:
        try:
            send_mail(
                subject=f"[WARecon] {title}",
                message=message,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@warecon.local"),
                recipient_list=[scan.user.email],
                fail_silently=True,
            )
        except Exception as exc:
            logger.warning("E-posta gönderilemedi: %s", exc)


def notify_critical_findings(scan: Scan, nuclei_items: list[dict]) -> None:
    if not scan.user or not nuclei_items:
        return
    profile = get_or_create_profile(scan.user)
    critical_high = []
    for item in nuclei_items:
        sev = (item.get("info") or {}).get("severity", "").lower()
        if sev in ("critical", "high"):
            critical_high.append(item)

    if not critical_high:
        return

    lines = []
    for item in critical_high[:10]:
        info = item.get("info") or {}
        sev = info.get("severity", "?").upper()
        name = info.get("name", item.get("template-id", "bulgu"))
        host = item.get("host", scan.domain)
        lines.append(f"[{sev}] {host} — {name}")

    title = f"{len(critical_high)} kritik/yüksek bulgu: {scan.domain}"
    message = "\n".join(lines)
    create_notification(
        scan.user,
        title=title,
        message=message,
        level=ScanNotification.Level.CRITICAL,
        scan=scan,
    )

    if profile.notify_email_critical_high and profile.notify_email and scan.user.email:
        try:
            send_mail(
                subject=f"[WARecon] {title}",
                message=message,
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@warecon.local"),
                recipient_list=[scan.user.email],
                fail_silently=True,
            )
        except Exception as exc:
            logger.warning("Kritik bulgu e-postası gönderilemedi: %s", exc)

    if profile.phone_critical_high and profile.notify_phone:
        logger.info(
            "SMS bildirimi (yapılandırılmadı): %s — %s",
            profile.notify_phone,
            title,
        )


def collect_nuclei_items_for_scan(scan: Scan) -> list[dict]:
    from scans.services.reports import _collect_nuclei_json

    return _collect_nuclei_json(scan)
