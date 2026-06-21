from django.core.management.base import BaseCommand

from scans.models import Scan
from scans.services.pipeline import refresh_scan_outputs


class Command(BaseCommand):
    help = "Tarama çıktılarını diskten yeniden oku veya seçili modülleri tekrar çalıştır."

    def add_arguments(self, parser):
        parser.add_argument("scan_id", type=int)
        parser.add_argument("--rerun-wayback", action="store_true")
        parser.add_argument("--rerun-httpx", action="store_true")
        parser.add_argument("--rerun-nuclei", action="store_true")
        parser.add_argument("--rerun-katana", action="store_true")
        parser.add_argument("--rerun-nmap", action="store_true")

    def handle(self, *args, **options):
        scan = Scan.objects.get(pk=options["scan_id"])
        refresh_scan_outputs(
            scan,
            rerun_wayback=options["rerun_wayback"],
            rerun_httpx=options["rerun_httpx"],
            rerun_nuclei=options["rerun_nuclei"],
            rerun_katana=options["rerun_katana"],
            rerun_nmap=options["rerun_nmap"],
        )
        self.stdout.write(self.style.SUCCESS(f"Tarama #{scan.pk} çıktıları güncellendi."))
