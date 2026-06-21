from django.conf import settings
from django.contrib.auth.models import User
from django.db import models


class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Bekliyor"
        RUNNING = "running", "Çalışıyor"
        COMPLETED = "completed", "Tamamlandı"
        FAILED = "failed", "Başarısız"

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="scans",
        null=True,
        blank=True,
    )
    domain = models.CharField(max_length=255, db_index=True)
    raw_input = models.CharField(max_length=512)
    modules = models.JSONField(default=list)
    config = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    current_module = models.CharField(max_length=64, blank=True)
    progress_message = models.CharField(max_length=255, blank=True)
    progress_percent = models.PositiveSmallIntegerField(default=0)
    error_message = models.TextField(blank=True)
    is_archived = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.domain} ({self.created_at:%Y-%m-%d %H:%M})"

    MODULE_LABELS = {
        "1": "Port",
        "2": "Subdomain",
        "3": "Wayback",
        "4": "HTTPX",
        "5": "Nuclei",
        "6": "DNS",
        "7": "Katana",
        "8": "Nmap",
    }

    @property
    def module_labels(self) -> list[str]:
        return [self.MODULE_LABELS.get(m, m) for m in self.modules]

    def update_progress(self, module: str, message: str, percent: int) -> None:
        self.current_module = module
        self.progress_message = message
        self.progress_percent = min(100, max(0, percent))
        self.save(update_fields=["current_module", "progress_message", "progress_percent"])


class ScanLog(models.Model):
    class Level(models.TextChoices):
        INFO = "info", "Bilgi"
        SUCCESS = "success", "Başarılı"
        WARNING = "warning", "Uyarı"
        ERROR = "error", "Hata"
        CMD = "cmd", "Komut"

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=16, choices=Level.choices, default=Level.INFO)
    message = models.TextField()
    module = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]

    def __str__(self):
        return f"{self.scan_id}: {self.message[:60]}"


class ScanModuleResult(models.Model):
    class Module(models.TextChoices):
        NAABU = "naabu", "Port Tarama"
        SUBDOMAIN = "subdomain", "Subdomain"
        WAYBACK = "wayback", "Wayback"
        HTTPX = "httpx", "HTTPX"
        NUCLEI = "nuclei", "Nuclei"
        DNSX = "dnsx", "DNS Kayıtları"
        KATANA = "katana", "Web Crawl"
        NMAP = "nmap", "Nmap Servis"

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="results")
    module = models.CharField(max_length=32, choices=Module.choices)
    output = models.TextField(blank=True)
    output_file = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.scan.domain} — {self.get_module_display()}"

    @property
    def download_url(self) -> str:
        if not self.output_file:
            return ""
        return f"/outputs/{self.output_file}"
