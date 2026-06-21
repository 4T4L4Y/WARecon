from django.db import models


class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Bekliyor"
        RUNNING = "running", "Çalışıyor"
        COMPLETED = "completed", "Tamamlandı"
        FAILED = "failed", "Başarısız"

    domain = models.CharField(max_length=255, db_index=True)
    raw_input = models.CharField(max_length=512)
    modules = models.JSONField(default=list)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.domain} ({self.created_at:%Y-%m-%d %H:%M})"

    @property
    def module_labels(self) -> list[str]:
        labels = {
            "1": "Port",
            "2": "Subdomain",
            "3": "Wayback",
            "4": "HTTPX",
            "5": "Nuclei",
        }
        return [labels.get(m, m) for m in self.modules]


class ScanModuleResult(models.Model):
    class Module(models.TextChoices):
        NAABU = "naabu", "Port Tarama"
        SUBDOMAIN = "subdomain", "Subdomain"
        WAYBACK = "wayback", "Wayback"
        HTTPX = "httpx", "HTTPX"
        NUCLEI = "nuclei", "Nuclei"

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="results")
    module = models.CharField(max_length=32, choices=Module.choices)
    output = models.TextField(blank=True)
    output_file = models.CharField(max_length=512, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.scan.domain} — {self.get_module_display()}"
