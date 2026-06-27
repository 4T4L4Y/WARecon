from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0009_scan_awaiting_port_selection"),
    ]

    operations = [
        migrations.CreateModel(
            name="SubdomainIntelResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hostname", models.CharField(db_index=True, max_length=255)),
                ("risk_score", models.PositiveSmallIntegerField(default=0)),
                (
                    "threat_level",
                    models.CharField(
                        choices=[
                            ("low", "Düşük Risk"),
                            ("medium", "Orta İlgi"),
                            ("high", "Yüksek Risk"),
                            ("critical", "Tehdit Aktiviteli"),
                        ],
                        default="low",
                        max_length=16,
                    ),
                ),
                ("live_reasons", models.JSONField(blank=True, default=list)),
                ("pulse_count", models.PositiveIntegerField(default=0)),
                ("malware_count", models.PositiveIntegerField(default=0)),
                ("malicious_votes", models.PositiveSmallIntegerField(default=0)),
                ("sources", models.JSONField(blank=True, default=list)),
                ("summary", models.TextField(blank=True)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("queried_at", models.DateTimeField(auto_now_add=True)),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="intel_results",
                        to="scans.scan",
                    ),
                ),
            ],
            options={
                "ordering": ["-risk_score", "hostname"],
                "unique_together": {("scan", "hostname")},
            },
        ),
    ]
