from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("scans", "0004_scan_archive"),
    ]

    operations = [
        migrations.AddField(
            model_name="scan",
            name="cancel_requested",
            field=models.BooleanField(default=False, db_index=True),
        ),
        migrations.AddField(
            model_name="scan",
            name="rq_job_id",
            field=models.CharField(blank=True, max_length=128),
        ),
        migrations.AddField(
            model_name="scan",
            name="skip_module_requested",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("notify_in_app", models.BooleanField(default=True)),
                ("notify_email", models.BooleanField(default=True)),
                ("notify_email_critical_high", models.BooleanField(default=True)),
                ("notify_phone", models.CharField(blank=True, max_length=32)),
                ("phone_critical_high", models.BooleanField(default=False)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="ScanNotification",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "level",
                    models.CharField(
                        choices=[
                            ("info", "Bilgi"),
                            ("success", "Başarılı"),
                            ("warning", "Uyarı"),
                            ("critical", "Kritik"),
                        ],
                        default="info",
                        max_length=16,
                    ),
                ),
                ("title", models.CharField(max_length=255)),
                ("message", models.TextField()),
                ("is_read", models.BooleanField(db_index=True, default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "scan",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notifications",
                        to="scans.scan",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scan_notifications",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
