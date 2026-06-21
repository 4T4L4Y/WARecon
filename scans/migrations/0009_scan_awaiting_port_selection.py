from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0008_truncate_huge_module_outputs"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scan",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Bekliyor"),
                    ("running", "Çalışıyor"),
                    ("awaiting_subdomains", "Alt Alan Seçimi"),
                    ("awaiting_ports", "Port Seçimi"),
                    ("cancelled", "İptal Edildi"),
                    ("completed", "Tamamlandı"),
                    ("failed", "Başarısız"),
                ],
                default="pending",
                max_length=20,
            ),
        ),
    ]
