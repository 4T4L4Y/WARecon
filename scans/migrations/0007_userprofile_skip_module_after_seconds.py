from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0006_alter_scan_status_alter_scanmoduleresult_module"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="skip_module_after_seconds",
            field=models.PositiveIntegerField(default=120),
        ),
    ]
