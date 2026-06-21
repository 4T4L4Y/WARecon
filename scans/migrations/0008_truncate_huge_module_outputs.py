from django.db import migrations

from scans.services.output_preview import MAX_DB_OUTPUT_CHARS, truncate_for_storage


def truncate_huge_module_outputs(apps, schema_editor):
    ScanModuleResult = apps.get_model("scans", "ScanModuleResult")
    for result in ScanModuleResult.objects.exclude(output="").iterator():
        if len(result.output or "") > MAX_DB_OUTPUT_CHARS:
            result.output = truncate_for_storage(result.output)
            result.save(update_fields=["output"])


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0007_userprofile_skip_module_after_seconds"),
    ]

    operations = [
        migrations.RunPython(truncate_huge_module_outputs, migrations.RunPython.noop),
    ]
