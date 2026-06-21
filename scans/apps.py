from django.apps import AppConfig


class ScansConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scans"

    def ready(self):
        from scans import signals  # noqa: F401
