from django.urls import path

from . import views

app_name = "scans"

urlpatterns = [
    path("", views.index, name="index"),
    path("history/", views.history, name="history"),
    path("history/<int:pk>/", views.scan_detail, name="detail"),
    path("outputs/<path:filename>", views.download_output, name="download"),
    path("outputs/<path:filename>/json", views.nuclei_json, name="nuclei_json"),
]
