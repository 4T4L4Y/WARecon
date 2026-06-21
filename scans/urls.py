from django.urls import include, path
from rest_framework.routers import DefaultRouter

from scans.api import ScanViewSet
from scans.auth_views import RegisterView, UserLoginView, UserLogoutView

from . import views

app_name = "scans"

router = DefaultRouter()
router.register("scans", ScanViewSet, basename="api-scan")

urlpatterns = [
    path("", views.index, name="index"),
    path("history/", views.history, name="history"),
    path("history/<int:pk>/", views.scan_detail, name="detail"),
    path("scan/<int:pk>/progress/", views.progress, name="progress"),
    path("scan/<int:pk>/events/", views.scan_events, name="events"),
    path("reports/<int:pk>/html/", views.report_html, name="report_html"),
    path("reports/<int:pk>/pdf/", views.report_pdf, name="report_pdf"),
    path("scan/<int:pk>/archive/", views.scan_archive, name="archive"),
    path("scan/<int:pk>/delete/", views.scan_delete, name="delete"),
    path("scan/<int:pk>/exploit-check/", views.run_exploit_check, name="exploit_check"),
    path("scan/<int:pk>/download/<path:filename>", views.download_output, name="download"),
    path("scan/<int:pk>/nuclei.json", views.nuclei_json_for_scan, name="nuclei_json"),
    path("accounts/login/", UserLoginView.as_view(), name="login"),
    path("accounts/logout/", UserLogoutView.as_view(), name="logout"),
    path("accounts/register/", RegisterView.as_view(), name="register"),
    path("api/", include(router.urls)),
]
