from django.http import HttpResponse
from rest_framework import permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from scans.models import Scan, ScanModuleResult
from scans.services.pipeline import create_scan, scan_to_context
from scans.services.reports import render_pdf_report
from scans.tasks import enqueue_scan


class ScanModuleResultSerializer(serializers.ModelSerializer):
    module_display = serializers.CharField(source="get_module_display", read_only=True)

    class Meta:
        model = ScanModuleResult
        fields = ["module", "module_display", "output", "output_file", "created_at"]


class ScanSerializer(serializers.ModelSerializer):
    results = ScanModuleResultSerializer(many=True, read_only=True)
    module_labels = serializers.ListField(read_only=True)

    class Meta:
        model = Scan
        fields = [
            "id", "domain", "raw_input", "modules", "module_labels", "status",
            "current_module", "progress_message", "progress_percent",
            "error_message", "is_archived", "created_at", "completed_at", "results",
        ]
        read_only_fields = fields


class ScanCreateSerializer(serializers.Serializer):
    domain = serializers.CharField(max_length=512)
    choices = serializers.ListField(child=serializers.CharField(), min_length=1)
    naabuPorts = serializers.CharField(required=False, allow_blank=True, default="")
    subdomainParams = serializers.ListField(
        child=serializers.CharField(), required=False, default=list
    )
    waybackKnownUrls = serializers.BooleanField(required=False, default=False)
    includeSubdomains = serializers.BooleanField(required=False, default=False)
    httpxFollowRedirects = serializers.BooleanField(required=False, default=False)
    httpxStatusCode = serializers.BooleanField(required=False, default=False)
    httpxMatchCodes = serializers.CharField(required=False, allow_blank=True, default="")
    nucleiTemplates = serializers.CharField(required=False, allow_blank=True, default="")
    nucleiSeverity = serializers.ListField(
        child=serializers.CharField(), required=False, default=list
    )
    katanaDepth = serializers.CharField(required=False, default="2")

    def create(self, validated_data):
        user = self.context["request"].user
        scan = create_scan(user, validated_data)
        enqueue_scan(scan.pk)
        return scan


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ScanSerializer

    def get_queryset(self):
        return Scan.objects.filter(
            user=self.request.user,
            is_archived=False,
        ).prefetch_related("results")

    @action(detail=True, methods=["post"])
    def archive(self, request, pk=None):
        scan = self.get_object()
        scan.is_archived = not scan.is_archived
        scan.save(update_fields=["is_archived"])
        return Response({"is_archived": scan.is_archived})

    @action(detail=True, methods=["post"])
    def remove(self, request, pk=None):
        scan = self.get_object()
        from scans.services.output_paths import cleanup_scan_outputs

        cleanup_scan_outputs(scan.pk)
        scan.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["post"], serializer_class=ScanCreateSerializer)
    def start(self, request):
        serializer = ScanCreateSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        scan = serializer.save()
        return Response(
            ScanSerializer(scan).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"])
    def results(self, request, pk=None):
        scan = self.get_object()
        return Response(scan_to_context(scan))

    @action(detail=True, methods=["get"])
    def report_pdf(self, request, pk=None):
        scan = self.get_object()
        pdf = render_pdf_report(scan)
        response = HttpResponse(pdf, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="warecon_{scan.domain}_{scan.pk}.pdf"'
        return response
