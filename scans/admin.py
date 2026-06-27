from django.contrib import admin

from .models import Scan, ScanModuleResult, SubdomainIntelResult


class ScanModuleResultInline(admin.TabularInline):
    model = ScanModuleResult
    extra = 0
    readonly_fields = ("module", "output_file", "created_at")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("domain", "user", "status", "progress_percent", "created_at", "completed_at")
    list_filter = ("status", "created_at")
    search_fields = ("domain", "raw_input", "user__username")
    readonly_fields = ("created_at", "completed_at")
    inlines = [ScanModuleResultInline]


@admin.register(ScanModuleResult)
class ScanModuleResultAdmin(admin.ModelAdmin):
    list_display = ("scan", "module", "output_file", "created_at")
    list_filter = ("module",)


@admin.register(SubdomainIntelResult)
class SubdomainIntelResultAdmin(admin.ModelAdmin):
    list_display = ("scan", "hostname", "risk_score", "threat_level", "queried_at")
    list_filter = ("threat_level",)
    search_fields = ("hostname",)
