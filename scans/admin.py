from django.contrib import admin

from .models import Scan, ScanModuleResult


class ScanModuleResultInline(admin.TabularInline):
    model = ScanModuleResult
    extra = 0
    readonly_fields = ("module", "output_file", "created_at")


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("domain", "status", "created_at", "completed_at")
    list_filter = ("status", "created_at")
    search_fields = ("domain", "raw_input")
    readonly_fields = ("created_at", "completed_at")
    inlines = [ScanModuleResultInline]


@admin.register(ScanModuleResult)
class ScanModuleResultAdmin(admin.ModelAdmin):
    list_display = ("scan", "module", "output_file", "created_at")
    list_filter = ("module",)
