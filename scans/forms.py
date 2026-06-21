from django import forms


class ScanForm(forms.Form):
    domain = forms.CharField(max_length=512)
    choices = forms.MultipleChoiceField(
        choices=[
            ("1", "Port Tarama"),
            ("2", "Subdomain"),
            ("3", "Wayback"),
            ("4", "HTTPX"),
            ("5", "Nuclei"),
            ("6", "DNS"),
            ("7", "Katana"),
        ],
        required=True,
    )
    naabuPorts = forms.CharField(required=False)
    subdomainParams = forms.MultipleChoiceField(
        choices=[("-all", "Tüm kaynaklar")],
        required=False,
    )
    waybackKnownUrls = forms.BooleanField(required=False)
    includeSubdomains = forms.BooleanField(required=False)
    httpxFollowRedirects = forms.BooleanField(required=False)
    httpxStatusCode = forms.BooleanField(required=False)
    httpxMatchCodes = forms.CharField(required=False)
    nucleiTemplates = forms.CharField(required=False)
    nucleiSeverity = forms.MultipleChoiceField(
        choices=[
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Info"),
        ],
        required=False,
    )
    katanaDepth = forms.CharField(required=False, initial="2")
