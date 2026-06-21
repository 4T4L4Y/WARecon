from django import forms


class ScanForm(forms.Form):
    domain = forms.CharField(
        max_length=512,
        widget=forms.TextInput(attrs={
            "class": "form-control",
            "placeholder": "ornek.com",
            "autocomplete": "off",
        }),
    )
    choices = forms.MultipleChoiceField(
        choices=[
            ("1", "Port Tarama"),
            ("2", "Subdomain"),
            ("3", "Wayback"),
            ("4", "HTTPX"),
            ("5", "Nuclei"),
        ],
        widget=forms.CheckboxSelectMultiple,
        required=True,
    )
    naabuPorts = forms.CharField(required=False, widget=forms.TextInput(attrs={
        "class": "form-control form-control-sm",
        "placeholder": "80,443,8080",
    }))
    subdomainParams = forms.MultipleChoiceField(
        choices=[("-all", "Tüm kaynaklar (-all)")],
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
    waybackKnownUrls = forms.BooleanField(required=False)
    includeSubdomains = forms.BooleanField(required=False)
    httpxFollowRedirects = forms.BooleanField(required=False)
    httpxStatusCode = forms.BooleanField(required=False)
    httpxMatchCodes = forms.CharField(required=False, widget=forms.TextInput(attrs={
        "class": "form-control form-control-sm",
        "placeholder": "200,302,404",
    }))
    nucleiTemplates = forms.CharField(required=False, widget=forms.TextInput(attrs={
        "class": "form-control form-control-sm",
        "placeholder": "caa-fingerprint",
    }))
    nucleiSeverity = forms.MultipleChoiceField(
        choices=[
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Info"),
        ],
        required=False,
        widget=forms.CheckboxSelectMultiple,
    )
